"""Unit tests for the federation proxy. No AWS or network access required.

Run:  cd proxy && python -m pytest -q
"""
import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
from urllib.parse import urlencode

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

import proxy
from conftest import AUDIENCE, ISSUER, REPLICATOR_ROLE

PROXY_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Stand-ins for the AWS STS signing keys (published at the issuer's JWKS).
STS_RSA = rsa.generate_private_key(public_exponent=65537, key_size=2048)
STS_EC = ec.generate_private_key(ec.SECP384R1())
ATTACKER_RSA = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(alg_cls, public_key, kid):
    d = json.loads(alg_cls.to_jwk(public_key))
    d["kid"] = kid
    return d


STS_JWKS = {"keys": [_jwk(RSAAlgorithm, STS_RSA.public_key(), "sts-rsa"),
                     _jwk(ECAlgorithm, STS_EC.public_key(), "sts-ec")]}


def b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def claims(**overrides):
    now = int(time.time())
    c = {"iss": ISSUER, "aud": AUDIENCE,
         "sub": "arn:aws:iam::111122223333:role/vpc-peering-replicator-ser",
         "iat": now, "exp": now + 300}
    c.update(overrides)
    return {k: v for k, v in c.items() if v is not None}


def sts_jwt(key=STS_RSA, alg="RS256", kid="sts-rsa", **overrides):
    return jwt.encode(claims(**overrides), key, algorithm=alg, headers={"kid": kid})


@pytest.fixture(autouse=True)
def stub_aws(monkeypatch):
    """Serve the STS JWKS and the IdP client secret without AWS."""
    monkeypatch.setattr(proxy, "_load_jwks", lambda: {ISSUER: STS_JWKS})
    monkeypatch.setattr(proxy, "_jwks", {"keys_by_issuer": {}, "fetched_at": 0.0})
    monkeypatch.setattr(proxy, "_get_secret_json",
                        lambda arn: {"client_id": "kafka-producer", "client_secret": "s3cret"})


def token_request(grant_type, token, field="assertion", scope="kafka", b64_body=False):
    body = urlencode({"grant_type": grant_type, field: token, "scope": scope})
    event = {"requestContext": {"http": {"method": "POST", "path": "/prod/token"}}}
    if b64_body:
        event["isBase64Encoded"] = True
        event["body"] = base64.b64encode(body.encode()).decode()
    else:
        event["body"] = body
    return event


# --- validate_sts_jwt: accepted ----------------------------------------------

def test_valid_rs256_token_passes():
    assert proxy.validate_sts_jwt(sts_jwt())["iss"] == ISSUER


def test_valid_es384_token_passes():
    assert proxy.validate_sts_jwt(sts_jwt(key=STS_EC, alg="ES384", kid="sts-ec"))


def test_subject_matches_role_regardless_of_path():
    # TRUSTED_SUBJECTS carries /service-role/; the token's sub may omit the path.
    proxy.validate_sts_jwt(sts_jwt(sub=REPLICATOR_ROLE))
    proxy.validate_sts_jwt(sts_jwt(sub="arn:aws:iam::111122223333:role/vpc-peering-replicator-ser"))


# --- validate_sts_jwt: forged / invalid tokens are rejected -------------------

def test_unsigned_alg_none_rejected():
    forged = f'{b64({"alg": "none", "kid": "sts-rsa"})}.{b64(claims())}.'
    with pytest.raises(Exception, match="algorithm"):
        proxy.validate_sts_jwt(forged)


def test_hs256_forgery_rejected():
    head, body = b64({"alg": "HS256", "kid": "sts-rsa"}), b64(claims())
    sig = base64.urlsafe_b64encode(hmac.new(b"guess", f"{head}.{body}".encode(),
                                            hashlib.sha256).digest()).rstrip(b"=").decode()
    with pytest.raises(Exception, match="algorithm"):
        proxy.validate_sts_jwt(f"{head}.{body}.{sig}")


def test_token_signed_by_wrong_key_rejected():
    with pytest.raises(jwt.InvalidSignatureError):
        proxy.validate_sts_jwt(sts_jwt(key=ATTACKER_RSA))


def test_attacker_issuer_rejected_without_fetching_its_keys(monkeypatch):
    fetched = []
    monkeypatch.setattr(proxy, "_load_jwks", lambda: fetched.append(1) or {})
    with pytest.raises(ValueError, match="Untrusted issuer"):
        proxy.validate_sts_jwt(sts_jwt(key=ATTACKER_RSA, iss="https://attacker.example"))
    assert not fetched


def test_unknown_kid_rejected():
    with pytest.raises(ValueError, match="No trusted signing key"):
        proxy.validate_sts_jwt(sts_jwt(kid="not-a-sts-key"))


def test_key_type_mismatch_rejected():
    # An RS256 header pointing at the EC key must not verify.
    with pytest.raises(Exception):
        proxy.validate_sts_jwt(sts_jwt(kid="sts-ec"))


def test_untrusted_subject_rejected():
    with pytest.raises(ValueError, match="Untrusted subject"):
        proxy.validate_sts_jwt(sts_jwt(sub="arn:aws:iam::111122223333:role/SomeOtherRole"))


def test_same_role_name_other_account_rejected():
    with pytest.raises(ValueError, match="Untrusted subject"):
        proxy.validate_sts_jwt(sts_jwt(sub="arn:aws:iam::999988887777:role/vpc-peering-replicator-ser"))


def test_wrong_audience_rejected():
    with pytest.raises(jwt.InvalidAudienceError):
        proxy.validate_sts_jwt(sts_jwt(aud="some-other-service"))


def test_expired_rejected():
    now = int(time.time())
    with pytest.raises(jwt.ExpiredSignatureError):
        proxy.validate_sts_jwt(sts_jwt(iat=now - 600, exp=now - 300))


@pytest.mark.parametrize("claim", ["exp", "iat", "sub", "aud"])
def test_missing_required_claim_rejected(claim):
    with pytest.raises(jwt.MissingRequiredClaimError):
        proxy.validate_sts_jwt(sts_jwt(**{claim: None}))


def test_excessive_lifetime_rejected():
    now = int(time.time())
    with pytest.raises(ValueError, match="lifetime"):
        proxy.validate_sts_jwt(sts_jwt(iat=now, exp=now + 86400))


def test_key_rotation_refreshes_jwks(monkeypatch):
    rotated = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = {"keys": list(STS_JWKS["keys"])}
    monkeypatch.setattr(proxy, "_load_jwks", lambda: {ISSUER: jwks})
    proxy.validate_sts_jwt(sts_jwt())                       # populate the cache
    jwks["keys"].append(_jwk(RSAAlgorithm, rotated.public_key(), "sts-rotated"))
    proxy._jwks["fetched_at"] -= proxy.JWKS_MIN_REFRESH_INTERVAL
    assert proxy.validate_sts_jwt(sts_jwt(key=rotated, kid="sts-rotated"))


# --- startup refuses insecure configuration ------------------------------------

@pytest.mark.parametrize("unset", ["TRUSTED_ISSUERS", "TRUSTED_AUDIENCES",
                                   "TRUSTED_SUBJECTS", "IDP_CLIENT_SECRET_ARN"])
def test_import_fails_closed_when_required_config_missing(unset):
    env = dict(os.environ, **{unset: ""})
    r = subprocess.run([sys.executable, "-c", "import proxy"], cwd=PROXY_DIR, env=env,
                       capture_output=True, text=True)
    assert r.returncode != 0 and unset in r.stderr


def test_import_rejects_non_https_issuer():
    env = dict(os.environ, TRUSTED_ISSUERS="http://sts.example")
    r = subprocess.run([sys.executable, "-c", "import proxy"], cwd=PROXY_DIR, env=env,
                       capture_output=True, text=True)
    assert r.returncode != 0 and "https" in r.stderr


# --- handler routing ---------------------------------------------------------

def test_wrong_path_404():
    ev = {"requestContext": {"http": {"method": "POST", "path": "/prod/nope"}}}
    assert proxy.handler(ev, None)["statusCode"] == 404


def test_get_method_404():
    ev = {"requestContext": {"http": {"method": "GET", "path": "/prod/token"}}}
    assert proxy.handler(ev, None)["statusCode"] == 404


def test_unsupported_grant_400():
    assert proxy.handler(token_request("client_credentials", sts_jwt()), None)["statusCode"] == 400


def test_missing_assertion_400():
    assert proxy.handler(token_request(proxy.GRANT_JWT_BEARER, ""), None)["statusCode"] == 400


def test_forged_token_401_and_never_reaches_idp(monkeypatch):
    calls = []
    monkeypatch.setattr(proxy.requests, "post", lambda *a, **k: calls.append(1))
    forged = f'{b64({"alg": "none"})}.{b64(claims())}.'
    resp = proxy.handler(token_request(proxy.GRANT_JWT_BEARER, forged), None)
    assert resp["statusCode"] == 401
    assert json.loads(resp["body"]) == {"error": "invalid_grant",
                                        "error_description": "STS JWT validation failed"}
    assert not calls


# --- happy path (downstream mint mocked) -------------------------------------

class _FakeResp:
    status_code = 200

    def json(self):
        return {"access_token": "downstream-bearer", "expires_in": 300}


def test_happy_path_jwt_bearer(monkeypatch):
    sent = {}
    monkeypatch.setattr(proxy.requests, "post", lambda *a, **k: sent.update(k) or _FakeResp())
    resp = proxy.handler(token_request(proxy.GRANT_JWT_BEARER, sts_jwt()), None)
    assert resp["statusCode"] == 200
    body = json.loads(resp["body"])
    assert body["access_token"] == "downstream-bearer"
    assert body["token_type"] == "Bearer"
    assert sent["data"]["client_id"] == "kafka-producer"
    assert sent["data"]["client_secret"] == "s3cret"


def test_happy_path_token_exchange_subject_token(monkeypatch):
    monkeypatch.setattr(proxy.requests, "post", lambda *a, **k: _FakeResp())
    ev = token_request(proxy.GRANT_TOKEN_EXCHANGE, sts_jwt(), field="subject_token")
    assert proxy.handler(ev, None)["statusCode"] == 200


def test_base64_encoded_body(monkeypatch):
    monkeypatch.setattr(proxy.requests, "post", lambda *a, **k: _FakeResp())
    ev = token_request(proxy.GRANT_JWT_BEARER, sts_jwt(), b64_body=True)
    assert proxy.handler(ev, None)["statusCode"] == 200


def test_downstream_failure_502_does_not_leak_idp_body(monkeypatch):
    class _Bad:
        status_code = 503
        text = "idp internal detail"
    monkeypatch.setattr(proxy.requests, "post", lambda *a, **k: _Bad())
    resp = proxy.handler(token_request(proxy.GRANT_JWT_BEARER, sts_jwt()), None)
    assert resp["statusCode"] == 502
    assert "idp internal detail" not in resp["body"]
