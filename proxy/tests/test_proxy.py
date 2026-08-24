"""Unit tests for the federation proxy. No AWS or network access required.

Run:  cd proxy && python -m pytest -q
"""
import base64
import json
import time
from urllib.parse import urlencode

import jwt
import pytest

import proxy


def make_sts_jwt(sub="arn:aws:sts::111122223333:assumed-role/Replicator/session",
                 iss="https://sts.amazonaws.com",
                 aud="federation-proxy", exp_delta=300, **extra):
    claims = {"sub": sub, "iss": iss, "aud": aud, "exp": int(time.time()) + exp_delta}
    claims.update(extra)
    # Signature is irrelevant: the proxy does claim-only checks unless
    # VALIDATE_STS_JWT is set, which these tests do not enable. The signing key
    # below is an arbitrary throwaway used only so PyJWT can encode the token.
    return jwt.encode(claims, "unit-test-signing-key", algorithm="HS256")


def token_request(grant_type, sts_jwt, field="assertion", scope="kafka", b64=False):
    body = urlencode({"grant_type": grant_type, field: sts_jwt, "scope": scope})
    event = {"requestContext": {"http": {"method": "POST", "path": "/prod/token"}}}
    if b64:
        event["isBase64Encoded"] = True
        event["body"] = base64.b64encode(body.encode()).decode()
    else:
        event["body"] = body
    return event


# --- validate_sts_jwt --------------------------------------------------------

def test_valid_claims_pass(monkeypatch):
    monkeypatch.setattr(proxy, "TRUSTED_ISSUERS", [])
    monkeypatch.setattr(proxy, "TRUSTED_AUDIENCES", [])
    claims = proxy.validate_sts_jwt(make_sts_jwt())
    assert claims["sub"].startswith("arn:aws:")


def test_missing_iss_rejected(monkeypatch):
    monkeypatch.setattr(proxy, "TRUSTED_ISSUERS", [])
    tok = jwt.encode({"sub": "arn:aws:sts::111122223333:x", "exp": int(time.time()) + 60},
                     "s", algorithm="HS256")
    with pytest.raises(ValueError, match="iss"):
        proxy.validate_sts_jwt(tok)


def test_non_arn_subject_rejected(monkeypatch):
    monkeypatch.setattr(proxy, "TRUSTED_ISSUERS", [])
    with pytest.raises(ValueError, match="ARN"):
        proxy.validate_sts_jwt(make_sts_jwt(sub="some-user"))


def test_expired_rejected(monkeypatch):
    monkeypatch.setattr(proxy, "TRUSTED_ISSUERS", [])
    with pytest.raises(ValueError, match="expired"):
        proxy.validate_sts_jwt(make_sts_jwt(exp_delta=-10))


def test_untrusted_issuer_rejected(monkeypatch):
    monkeypatch.setattr(proxy, "TRUSTED_ISSUERS", ["https://sts.amazonaws.com"])
    with pytest.raises(ValueError, match="Untrusted issuer"):
        proxy.validate_sts_jwt(make_sts_jwt(iss="https://evil.example.com"))


def test_untrusted_audience_rejected(monkeypatch):
    monkeypatch.setattr(proxy, "TRUSTED_ISSUERS", [])
    monkeypatch.setattr(proxy, "TRUSTED_AUDIENCES", ["federation-proxy"])
    with pytest.raises(ValueError, match="Untrusted audience"):
        proxy.validate_sts_jwt(make_sts_jwt(aud="wrong-audience"))


# --- handler routing ---------------------------------------------------------

def test_wrong_path_404():
    ev = {"requestContext": {"http": {"method": "POST", "path": "/prod/nope"}}}
    assert proxy.handler(ev, None)["statusCode"] == 404


def test_get_method_404():
    ev = {"requestContext": {"http": {"method": "GET", "path": "/prod/token"}}}
    assert proxy.handler(ev, None)["statusCode"] == 404


def test_unsupported_grant_400(monkeypatch):
    monkeypatch.setattr(proxy, "TRUSTED_ISSUERS", [])
    ev = token_request("client_credentials", make_sts_jwt())
    assert proxy.handler(ev, None)["statusCode"] == 400


def test_missing_assertion_400():
    ev = token_request(proxy.GRANT_JWT_BEARER, "")
    assert proxy.handler(ev, None)["statusCode"] == 400


def test_invalid_sts_jwt_401(monkeypatch):
    monkeypatch.setattr(proxy, "TRUSTED_ISSUERS", [])
    ev = token_request(proxy.GRANT_JWT_BEARER, make_sts_jwt(sub="not-an-arn"))
    assert proxy.handler(ev, None)["statusCode"] == 401


# --- happy path (downstream mint mocked) -------------------------------------

class _FakeResp:
    status_code = 200

    def json(self):
        return {"access_token": "downstream-bearer", "expires_in": 300}


def test_happy_path_jwt_bearer(monkeypatch):
    monkeypatch.setattr(proxy, "TRUSTED_ISSUERS", [])
    monkeypatch.setattr(proxy, "TRUSTED_AUDIENCES", [])
    monkeypatch.setattr(proxy.requests, "post", lambda *a, **k: _FakeResp())
    ev = token_request(proxy.GRANT_JWT_BEARER, make_sts_jwt())
    resp = proxy.handler(ev, None)
    assert resp["statusCode"] == 200
    body = json.loads(resp["body"])
    assert body["access_token"] == "downstream-bearer"
    assert body["token_type"] == "Bearer"


def test_happy_path_token_exchange_subject_token(monkeypatch):
    monkeypatch.setattr(proxy, "TRUSTED_ISSUERS", [])
    monkeypatch.setattr(proxy, "TRUSTED_AUDIENCES", [])
    monkeypatch.setattr(proxy.requests, "post", lambda *a, **k: _FakeResp())
    ev = token_request(proxy.GRANT_TOKEN_EXCHANGE, make_sts_jwt(), field="subject_token")
    assert proxy.handler(ev, None)["statusCode"] == 200


def test_base64_encoded_body(monkeypatch):
    monkeypatch.setattr(proxy, "TRUSTED_ISSUERS", [])
    monkeypatch.setattr(proxy, "TRUSTED_AUDIENCES", [])
    monkeypatch.setattr(proxy.requests, "post", lambda *a, **k: _FakeResp())
    ev = token_request(proxy.GRANT_JWT_BEARER, make_sts_jwt(), b64=True)
    assert proxy.handler(ev, None)["statusCode"] == 200


def test_downstream_failure_502(monkeypatch):
    monkeypatch.setattr(proxy, "TRUSTED_ISSUERS", [])
    monkeypatch.setattr(proxy, "TRUSTED_AUDIENCES", [])

    class _Bad:
        status_code = 503
        text = "idp down"
    monkeypatch.setattr(proxy.requests, "post", lambda *a, **k: _Bad())
    ev = token_request(proxy.GRANT_JWT_BEARER, make_sts_jwt())
    assert proxy.handler(ev, None)["statusCode"] == 502
