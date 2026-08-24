"""
Federation proxy for MSK Replicator OAuth (IAM_JWT_BEARER / token-exchange).

WHAT THIS IS
------------
A small OAuth token endpoint that sits between MSK Replicator and an enterprise
Identity Provider (IdP). From the Replicator's point of view it is a single,
standard OAuth token endpoint. Internally it:

  1. Receives the AWS STS JWT the Replicator presents (proof of the Replicator's
     IAM identity), sent either as:
       - grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer   assertion=<STS JWT>   (IAM_JWT_BEARER)
       - grant_type=urn:ietf:params:oauth:grant-type:token-exchange  subject_token=<STS JWT>
  2. Validates that STS JWT (claim checks always; optional signature verification
     via the AWS STS OIDC JWKS when VALIDATE_STS_JWT=true).
  3. Exchanges it for a downstream OAuth Bearer token that the self-managed Kafka
     brokers trust, using one of two modes (EXCHANGE_MODE):
       - client_credentials : the proxy holds a client_id/secret at the IdP and
                              mints a token on the validated identity's behalf.
                              This is the default and is fully self-contained.
       - token_exchange     : RFC 8693. The proxy forwards the STS JWT to an IdP
                              that federates AWS STS as an external token issuer.
  4. Returns a standard OAuth token response {access_token, token_type, expires_in}.

WHY A PROXY
-----------
MSK Replicator's OAuth contract is deliberately narrow: it calls ONE token
endpoint with ONE grant type and expects a standard token response. Enterprises
whose real auth path is multi-hop (identity federation, token exchange, claim
enrichment, an IdP that needs mТLS, etc.) collapse that chain behind this single
endpoint. Everything behind the endpoint is owned by the customer and opaque to
the Replicator. This module is a reference implementation of that endpoint.

To adapt it to a real multi-hop chain, replace `exchange_for_downstream_token`
with your own orchestration (keep the same input: validated STS claims + the raw
STS JWT; same output: an access_token string).

CONFIGURATION (environment variables)
-------------------------------------
  IDP_TOKEN_ENDPOINT   Downstream IdP token endpoint (HTTPS).
  IDP_CLIENT_ID        Client id used for the downstream mint / client auth.
  IDP_CLIENT_SECRET    Client secret (store in Secrets Manager; inject at deploy).
  IDP_SCOPE            Optional OAuth scope to request downstream.
  IDP_CA_PEM           Optional PEM of a private CA that signed the IdP TLS cert.
  EXCHANGE_MODE        "client_credentials" (default) or "token_exchange".
  TRUSTED_ISSUERS      Comma-separated allowlist of STS issuer URLs (empty = any).
  TRUSTED_AUDIENCES    Comma-separated allowlist of STS audiences (empty = any).
  VALIDATE_STS_JWT     "true" verifies the STS JWT signature via JWKS (needs
                       egress to the STS OIDC endpoint). "false" (default) does
                       claim-only checks (iss/aud/exp/sub), suitable for a
                       no-egress private subnet.
"""

import base64
import json
import os
import tempfile
import time
from urllib.parse import parse_qs

import jwt
import requests

# --- OAuth grant type URNs ---------------------------------------------------
GRANT_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
SUBJECT_TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"

# --- Configuration -----------------------------------------------------------
TRUSTED_ISSUERS = [x.strip() for x in os.environ.get("TRUSTED_ISSUERS", "").split(",") if x.strip()]
TRUSTED_AUDIENCES = [x.strip() for x in os.environ.get("TRUSTED_AUDIENCES", "").split(",") if x.strip()]
VALIDATE_STS_JWT = os.environ.get("VALIDATE_STS_JWT", "false").lower() == "true"

IDP_TOKEN_ENDPOINT = os.environ.get("IDP_TOKEN_ENDPOINT", "")
IDP_CLIENT_ID = os.environ.get("IDP_CLIENT_ID", "")
IDP_CLIENT_SECRET = os.environ.get("IDP_CLIENT_SECRET", "")
IDP_SCOPE = os.environ.get("IDP_SCOPE", "")
IDP_CA_PEM = os.environ.get("IDP_CA_PEM", "")
EXCHANGE_MODE = os.environ.get("EXCHANGE_MODE", "client_credentials").lower()

JWKS_CACHE_TTL = 300

# Write the IdP CA to a temp file once so `requests` can trust a private CA.
_CA_FILE = None
if IDP_CA_PEM:
    _CA_FILE = os.path.join(tempfile.gettempdir(), "idp-ca.pem")
    with open(_CA_FILE, "w", encoding="utf-8") as f:
        f.write(IDP_CA_PEM)

_verify = _CA_FILE or True

_jwks_cache, _jwks_time = {}, {}


# --- STS JWT validation ------------------------------------------------------

def _unverified_claims(token):
    """Read a JWT's claims WITHOUT verifying the signature, by base64url-decoding
    the payload segment directly.

    Used only for the pre-signature claim checks (issuer/audience/expiry/subject)
    and to locate the signing key. When VALIDATE_STS_JWT is enabled the token is
    afterwards re-decoded with full signature verification.
    """
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("Malformed JWT")
    payload_b64 = parts[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)  # restore base64 padding
    return json.loads(base64.urlsafe_b64decode(payload_b64))


def _fetch_jwks(issuer):
    now = time.time()
    if issuer in _jwks_cache and now - _jwks_time.get(issuer, 0) < JWKS_CACHE_TTL:
        return _jwks_cache[issuer]
    disc_resp = requests.get(f"{issuer}/.well-known/openid-configuration", timeout=10)
    disc_resp.raise_for_status()
    disc = disc_resp.json()
    jwks_resp = requests.get(disc.get("jwks_uri", f"{issuer}/.well-known/jwks.json"), timeout=10)
    jwks_resp.raise_for_status()
    jwks = jwks_resp.json()
    _jwks_cache[issuer], _jwks_time[issuer] = jwks, now
    return jwks


def validate_sts_jwt(token):
    """Validate the AWS STS JWT presented by the Replicator.

    Claim checks (issuer allowlist, audience allowlist, expiry, and that the
    subject is an AWS ARN) always run. Signature verification via the issuer's
    JWKS is optional (VALIDATE_STS_JWT) so the proxy can run in a subnet without
    internet egress. Returns the decoded claims on success; raises ValueError
    otherwise.
    """
    header = jwt.get_unverified_header(token)
    payload = _unverified_claims(token)

    issuer = payload.get("iss")
    if not issuer:
        raise ValueError("Missing iss claim")
    if TRUSTED_ISSUERS and issuer not in TRUSTED_ISSUERS:
        raise ValueError(f"Untrusted issuer: {issuer}")
    if TRUSTED_AUDIENCES:
        aud = payload.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        if not any(a in TRUSTED_AUDIENCES for a in auds):
            raise ValueError(f"Untrusted audience: {aud}")
    if payload.get("exp") and payload["exp"] < time.time():
        raise ValueError("Token expired")
    if not str(payload.get("sub", "")).startswith("arn:aws:"):
        raise ValueError(f"Subject is not an AWS ARN: {payload.get('sub')}")

    if VALIDATE_STS_JWT:
        from jwt.algorithms import RSAAlgorithm, ECAlgorithm
        kid, alg = header.get("kid"), header.get("alg")
        if not kid or not alg:
            raise ValueError("Missing kid or alg for signature verification")
        jwks = _fetch_jwks(issuer)
        kd = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
        if not kd:
            raise ValueError(f"No JWKS key for kid {kid}")
        pk = (RSAAlgorithm.from_jwk(json.dumps(kd)) if kd.get("kty") == "RSA"
              else ECAlgorithm.from_jwk(json.dumps(kd)))
        payload = jwt.decode(
            token, pk, algorithms=[alg],
            audience=TRUSTED_AUDIENCES or None,
            options={"verify_aud": bool(TRUSTED_AUDIENCES), "verify_exp": True},
        )
    return payload


# --- Downstream token acquisition -------------------------------------------

def exchange_for_downstream_token(sts_jwt, claims):
    """Obtain a downstream OAuth Bearer token the self-managed Kafka trusts.

    This is the single seam to adapt for a real multi-hop chain. Inputs: the raw
    validated STS JWT and its decoded claims. Output: an OAuth token response
    dict containing at least `access_token`.

    Note: the downstream request uses the proxy's configured IDP_SCOPE, not the
    scope the Replicator requested. The Replicator's scope names a resource at the
    SOURCE Kafka and generally has no meaning at the downstream IdP, so forwarding
    it would break IdPs that validate scope names.
    """
    if EXCHANGE_MODE == "token_exchange":
        # RFC 8693 token exchange: forward the STS JWT to an IdP that federates
        # AWS STS as an external issuer. The IdP validates it and returns its own
        # access token.
        data = {
            "grant_type": GRANT_TOKEN_EXCHANGE,
            "subject_token": sts_jwt,
            "subject_token_type": SUBJECT_TOKEN_TYPE_JWT,
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        }
        if IDP_CLIENT_ID:
            data["client_id"] = IDP_CLIENT_ID
        if IDP_CLIENT_SECRET:
            data["client_secret"] = IDP_CLIENT_SECRET
    else:
        # client_credentials (default): the proxy holds a downstream client and
        # mints a token on the validated identity's behalf. Fully self-contained.
        data = {
            "grant_type": "client_credentials",
            "client_id": IDP_CLIENT_ID,
            "client_secret": IDP_CLIENT_SECRET,
        }
    if IDP_SCOPE:
        data["scope"] = IDP_SCOPE

    resp = requests.post(
        IDP_TOKEN_ENDPOINT, data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        verify=_verify, timeout=10,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"IdP returned {resp.status_code}: {resp.text[:200]}")
    return resp.json()


# --- Lambda handler ----------------------------------------------------------

def handler(event, context):
    method, path = _method_and_path(event)
    if not path.endswith("/token") or method != "POST":
        return _respond(404, {"error": "not_found"})

    params = _parse_body(event)
    grant_type = params.get("grant_type", [""])[0]
    scope = params.get("scope", [IDP_SCOPE or "kafka"])[0]
    # The STS JWT arrives as `assertion` (IAM_JWT_BEARER) or `subject_token`
    # (token-exchange).
    sts_jwt = params.get("assertion", [""])[0] or params.get("subject_token", [""])[0]

    if grant_type not in (GRANT_JWT_BEARER, GRANT_TOKEN_EXCHANGE):
        return _respond(400, {
            "error": "unsupported_grant_type",
            "error_description": f"expected {GRANT_JWT_BEARER} or {GRANT_TOKEN_EXCHANGE}",
        })
    if not sts_jwt:
        return _respond(400, {
            "error": "invalid_request",
            "error_description": "assertion/subject_token (STS JWT) is required",
        })

    try:
        claims = validate_sts_jwt(sts_jwt)
    except Exception as e:  # noqa: BLE001 - surface as OAuth error
        return _respond(401, {"error": "invalid_grant", "error_description": str(e)})
    print(f"Validated STS identity: {claims.get('sub')}")

    try:
        tok = exchange_for_downstream_token(sts_jwt, claims)
    except Exception as e:  # noqa: BLE001
        return _respond(502, {"error": "server_error", "error_description": str(e)})

    return _respond(200, {
        "access_token": tok["access_token"],
        "token_type": "Bearer",
        "expires_in": tok.get("expires_in", 300),
        "scope": tok.get("scope", scope),
    })


# --- helpers -----------------------------------------------------------------

def _method_and_path(event):
    """Support both API Gateway REST (v1) and HTTP API (v2) event shapes."""
    rc = event.get("requestContext", {})
    if "http" in rc:
        return rc["http"]["method"], rc["http"]["path"]
    return event.get("httpMethod", "GET"), event.get("path", "/")


def _parse_body(event):
    body = event.get("body", "") or ""
    if event.get("isBase64Encoded") and body:
        body = base64.b64decode(body).decode("utf-8")
    return parse_qs(body)


def _respond(status, body):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json", "Cache-Control": "no-store"},
        "body": json.dumps(body),
    }
