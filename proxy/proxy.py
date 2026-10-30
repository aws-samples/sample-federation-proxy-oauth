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
  2. Authenticates the caller by fully validating that STS JWT: the signature is
     verified against the AWS STS JWKS of an allowlisted issuer, and the issuer,
     audience, subject, expiry and lifetime claims are enforced. There is no
     claim-only mode: unsigned claims are attacker-controlled and prove nothing.
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
The proxy refuses to start (raises at import) if any REQUIRED value is missing.

  TRUSTED_ISSUERS       REQUIRED. Comma-separated STS issuer URLs to trust, i.e. the
                        account's outbound identity federation issuer
                        (`aws iam get-outbound-web-identity-federation-info`).
  TRUSTED_AUDIENCES     REQUIRED. Comma-separated audiences; must include the
                        audience the Replicator is configured to request.
  TRUSTED_SUBJECTS      REQUIRED. Comma-separated IAM role ARNs allowed to obtain a
                        token (the Replicator's service execution role).
  ALLOWED_ALGORITHMS    Signing algorithms accepted. Default "RS256,ES384".
  JWKS_SECRET_ARN       Secrets Manager secret holding {"<issuer>": <JWKS>, ...},
                        kept fresh by a scheduled refresher. Use this when the proxy
                        has no internet egress. If unset, the JWKS is fetched
                        directly from each trusted issuer (needs egress).
  IDP_TOKEN_ENDPOINT    Downstream IdP token endpoint (HTTPS).
  IDP_CLIENT_SECRET_ARN Secrets Manager secret {"client_id": ..., "client_secret": ...}
                        for the downstream IdP client.
  IDP_CLIENT_ID         Optional override of the client id from the secret.
  IDP_SCOPE             Optional OAuth scope to request downstream.
  IDP_CA_PEM            Optional PEM of a private CA that signed the IdP TLS cert.
  EXCHANGE_MODE         "client_credentials" (default) or "token_exchange".
"""

import base64
import json
import os
import re
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


def _csv(name, default=""):
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


TRUSTED_ISSUERS = _csv("TRUSTED_ISSUERS")
TRUSTED_AUDIENCES = _csv("TRUSTED_AUDIENCES")
TRUSTED_SUBJECTS = _csv("TRUSTED_SUBJECTS")
ALLOWED_ALGORITHMS = _csv("ALLOWED_ALGORITHMS", "RS256,ES384")
JWKS_SECRET_ARN = os.environ.get("JWKS_SECRET_ARN", "")

IDP_TOKEN_ENDPOINT = os.environ.get("IDP_TOKEN_ENDPOINT", "")
IDP_CLIENT_SECRET_ARN = os.environ.get("IDP_CLIENT_SECRET_ARN", "")
IDP_CLIENT_ID = os.environ.get("IDP_CLIENT_ID", "")
IDP_SCOPE = os.environ.get("IDP_SCOPE", "")
IDP_CA_PEM = os.environ.get("IDP_CA_PEM", "")
EXCHANGE_MODE = os.environ.get("EXCHANGE_MODE", "client_credentials").lower()

JWKS_CACHE_TTL = 300
JWKS_MIN_REFRESH_INTERVAL = 30  # bound forced refreshes on unknown kids
SECRET_CACHE_TTL = 300
MAX_TOKEN_LIFETIME = 3600       # GetWebIdentityToken DurationSeconds maximum
CLOCK_SKEW_LEEWAY = 30

_SUPPORTED_ALGORITHMS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}


def _config_errors():
    errors = []
    if not TRUSTED_ISSUERS:
        errors.append("TRUSTED_ISSUERS is required")
    if any(not i.startswith("https://") for i in TRUSTED_ISSUERS):
        errors.append("TRUSTED_ISSUERS entries must be https:// URLs")
    if not TRUSTED_AUDIENCES:
        errors.append("TRUSTED_AUDIENCES is required")
    if not TRUSTED_SUBJECTS:
        errors.append("TRUSTED_SUBJECTS is required")
    if not ALLOWED_ALGORITHMS or not set(ALLOWED_ALGORITHMS) <= _SUPPORTED_ALGORITHMS:
        errors.append(f"ALLOWED_ALGORITHMS must be a subset of {sorted(_SUPPORTED_ALGORITHMS)}")
    if EXCHANGE_MODE not in ("client_credentials", "token_exchange"):
        errors.append("EXCHANGE_MODE must be client_credentials or token_exchange")
    if EXCHANGE_MODE == "client_credentials" and not IDP_CLIENT_SECRET_ARN:
        errors.append("IDP_CLIENT_SECRET_ARN is required for EXCHANGE_MODE=client_credentials")
    if not IDP_TOKEN_ENDPOINT.startswith("https://"):
        errors.append("IDP_TOKEN_ENDPOINT must be an https:// URL")
    return errors


# Fail closed: a misconfigured proxy must not start, rather than start and
# accept tokens it cannot properly authenticate.
_errors = _config_errors()
if _errors:
    raise RuntimeError("Federation proxy misconfigured: " + "; ".join(_errors))

# Write the IdP CA to a temp file once so `requests` can trust a private CA.
_CA_FILE = None
if IDP_CA_PEM:
    _CA_FILE = os.path.join(tempfile.gettempdir(), "idp-ca.pem")
    with open(_CA_FILE, "w", encoding="utf-8") as f:
        f.write(IDP_CA_PEM)

_verify = _CA_FILE or True

_jwks = {"keys_by_issuer": {}, "fetched_at": 0.0}
_secret_cache = {}
_sm_client = None


# --- AWS helpers -------------------------------------------------------------

def _get_secret_json(arn):
    """Read and cache a JSON secret from Secrets Manager (reached through the
    VPC's Secrets Manager interface endpoint)."""
    global _sm_client
    cached = _secret_cache.get(arn)
    if cached and time.time() - cached[0] < SECRET_CACHE_TTL:
        return cached[1]
    if _sm_client is None:
        import boto3  # provided by the Lambda runtime
        _sm_client = boto3.client("secretsmanager")
    value = json.loads(_sm_client.get_secret_value(SecretId=arn)["SecretString"])
    _secret_cache[arn] = (time.time(), value)
    return value


# --- STS JWT validation ------------------------------------------------------

def _unverified_claims(token):
    """Read a JWT's claims WITHOUT verifying the signature.

    Used ONLY to pick which allowlisted issuer's key set to verify against.
    Nothing read here is trusted: every claim is re-checked by `jwt.decode`
    after the signature has been verified.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed JWT")
    payload_b64 = parts[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)  # restore base64 padding
    claims = json.loads(base64.urlsafe_b64decode(payload_b64))
    if not isinstance(claims, dict):
        raise ValueError("Malformed JWT")
    return claims


def _load_jwks():
    """Return {issuer: jwks} for the trusted issuers only.

    Keys are never fetched from a URL taken from the token: only from the
    refresher-maintained secret or from the configured TRUSTED_ISSUERS.
    """
    if JWKS_SECRET_ARN:
        _secret_cache.pop(JWKS_SECRET_ARN, None)
        stored = _get_secret_json(JWKS_SECRET_ARN)
        return {iss: stored[iss] for iss in TRUSTED_ISSUERS if iss in stored}
    out = {}
    for iss in TRUSTED_ISSUERS:
        resp = requests.get(f"{iss.rstrip('/')}/.well-known/jwks.json", timeout=10)
        resp.raise_for_status()
        out[iss] = resp.json()
    return out


def _signing_key(issuer, kid, alg, allow_refresh=True):
    now = time.time()
    if now - _jwks["fetched_at"] >= JWKS_CACHE_TTL:
        _jwks["keys_by_issuer"], _jwks["fetched_at"] = _load_jwks(), now
    keys = _jwks["keys_by_issuer"].get(issuer, {}).get("keys", [])
    kd = next((k for k in keys if k.get("kid") == kid), None)
    if kd is None:
        # Possibly a key rotation: refresh once, rate-limited.
        if allow_refresh and now - _jwks["fetched_at"] >= JWKS_MIN_REFRESH_INTERVAL:
            _jwks["fetched_at"] = 0.0
            return _signing_key(issuer, kid, alg, allow_refresh=False)
        raise ValueError(f"No trusted signing key for kid {kid}")
    if kd.get("alg") and kd["alg"] != alg:
        raise ValueError("Token alg does not match the signing key")
    return jwt.PyJWK(kd, algorithm=alg).key  # raises if the key type does not fit alg


_ROLE_ARN = re.compile(r"^arn:(aws[a-z-]*):iam::(\d{12}):role/(?:[^/]+/)*([\w+=,.@-]+)$")


def _role_key(arn):
    m = _ROLE_ARN.match(arn or "")
    return m.groups() if m else None


# IAM role names are unique per account regardless of path, so a role is
# matched on (partition, account, name). This tolerates the role path being
# present in TRUSTED_SUBJECTS but not in the STS `sub` claim, or vice versa.
_TRUSTED_ROLE_KEYS = {k for k in map(_role_key, TRUSTED_SUBJECTS) if k}


def _subject_trusted(sub):
    if sub in TRUSTED_SUBJECTS:
        return True
    key = _role_key(sub)
    return key is not None and key in _TRUSTED_ROLE_KEYS


def validate_sts_jwt(token):
    """Authenticate the caller from the AWS STS JWT presented by the Replicator.

    The signature is always verified against the JWKS of an allowlisted issuer,
    then issuer, audience, expiry, issued-at, lifetime and subject are enforced.
    Returns the verified claims on success; raises ValueError (or a PyJWT
    error) otherwise.
    """
    header = jwt.get_unverified_header(token)
    alg, kid = header.get("alg"), header.get("kid")
    if alg not in ALLOWED_ALGORITHMS:
        raise ValueError(f"Disallowed signing algorithm: {alg}")
    if not kid:
        raise ValueError("Missing kid")

    issuer = _unverified_claims(token).get("iss")
    if issuer not in TRUSTED_ISSUERS:
        raise ValueError("Untrusted issuer")

    claims = jwt.decode(
        token,
        _signing_key(issuer, kid, alg),
        algorithms=[alg],
        issuer=issuer,
        audience=TRUSTED_AUDIENCES,
        leeway=CLOCK_SKEW_LEEWAY,
        options={"require": ["iss", "aud", "sub", "exp", "iat"]},
    )
    if claims["exp"] - claims["iat"] > MAX_TOKEN_LIFETIME:
        raise ValueError("Token lifetime exceeds maximum")
    if not _subject_trusted(claims["sub"]):
        raise ValueError(f"Untrusted subject: {claims['sub']}")
    return claims


# --- Downstream token acquisition -------------------------------------------

def _idp_client_credentials():
    """(client_id, client_secret) for the downstream IdP, from Secrets Manager."""
    if not IDP_CLIENT_SECRET_ARN:
        return IDP_CLIENT_ID, ""
    creds = _get_secret_json(IDP_CLIENT_SECRET_ARN)
    return IDP_CLIENT_ID or creds.get("client_id", ""), creds.get("client_secret", "")


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
    client_id, client_secret = _idp_client_credentials()
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
        if client_id:
            data["client_id"] = client_id
        if client_secret:
            data["client_secret"] = client_secret
    else:
        # client_credentials (default): the proxy holds a downstream client and
        # mints a token on the validated identity's behalf. Fully self-contained.
        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
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

    # Failure details are logged, not returned, so callers cannot use the error
    # text to probe the validation rules or read IdP responses.
    try:
        claims = validate_sts_jwt(sts_jwt)
    except Exception as e:  # noqa: BLE001 - every failure is an OAuth invalid_grant
        print(f"Rejected STS JWT: {type(e).__name__}: {e}")
        return _respond(401, {"error": "invalid_grant",
                              "error_description": "STS JWT validation failed"})
    print(f"Validated STS identity: {claims['sub']}")

    try:
        tok = exchange_for_downstream_token(sts_jwt, claims)
    except Exception as e:  # noqa: BLE001
        print(f"Downstream token request failed: {type(e).__name__}: {e}")
        return _respond(502, {"error": "server_error",
                              "error_description": "downstream token request failed"})

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
