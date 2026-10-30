#!/usr/bin/env bash
# Smoke-test the deployed federation proxy Lambda directly (no Replicator needed).
#
# Invokes the proxy Lambda with forged STS JWTs and checks that EVERY one is rejected
# with 401 invalid_grant, i.e. that the proxy authenticates callers by signature and does
# not hand out downstream tokens for attacker-made JWTs:
#   1. unsigned (alg=none) JWT with Replicator-shaped claims
#   2. HS256 JWT "signed" with a guessed secret
#   3. RS256-shaped JWT whose issuer is not the trusted STS issuer
#
# The positive path (a real, STS-signed JWT from the Replicator's role) is proven by the
# Replicator itself reaching RUNNING (scripts/describe-replicator.sh) and replicating.
#
# Usage:
#   PROFILE=my-profile ./scripts/smoke-test.sh
#
# Env:
#   PROXY_STACK  default: federation-proxy
#   REGION       default: us-east-1
#   PROFILE      optional AWS CLI profile
set -euo pipefail

REGION="${REGION:-us-east-1}"
PROXY_STACK="${PROXY_STACK:-federation-proxy}"
PROFILE_ARG=""
[ -n "${PROFILE:-}" ] && PROFILE_ARG="--profile ${PROFILE}"

out() { aws cloudformation describe-stacks --stack-name "$PROXY_STACK" --region "$REGION" ${PROFILE_ARG} \
  --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }
LAMBDA=$(out ProxyLambdaName)
AUDIENCE=$(out TrustedAudience)
[ -z "$LAMBDA" ] || [ "$LAMBDA" = "None" ] && { echo "proxy Lambda not found in stack $PROXY_STACK"; exit 1; }

EVENTS=$(python3 - "$AUDIENCE" <<'PY'
import base64, hashlib, hmac, json, sys, time
aud = sys.argv[1]
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def seg(d): return b64(json.dumps(d).encode())
now = int(time.time())
claims = {"sub": "arn:aws:iam::111122223333:role/service-role/replicator", "aud": aud,
          "iss": "https://attacker.example", "iat": now, "exp": now + 300}
forged = {}
forged["alg-none"] = f'{seg({"alg": "none", "typ": "JWT"})}.{seg(claims)}.'
h, p = seg({"alg": "HS256", "kid": "x"}), seg(claims)
forged["hs256-guess"] = f'{h}.{p}.' + b64(hmac.new(b"guess", f"{h}.{p}".encode(), hashlib.sha256).digest())
h = seg({"alg": "RS256", "kid": "attacker-key"})
forged["rs256-attacker-iss"] = f'{h}.{p}.' + b64(b"\0" * 256)
for name, tok in forged.items():
    body = f"grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={tok}&scope=kafka"
    print(name, json.dumps({"requestContext": {"http": {"method": "POST", "path": "/prod/token"}},
                            "body": body, "isBase64Encoded": False}))
PY
)

OUT=$(mktemp)
trap 'rm -f "$OUT"' EXIT
FAILED=0
while read -r NAME EVENT; do
  aws lambda invoke --function-name "$LAMBDA" --region "$REGION" ${PROFILE_ARG} \
    --cli-binary-format raw-in-base64-out --payload "$EVENT" "$OUT" >/dev/null
  if python3 - "$OUT" <<'PY'
import json, sys
resp = json.load(open(sys.argv[1]))
body = json.loads(resp.get("body", "{}"))
ok = resp.get("statusCode") == 401 and body.get("error") == "invalid_grant" and "access_token" not in body
print(("  rejected" if ok else "  NOT REJECTED"), resp.get("statusCode"), json.dumps(body))
sys.exit(0 if ok else 1)
PY
  then echo "PASS: forged JWT ($NAME) rejected"
  else echo "FAIL: forged JWT ($NAME) was not rejected"; FAILED=1
  fi
done <<< "$EVENTS"

[ "$FAILED" -eq 0 ] && echo "PASS: proxy rejects forged STS JWTs" || { echo "FAIL"; exit 1; }
