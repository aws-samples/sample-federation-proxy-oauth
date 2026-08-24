#!/usr/bin/env bash
# Smoke-test the deployed federation proxy Lambda directly (no Replicator needed).
#
# Builds a synthetic API Gateway event carrying an IAM_JWT_BEARER token request with a
# minimal STS-shaped JWT (sub = an AWS ARN), invokes the proxy Lambda, and checks that
# the proxy validated the identity and returned a downstream Bearer from the IdP.
#
# This exercises the full proxy path: request parsing -> STS-claim validation ->
# downstream token acquisition from Keycloak.
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

LAMBDA=$(aws cloudformation describe-stacks --stack-name "$PROXY_STACK" --region "$REGION" ${PROFILE_ARG} \
  --query "Stacks[0].Outputs[?OutputKey=='ProxyLambdaName'].OutputValue" --output text)
[ -z "$LAMBDA" ] || [ "$LAMBDA" = "None" ] && { echo "proxy Lambda not found in stack $PROXY_STACK"; exit 1; }

# A minimal unsigned JWT with an AWS-ARN subject. The proxy does claim-only checks by
# default (VALIDATE_STS_JWT=false), so an unsigned token with the right shape is accepted;
# this validates the request/validation/downstream-mint path end to end.
EVENT=$(python3 - <<'PY'
import base64, json, time
def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()
hdr = b64({"alg": "none", "typ": "JWT"})
claims = b64({"sub": "arn:aws:sts::111122223333:assumed-role/Replicator/smoke",
              "iss": "https://sts.amazonaws.com", "aud": "kafka",
              "exp": int(time.time()) + 300})
jwt = f"{hdr}.{claims}."
body = f"grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={jwt}&scope=kafka"
print(json.dumps({
    "requestContext": {"http": {"method": "POST", "path": "/prod/token"}},
    "body": body, "isBase64Encoded": False,
}))
PY
)

echo ">>> invoking ${LAMBDA}"
OUT=$(mktemp)
aws lambda invoke --function-name "$LAMBDA" --region "$REGION" ${PROFILE_ARG} \
  --cli-binary-format raw-in-base64-out --payload "$EVENT" "$OUT" >/dev/null

python3 - "$OUT" <<'PY'
import json, sys
resp = json.load(open(sys.argv[1]))
status = resp.get("statusCode")
body = json.loads(resp.get("body", "{}"))
print("statusCode:", status)
if status == 200 and body.get("access_token"):
    print("PASS: proxy returned a downstream Bearer token")
    print("token_type:", body.get("token_type"), "expires_in:", body.get("expires_in"))
    tok = body["access_token"]
    print("access_token (prefix):", tok[:24] + "...")
    sys.exit(0)
print("FAIL:", json.dumps(body))
sys.exit(1)
PY
rc=$?
rm -f "$OUT"
exit $rc
