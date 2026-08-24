#!/usr/bin/env bash
# Deploy the full federation-proxy-oauth stack set:
#   Stack 1 (self-managed Kafka + Keycloak)  and  Stack 2 (target MSK)  in parallel,
#   then Stack 3 (VPC peering + DNS + SER + bastion),
#   then package the proxy Lambda and deploy Stack 4 (federation proxy).
#
# Usage:
#   S3_BUCKET=my-artifacts-bucket PROFILE=my-profile ./scripts/deploy-all.sh
#
# Env:
#   S3_BUCKET   (required) S3 bucket for the packaged proxy zip
#   PROFILE     (optional) AWS CLI profile
#   REGION      (optional) default us-east-1
#   EXCHANGE_MODE (optional) client_credentials (default) | token_exchange
set -euo pipefail

: "${S3_BUCKET:?set S3_BUCKET to an S3 bucket you own (for the proxy Lambda zip)}"
REGION="${REGION:-us-east-1}"
EXCHANGE_MODE="${EXCHANGE_MODE:-client_credentials}"
PROFILE_ARG=""
[ -n "${PROFILE:-}" ] && PROFILE_ARG="--profile ${PROFILE}"

SELF_MANAGED_STACK="${SELF_MANAGED_STACK:-selfmanaged-kafka}"
MSK_STACK="${MSK_STACK:-msk-target}"
PEERING_STACK="${PEERING_STACK:-vpc-peering}"
PROXY_STACK="${PROXY_STACK:-federation-proxy}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CFN="${ROOT}/cfn"

deploy() { # deploy <stack-name> <template> [extra args...]
  aws cloudformation deploy --region "$REGION" ${PROFILE_ARG} \
    --stack-name "$1" --template-file "$2" \
    --no-fail-on-empty-changeset "${@:3}"
}
out() { aws cloudformation describe-stacks --stack-name "$1" --region "$REGION" ${PROFILE_ARG} \
  --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text; }

echo "=== Stacks 1 + 2 (parallel) ==="
deploy "$SELF_MANAGED_STACK" "${CFN}/01-self-managed-kafka-keycloak.yaml" --capabilities CAPABILITY_IAM \
  > /tmp/deploy-1.log 2>&1 &
P1=$!
deploy "$MSK_STACK" "${CFN}/02-msk.yaml" > /tmp/deploy-2.log 2>&1 &
P2=$!
wait $P1 || { echo "Stack 1 FAILED"; tail -30 /tmp/deploy-1.log; exit 1; }
wait $P2 || { echo "Stack 2 FAILED"; tail -30 /tmp/deploy-2.log; exit 1; }
echo "Stacks 1 & 2 done."

echo "=== Stack 3 (peering + DNS + SER + bastion) ==="
deploy "$PEERING_STACK" "${CFN}/03-vpc-peering.yaml" --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides "SelfManagedStackName=${SELF_MANAGED_STACK}" "MskStackName=${MSK_STACK}"

echo "=== Package + deploy Stack 4 (federation proxy) ==="
S3_BUCKET="$S3_BUCKET" S3_KEY="federation-proxy/proxy.zip" \
  PROFILE="${PROFILE:-}" REGION="$REGION" "${ROOT}/scripts/package-proxy.sh"

# Pull the self-signed CA PEM from Stack 1's secret so the proxy Lambda trusts the IdP.
CA_SECRET_ARN=$(out "$SELF_MANAGED_STACK" SourceCaSecretArn)
CA_PEM=$(aws secretsmanager get-secret-value --secret-id "$CA_SECRET_ARN" --region "$REGION" ${PROFILE_ARG} \
  --query SecretString --output text | python3 -c "import sys,json;print(json.load(sys.stdin)['certificate'])")

deploy "$PROXY_STACK" "${CFN}/04-federation-proxy.yaml" --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    "SelfManagedStackName=${SELF_MANAGED_STACK}" "MskStackName=${MSK_STACK}" \
    "LambdaCodeS3Bucket=${S3_BUCKET}" "LambdaCodeS3Key=federation-proxy/proxy.zip" \
    "ExchangeMode=${EXCHANGE_MODE}" "IdpCaPem=${CA_PEM}"

echo
echo "=== Done. Proxy token endpoint: ==="
out "$PROXY_STACK" TokenEndpointUrl
echo
echo "Next: create the replicator (needs the source KRaft cluster.id — see README):"
echo "  SOURCE_CLUSTER_ID=<id> PROFILE=${PROFILE:-} ./scripts/create-replicator.sh"
