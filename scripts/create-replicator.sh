#!/usr/bin/env bash
# Create the MSK Replicator for the federation-proxy (IAM_JWT_BEARER) path.
#
# The Replicator reads from the self-managed OAuth Kafka (source) and writes to the
# target MSK cluster. Its OAuth token endpoint is the federation proxy (Stack 4): the
# Replicator sends an STS JWT (assertion), the proxy exchanges it for a Bearer the
# source Kafka trusts.
#
# All coordinates are resolved from CloudFormation stack outputs — nothing is hardcoded.
#
# Usage:
#   PROFILE=my-profile ./scripts/create-replicator.sh
#
# Env (optional overrides; defaults resolve from stacks):
#   SELF_MANAGED_STACK   default: selfmanaged-kafka   (Stack 1)
#   MSK_STACK            default: msk-target          (Stack 2)
#   PEERING_STACK        default: vpc-peering         (Stack 3)
#   PROXY_STACK          default: federation-proxy    (Stack 4)
#   SOURCE_CLUSTER_ID    the apacheKafkaClusterId of the source cluster (REQUIRED — this is
#                        the KRaft cluster.id of the self-managed Kafka; see README)
#   REGION               default: us-east-1
#   REPLICATOR_NAME      default: federation-proxy-repl-<HHMMSS>
#   AUDIENCE             default: kafka   (aud claim minted into the STS JWT)
#   SIGNING_ALGORITHM    default: RS256
#   TOPICS_REGEX         default: .*
#   REPLICATOR_API_BASE  optional. If set (e.g. a preview REST base URL), the request is
#                        POSTed there via awscurl. If unset, `aws kafka create-replicator`
#                        is used (the public path; requires the OAuth-for-Replicator
#                        capability to be available in your account/region).
set -euo pipefail

REGION="${REGION:-us-east-1}"
SELF_MANAGED_STACK="${SELF_MANAGED_STACK:-selfmanaged-kafka}"
MSK_STACK="${MSK_STACK:-msk-target}"
PEERING_STACK="${PEERING_STACK:-vpc-peering}"
PROXY_STACK="${PROXY_STACK:-federation-proxy}"
AUDIENCE="${AUDIENCE:-kafka}"
SIGNING_ALGORITHM="${SIGNING_ALGORITHM:-RS256}"
TOPICS_REGEX="${TOPICS_REGEX:-.*}"
: "${SOURCE_CLUSTER_ID:?set SOURCE_CLUSTER_ID to the self-managed Kafka KRaft cluster.id}"

PROFILE_ARG=""
[ -n "${PROFILE:-}" ] && PROFILE_ARG="--profile ${PROFILE}"

out() { # out <stack> <OutputKey>
  aws cloudformation describe-stacks --stack-name "$1" --region "$REGION" ${PROFILE_ARG} \
    --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text
}

# SER defaults to the one created by Stack 3; override with SER_ARN if you use another.
SER="${SER_ARN:-$(out "$PEERING_STACK" ReplicatorServiceRoleArn)}"
LOG_GROUP="${LOG_GROUP:-$(out "$PEERING_STACK" ReplicatorLogGroup)}"
TARGET_MSK=$(out "$MSK_STACK" MskClusterArn)
SUBNETS_CSV=$(out "$MSK_STACK" PrivateSubnets)
MSK_SG=$(out "$MSK_STACK" MskSecurityGroupId)
SOURCE_BOOTSTRAP="$(out "$SELF_MANAGED_STACK" BrokerHostname):9096"
CA_SECRET=$(out "$SELF_MANAGED_STACK" SourceCaSecretArn)
TOKEN_URL=$(out "$PROXY_STACK" TokenEndpointUrl)

SUBNETS_JSON=$(python3 -c "import sys,json;print(json.dumps(sys.argv[1].split(',')))" "$SUBNETS_CSV")
REPL_NAME="${REPLICATOR_NAME:-federation-proxy-repl-$(date +%H%M%S)}"

BODY=$(cat <<JSON
{
  "replicatorName": "${REPL_NAME}",
  "description": "Federation proxy (IAM_JWT_BEARER) self-managed OAuth Kafka -> MSK",
  "serviceExecutionRoleArn": "${SER}",
  "logDelivery": { "replicatorLogDelivery": { "cloudWatchLogs": { "enabled": true, "logGroup": "${LOG_GROUP}" } } },
  "kafkaClusters": [
    {
      "apacheKafkaCluster": {
        "apacheKafkaClusterId": "${SOURCE_CLUSTER_ID}",
        "bootstrapBrokerString": "${SOURCE_BOOTSTRAP}"
      },
      "clientAuthentication": {
        "saslOAuthBearer": {
          "tokenEndpointUrl": "${TOKEN_URL}",
          "iamJwtBearer": { "audience": "${AUDIENCE}", "signingAlgorithm": "${SIGNING_ALGORITHM}" },
          "tokenEndpointAuthenticationMethod": "NONE"
        }
      },
      "encryptionInTransit": { "encryptionType": "TLS", "rootCaCertificate": "${CA_SECRET}" }
    },
    {
      "amazonMskCluster": { "mskClusterArn": "${TARGET_MSK}" },
      "vpcConfig": { "securityGroupIds": ["${MSK_SG}"], "subnetIds": ${SUBNETS_JSON} }
    }
  ],
  "replicationInfoList": [
    {
      "sourceKafkaClusterId": "${SOURCE_CLUSTER_ID}",
      "targetKafkaClusterArn": "${TARGET_MSK}",
      "targetCompressionType": "NONE",
      "topicReplication": {
        "topicsToReplicate": ["${TOPICS_REGEX}"],
        "detectAndCopyNewTopics": true,
        "copyTopicConfigurations": true,
        "topicNameConfiguration": { "type": "IDENTICAL" },
        "startingPosition": { "type": "EARLIEST" }
      },
      "consumerGroupReplication": {
        "consumerGroupsToReplicate": ["${TOPICS_REGEX}"],
        "detectAndCopyNewConsumerGroups": true,
        "synchroniseConsumerGroupOffsets": true
      }
    }
  ],
  "tags": {}
}
JSON
)

echo "$BODY" | python3 -m json.tool >/dev/null   # validate JSON before sending
echo ">>> creating replicator '${REPL_NAME}'"
echo ">>> tokenEndpointUrl = ${TOKEN_URL}"

if [ -n "${REPLICATOR_API_BASE:-}" ]; then
  # Preview/self-hosted endpoint path (SigV4 via awscurl).
  awscurl --service kafka --region "$REGION" ${PROFILE:+--profile $PROFILE} \
    -X POST -H "Content-Type: application/json" -d "$BODY" \
    "${REPLICATOR_API_BASE%/}/replicators"
else
  # Public path.
  TMP=$(mktemp)
  echo "$BODY" > "$TMP"
  aws kafka create-replicator --region "$REGION" ${PROFILE_ARG} --cli-input-json "file://${TMP}"
  rm -f "$TMP"
fi
echo
echo ">>> done. Poll with: REPLICATOR_NAME='${REPL_NAME}' ./scripts/describe-replicator.sh"
