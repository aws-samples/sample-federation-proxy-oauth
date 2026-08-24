#!/usr/bin/env bash
# Poll an MSK Replicator's state (and stateInfo on failure).
#
# Usage:
#   REPLICATOR_ARN=arn:aws:kafka:...:replicator/... ./scripts/describe-replicator.sh
#   REPLICATOR_NAME=federation-proxy-repl-123456     ./scripts/describe-replicator.sh
#
# Env:
#   REGION               default: us-east-1
#   PROFILE              optional AWS CLI profile
#   REPLICATOR_API_BASE  optional preview REST base (uses awscurl); else the public CLI
set -euo pipefail

REGION="${REGION:-us-east-1}"
PROFILE_ARG=""
[ -n "${PROFILE:-}" ] && PROFILE_ARG="--profile ${PROFILE}"

if [ -n "${REPLICATOR_API_BASE:-}" ]; then
  base="${REPLICATOR_API_BASE%/}"
  arn="${REPLICATOR_ARN:-}"
  if [ -z "$arn" ]; then
    arn=$(awscurl --service kafka --region "$REGION" ${PROFILE:+--profile $PROFILE} "${base}/replicators" 2>/dev/null \
      | python3 -c "import sys,json,os;n=os.environ.get('REPLICATOR_NAME','');rs=[r for r in json.load(sys.stdin).get('replicators',[]) if r['replicatorName']==n];print(rs[0]['replicatorArn'] if rs else '')")
  fi
  [ -z "$arn" ] && { echo "replicator not found"; exit 1; }
  enc=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$arn")
  awscurl --service kafka --region "$REGION" ${PROFILE:+--profile $PROFILE} "${base}/replicators/${enc}" 2>/dev/null \
    | python3 -c "import sys,json;d=json.load(sys.stdin);print('state:',d.get('replicatorState'));si=d.get('stateInfo');print('info: ',json.dumps(si)) if si else None"
else
  arn="${REPLICATOR_ARN:-}"
  if [ -z "$arn" ]; then
    arn=$(aws kafka list-replicators --region "$REGION" ${PROFILE_ARG} \
      --query "Replicators[?ReplicatorName=='${REPLICATOR_NAME:-}'].ReplicatorArn | [0]" --output text)
  fi
  [ -z "$arn" ] || [ "$arn" = "None" ] && { echo "replicator not found"; exit 1; }
  aws kafka describe-replicator --replicator-arn "$arn" --region "$REGION" ${PROFILE_ARG} \
    --query "{state:ReplicatorState,info:StateInfo}" --output json
fi
