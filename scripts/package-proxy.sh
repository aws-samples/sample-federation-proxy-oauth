#!/usr/bin/env bash
# Package the federation proxy Lambda (proxy.py + Python deps) into a zip and
# upload it to S3 for Stack 4 to consume.
#
# Usage:
#   S3_BUCKET=my-artifacts-bucket ./scripts/package-proxy.sh
#
# Env:
#   S3_BUCKET  (required) S3 bucket for the packaged zip
#   S3_KEY     (optional) object key. Default: federation-proxy/proxy.zip
#   PROFILE    (optional) AWS CLI profile
#   REGION     (optional) AWS region. Default: us-east-1
set -euo pipefail

: "${S3_BUCKET:?set S3_BUCKET to an S3 bucket you own}"
S3_KEY="${S3_KEY:-federation-proxy/proxy.zip}"
REGION="${REGION:-us-east-1}"
PROFILE_ARG=""
[ -n "${PROFILE:-}" ] && PROFILE_ARG="--profile ${PROFILE}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${ROOT}/proxy/build"

rm -rf "${BUILD}"
mkdir -p "${BUILD}"
# Install Linux (manylinux) wheels so native deps (cryptography) work on the Lambda
# runtime regardless of the host OS the packaging runs on.
python3 -m pip install --quiet --target "${BUILD}" \
  --platform manylinux2014_x86_64 --python-version 3.12 --only-binary :all: \
  -r "${ROOT}/proxy/requirements.txt"
cp "${ROOT}/proxy/proxy.py" "${BUILD}/"

( cd "${BUILD}" && zip -qr "${ROOT}/proxy/proxy.zip" . )
echo ">>> built ${ROOT}/proxy/proxy.zip"

aws s3 cp "${ROOT}/proxy/proxy.zip" "s3://${S3_BUCKET}/${S3_KEY}" \
  --region "${REGION}" ${PROFILE_ARG}
echo ">>> uploaded to s3://${S3_BUCKET}/${S3_KEY}"
