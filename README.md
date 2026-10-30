# federation-proxy-oauth

A complete, runnable reference for migrating a **self-managed, OAuth-authenticated
Apache Kafka** cluster to **Amazon Managed Streaming for Apache Kafka (Amazon MSK)**
with **Amazon MSK Replicator**, where the source Kafka's identity provider sits behind
an enterprise **federation / token-exchange** chain instead of a plain OAuth endpoint.

It deploys most of the components you need — the OAuth IdP, the self-managed Kafka
source, the target Amazon MSK cluster, the network path, and a **federation proxy**
that lets Amazon MSK Replicator authenticate through a multi-hop identity chain using a
single, standard OAuth token endpoint.

> Why this exists: Amazon MSK Replicator's OAuth contract is intentionally narrow — one
> token endpoint, one grant type, a standard token response. Enterprises whose real
> auth path is multi-hop (identity federation, token exchange, claim enrichment, an
> IdP that needs mutual TLS) can't expose that directly. The **federation proxy**
> collapses the chain behind the single endpoint the Replicator expects. See
> [docs/architecture.md](docs/architecture.md) for the full design and token flow.

## What gets deployed

| Stack | Template | Role |
|-------|----------|------|
| 1 | `cfn/01-self-managed-kafka-keycloak.yaml` | Self-managed KRaft Kafka (SASL_SSL / OAUTHBEARER) + Keycloak IdP — the migration **source** |
| 2 | `cfn/02-msk.yaml` | 3-broker Amazon MSK cluster (IAM auth) — the migration **target** |
| 3 | `cfn/03-vpc-peering.yaml` | VPC peering + private DNS + Replicator Service Execution Role + a bastion for smoke tests |
| 4 | `cfn/04-federation-proxy.yaml` | VPC-attached Lambda behind a **private** API Gateway — the federation proxy (`POST /token`) |

The Amazon MSK Replicator itself is created by `scripts/create-replicator.sh` (grant type
`IAM_JWT_BEARER`), not by CloudFormation.

```
 Self-managed VPC (10.10.0.0/16)                 Amazon MSK VPC (10.20.0.0/16)
┌──────────────────────────────┐   VPC peering ┌─────────────────────────────────────────────┐
│  Kafka (KRaft) SASL_SSL :9096 │◀─────────────▶│  Amazon MSK (3 brokers, IAM auth)           │
│  Keycloak IdP :8443           │  + private    │  Amazon MSK Replicator ENIs ──▶ federation  │
│  realm "kafka"                │    DNS zone   │  proxy Lambda (private API /token)          │
└──────────────────────────────┘               └─────────────────────────────────────────────┘
```

## Repository layout

```
cfn/       CloudFormation templates for the four stacks
proxy/     The federation proxy Lambda (proxy.py) + unit tests + requirements
scripts/   Deploy, package, create-replicator, describe-replicator, smoke-test
docs/      Architecture and token-flow documentation
```

## Prerequisites

- An AWS account and the **AWS CLI v2** configured (`aws sts get-caller-identity` works).
- Python 3.12+ and `pip` (to package the Lambda and run the proxy unit tests).
- [`awscurl`](https://github.com/okigan/awscurl) — only if you submit the replicator
  via a preview endpoint (`REPLICATOR_API_BASE`); not needed for the public path.
- An S3 bucket you own (for the packaged proxy Lambda zip).
- Amazon MSK Replicator OAuth authentication available in your account/region.
- **IAM outbound identity federation enabled** in the account, so the Replicator can mint
  signed STS JWTs and the proxy can verify them. Enable it once with
  `aws iam enable-outbound-web-identity-federation`; the issuer URL the proxy trusts is
  `aws iam get-outbound-web-identity-federation-info --query IssuerIdentifier`.

## Configuration

There are **no default credentials**. Stack 1 generates the Keycloak client secrets
(`kafka-broker`, `kafka-producer`, `kafka-consumer`) and the Keycloak admin password in
AWS Secrets Manager at deploy time; the instance reads them at boot. The federation proxy
reads the `kafka-producer` credentials from the same secret, so nothing has to be kept in
sync by hand. The only remaining password parameter is the local keystore password.

| Stack | Parameter | Default | Notes |
|-------|-----------|---------|-------|
| 1 | `KeystorePassword` | `changeit` | Recommended to override — broker PKCS12 keystore/truststore password |
| 1 | `KeycloakAdminUser` | `admin` | Optional — Keycloak admin username (password is generated; see output `KeycloakAdminSecretArn`) |
| 3 | `KeystorePassword` | `changeit` | Recommended to override — bastion truststore password |
| 4 | `TrustedIssuers` | **required** | STS outbound identity federation issuer URL(s) (`deploy-all.sh` resolves it) |
| 4 | `TrustedAudience` | **required** | Audience the Replicator requests (`deploy-all.sh` default: `federation-proxy-<stack>`) |
| 4 | `TrustedSubjects` | `` → Stack 3 Replicator role | IAM role ARN(s) allowed to obtain a token |
| 4 | `PeeringStackName` | `vpc-peering` | Stack 3 name (source of the Replicator role ARN) |
| 4 | `IdpClientSecretArn` | `` → Stack 1 `kafka-producer` secret | Secret `{"client_id","client_secret"}` the proxy uses at the IdP |
| 4 | `IdpClientId` | `` (from the secret) | Optional client id override |
| 4 | `TokenClientSecurityGroupId` | `` → Stack 2 MSK SG | The only security group allowed to reach the token endpoint (Replicator ENIs) |
| 4 | `ExchangeMode` | `client_credentials` | Optional — `client_credentials` or `token_exchange` |
| 4 | `IdpScope` | `` (empty) | Optional — OAuth scope requested downstream |
| 4 | `ExistingExecuteApiVpceId` | `` (empty) | Set if the VPC already has an `execute-api` endpoint |

## Quick start

### 1. Deploy the stacks

```bash
S3_BUCKET=my-artifacts-bucket PROFILE=my-aws-profile ./scripts/deploy-all.sh
```

The script resolves the account's STS issuer (override with `TRUSTED_ISSUER=`) and stops
if outbound identity federation is not enabled. This deploys stacks 1 and 2 in parallel, then stack 3, then packages the proxy and
deploys stack 4. Stack 1's EC2 bootstrap (Keycloak + Kafka + a self-signed CA) takes
a few minutes after the stack completes; the CA is published to Secrets Manager and
consumed automatically. When it finishes it prints the proxy's token endpoint URL.


> If the target VPC already has an `execute-api` interface endpoint with private DNS,
> pass its id so the proxy reuses it instead of creating a conflicting one:
> add `ExistingExecuteApiVpceId=vpce-...` to the Stack 4 parameters.

### 2. Find the source cluster id

The Replicator references the self-managed source by its KRaft `cluster.id`. Read it
from the Kafka host (via SSM Session Manager on the Stack 1 instance):

```bash
docker exec kafka cat /var/lib/kafka/data/meta.properties | grep cluster.id
# cluster.id=oZVwAJ0-TyOuSuCiwgdaFA   <-- use this value
```

### 3. Create the replicator

```bash
SOURCE_CLUSTER_ID=<cluster.id-from-step-2> PROFILE=my-aws-profile ./scripts/create-replicator.sh
```

The script resolves every ARN, subnet, security group, and the proxy token endpoint
from the CloudFormation stack outputs — nothing is hardcoded.

### 4. Verify

```bash
# Smoke-test the proxy directly: forged/unsigned STS JWTs must be rejected with 401:
PROFILE=my-aws-profile PROXY_STACK=federation-proxy ./scripts/smoke-test.sh

# Poll the replicator until RUNNING:
REPLICATOR_NAME=<name-printed-by-step-3> PROFILE=my-aws-profile ./scripts/describe-replicator.sh
```

Produce a few records to a topic on the source Kafka and confirm they appear on the
target Amazon MSK cluster (the Stack 3 bastion is preconfigured with Kafka CLI clients for
both the OAuth source and the IAM target).

## The federation proxy

`proxy/proxy.py` is the reference proxy. It accepts the Replicator's OAuth request
(`grant_type=jwt-bearer` with `assertion=<STS JWT>`, or `grant_type=token-exchange`
with `subject_token=<STS JWT>`), validates the AWS STS JWT, then obtains a downstream
Bearer token the source Kafka trusts.

Two exchange modes (env var `EXCHANGE_MODE`):

- **`client_credentials`** (default) — the proxy holds a client at the IdP and mints a
  token on the validated identity's behalf. Fully self-contained.
- **`token_exchange`** — RFC 8693; forwards the STS JWT to an IdP that federates AWS
  STS as an external issuer.

To model a **real** multi-hop chain, replace the single function
`exchange_for_downstream_token`. Its contract is stable: input is the validated STS
claims plus the raw STS JWT; output is an `access_token` string. Everything else
(request parsing, STS validation, the OAuth response) stays the same.

### Run the proxy unit tests

```bash
cd proxy
python -m pip install -r requirements.txt pytest
python -m pytest -q
```

## Security notes

- The proxy API is a **private** REST API Gateway, locked by resource policy to the
  VPC's `execute-api` endpoint — not reachable from the internet.
- The token endpoint has no API Gateway authorizer (the Replicator does not SigV4-sign
  token requests), so **the STS JWT is the caller's credential** and the proxy always
  verifies it cryptographically: signature against the trusted issuer's JWKS, plus
  issuer, audience, expiry/lifetime, and `sub` pinned to the Replicator role. There is
  no claim-only mode — unsigned claims are attacker-controlled and prove nothing. The
  proxy refuses to start if the issuer, audience or subject allowlist is empty.
- The proxy runs in **private subnets with no internet egress**. A scheduled, non-VPC
  refresher Lambda copies the trusted issuer's public JWKS into Secrets Manager hourly
  (and at deploy time); the proxy reads it through the VPC's Secrets Manager endpoint.
- Only the Replicator ENIs' security group can reach the `execute-api` endpoint, and the
  proxy Lambda can only reach the Secrets Manager endpoint and Keycloak.
- Downstream IdP credentials are generated in and read from AWS Secrets Manager; they
  are not passed as parameters or Lambda environment variables.
- The demo source broker has no Kafka authorizer: any valid IdP token has full access to
  the source cluster. Add ACLs before using this pattern beyond a demo.
- Never commit real credentials, account ids, or ARNs — the scripts resolve them at
  runtime from stack outputs.

## Teardown

Delete in reverse dependency order (delete the replicator first):

```bash
aws cloudformation delete-stack --stack-name federation-proxy
aws cloudformation delete-stack --stack-name vpc-peering
aws cloudformation delete-stack --stack-name msk-target
aws cloudformation delete-stack --stack-name selfmanaged-kafka
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for how to report a
security issue. This is reference/demo software — review and harden the stacks before
any real or long-lived deployment.

## License

[MIT-0](LICENSE). This is reference/demo software; review and harden before any
production use.
