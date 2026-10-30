# Architecture

## The problem

Amazon MSK Replicator can authenticate to a self-managed Apache Kafka source with
OAuth (SASL/OAUTHBEARER). Its OAuth contract is deliberately **narrow**: the
Replicator calls exactly **one** token endpoint, with **one** grant type, and
expects a standard OAuth token response. It refreshes the token automatically.

Many enterprises cannot expose such a simple endpoint. Their real authentication
path is **multi-hop**: an AWS identity is federated through one or more internal
services (token exchange, claim enrichment, an IdP that requires mutual TLS, an
IdP migration in progress, etc.) before a token the Kafka brokers accept is
finally issued.

## The pattern: a federation proxy

The enterprise deploys a small **federation proxy** in its own VPC and points the
Replicator's `tokenEndpointUrl` at it. From the Replicator's point of view the
proxy is an ordinary OAuth token endpoint. Behind it, the proxy collapses the
enterprise's multi-hop chain into the single-endpoint contract the Replicator
expects. Everything behind the proxy is owned by the customer and opaque to the
Replicator.

This repository is a complete, runnable reference implementation of that pattern.

## Components

```
 Self-managed VPC (10.10.0.0/16)                 MSK VPC (10.20.0.0/16)
┌──────────────────────────────┐   VPC peering ┌────────────────────────────────────┐
│  EC2: self-managed Kafka      │◀─────────────▶│  MSK cluster (3 brokers, IAM auth)  │
│   - KRaft, SASL_SSL :9096     │  + Route53    │                                     │
│     OAUTHBEARER (Strimzi)     │  private zone │  MSK Replicator ENIs ───────────┐   │
│  Keycloak IdP :8443           │               │   (in private subnets)          │   │
│   - realm "kafka"             │               │                                 ▼   │
└──────────────────────────────┘               │  Federation proxy (Lambda)          │
                                                │   behind PRIVATE API Gateway        │
                                                │   POST /token                       │
                                                └────────────────────────────────────┘
```

- **Stack 1 — self-managed Kafka + Keycloak** (the migration *source*). A single
  EC2 host runs Keycloak (the IdP, realm `kafka`) and a KRaft Kafka broker whose
  `SASL_SSL` listener validates OAUTHBEARER tokens against Keycloak's JWKS.
- **Stack 2 — MSK** (the migration *target*). A 3-broker MSK cluster with IAM
  authentication. The Replicator's ENIs live in this VPC.
- **Stack 3 — VPC peering + DNS + Replicator prerequisites**. Peers the two VPCs,
  publishes a private hosted zone so the broker/IdP hostname resolves from the MSK
  VPC, and creates the Replicator's Service Execution Role (SER) and log group.
- **Stack 4 — federation proxy**. A VPC-attached Lambda in the MSK private subnets,
  exposed as `POST /token` behind a **private** API Gateway reachable only from
  inside the VPC (via an `execute-api` interface VPC endpoint).

## Token flow (IAM_JWT_BEARER)

```
Replicator                Federation proxy            Enterprise IdP (Keycloak)      Source Kafka
    │                          │                              │                          │
    │ 1. STS GetWebIdentityToken (its own IAM identity as a signed JWT)                   │
    │                          │                              │                          │
    │ 2. POST /token           │                              │                          │
    │   grant_type=jwt-bearer  │                              │                          │
    │   assertion=<STS JWT> ──▶ │                              │                          │
    │                          │ 3. verify STS JWT signature  │                          │
    │                          │    (trusted issuer's JWKS);  │                          │
    │                          │    enforce iss/aud/exp/sub   │                          │
    │                          │ 4. exchange for downstream ─▶ │                          │
    │                          │    token (client_credentials │                          │
    │                          │    or RFC 8693 token-exchange)│                          │
    │                          │ ◀── access_token (Bearer)    │                          │
    │ ◀── {access_token} ───── │                              │                          │
    │                          │                              │                          │
    │ 5. SASL/OAUTHBEARER handshake with the Bearer ─────────────────────────────────────▶│
    │                          │                              │  6. broker validates the  │
    │                          │                              │     Bearer via Keycloak   │
    │                          │                              │     JWKS, then serves data│
```

The Replicator obtains a signed JWT representing **its own IAM identity** from AWS
STS (`GetWebIdentityToken`), then presents that JWT to the proxy as the OAuth
`assertion`. The proxy verifies its signature against the trusted STS issuer's JWKS,
enforces the issuer, audience, expiry and subject (the Replicator role), and only then
returns a downstream Bearer that the source Kafka brokers trust.

The token endpoint has no API Gateway authorizer, so this JWT is the caller's only
credential: anything that can reach the endpoint can send a request, and only a JWT that
AWS STS signed for the Replicator role gets a token back.

## Exchange modes

The proxy's single adaptation seam is `exchange_for_downstream_token`. Two modes
ship out of the box (env var `EXCHANGE_MODE`):

| Mode | What the proxy does | When to use |
|------|---------------------|-------------|
| `client_credentials` (default) | Holds a client_id/secret at the IdP and mints a token on the validated identity's behalf. Fully self-contained. | Demos; IdPs that don't federate AWS STS. |
| `token_exchange` | RFC 8693. Forwards the STS JWT to an IdP that federates AWS STS as an external issuer. | IdPs configured to trust AWS STS directly. |

For a **real** multi-hop chain, replace `exchange_for_downstream_token` with your
own orchestration. Its contract is stable: input is the validated STS claims plus
the raw STS JWT; output is an `access_token` string.

## Security properties

- The proxy API is a **private** REST API Gateway, locked by a resource policy to
  the `execute-api` VPC endpoint — it is not reachable from the internet.
- Only the Replicator ENIs' security group may reach the `execute-api` endpoint.
- The proxy always verifies the STS JWT signature; there is no claim-only mode, since
  unsigned claims are attacker-controlled. It refuses to start without non-empty issuer,
  audience and subject allowlists, fetches keys only for allowlisted issuers (never from
  a URL named in the token), pins the accepted algorithms, and requires `exp`/`iat`
  with a bounded lifetime.
- The proxy runs in **private subnets** with no internet egress. A scheduled, non-VPC
  refresher Lambda copies the trusted issuer's public JWKS into Secrets Manager; the
  proxy reads it through the VPC's Secrets Manager interface endpoint. Unknown key ids
  trigger a rate-limited re-read to follow key rotation.
- Downstream IdP credentials are generated in AWS Secrets Manager by Stack 1 and read
  by the proxy at runtime; no default credentials exist.
- The Replicator authenticates to the target MSK with IAM (no shared secret).
