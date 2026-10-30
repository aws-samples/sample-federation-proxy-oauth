"""Test configuration. The proxy refuses to import without its required
settings, so they are set here before any test module imports `proxy`."""
import os
import sys

ISSUER = "https://11111111-2222-3333-4444-555555555555.tokens.sts.global.api.aws"
AUDIENCE = "federation-proxy-test"
REPLICATOR_ROLE = "arn:aws:iam::111122223333:role/service-role/vpc-peering-replicator-ser"

os.environ.update({
    "TRUSTED_ISSUERS": ISSUER,
    "TRUSTED_AUDIENCES": AUDIENCE,
    "TRUSTED_SUBJECTS": REPLICATOR_ROLE,
    "IDP_TOKEN_ENDPOINT": "https://idp.example.internal/token",
    "IDP_CLIENT_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:111122223333:secret:idp-client",
})
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
