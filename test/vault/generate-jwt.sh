#!/usr/bin/env bash
# Regenerates the test-only JWT fixtures used by the jwt auth integration test.
# Writes jwt_public.pem (configured in Vault by setup.sh) and test.jwt (used by the test).
# The private key is thrown away: these fixtures only exist to exercise Vault's jwt login.
set -euo pipefail
cd "$(dirname "$0")"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

openssl genrsa -out "$tmp/key.pem" 2048 2>/dev/null
openssl rsa -in "$tmp/key.pem" -pubout -out jwt_public.pem 2>/dev/null

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

header=$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)
# Valid until 2100-01-01
payload=$(printf '{"iss":"duckdb-vault-test","sub":"duckdb-ci","aud":"duckdb-vault","iat":1700000000,"nbf":1700000000,"exp":4102444800}' | b64url)
signature=$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign "$tmp/key.pem" -binary | b64url)

printf '%s.%s.%s' "$header" "$payload" "$signature" > test.jwt
echo "Wrote jwt_public.pem and test.jwt"
