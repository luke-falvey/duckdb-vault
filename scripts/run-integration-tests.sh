#!/usr/bin/env bash
# Runs the integration tests against a real Vault server started with docker compose.
#
#   make                                # build first
#   ./scripts/run-integration-tests.sh  # or: make integration-test
#
# Environment:
#   BUILD=release|debug|reldebug   which build to test (default: release)
#   VAULT_PORT=8200                host port for Vault
#   VAULT_TLS_PORT=8300            host port for the HTTPS Vault
#   KEEP_VAULT=1                   leave the Vault container running afterwards
set -euo pipefail
cd "$(dirname "$0")/.."

BUILD=${BUILD:-release}
UNITTEST=build/$BUILD/test/unittest
if [ ! -x "$UNITTEST" ]; then
	echo "error: $UNITTEST not found, build the extension first (make $BUILD)" >&2
	exit 1
fi

export VAULT_PORT=${VAULT_PORT:-8200}
export VAULT_TLS_PORT=${VAULT_TLS_PORT:-8300}

cleanup() {
	if [ "${KEEP_VAULT:-0}" != "1" ]; then
		docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

echo "--- Starting Vault"
# Created here so the bind mount is not created root-owned by docker
mkdir -p test/vault/k8s/generated test/vault/tls/generated
docker compose up -d --wait vault vault-tls lldap k3s
docker compose cp vault-tls:/tmp/vault-ca.pem test/vault/tls/generated/vault-ca.pem
docker compose run --rm --no-deps lldap-bootstrap
docker compose run --rm --no-deps k8s-bootstrap
docker compose run --rm --no-deps vault-setup

export VAULT_TEST_ADDR="http://127.0.0.1:${VAULT_PORT}"
export VAULT_TEST_TOKEN=root
# HTTPS Vault with a self-signed certificate, and its CA certificate
export VAULT_TEST_TLS_ADDR="https://127.0.0.1:${VAULT_TLS_PORT}"
export VAULT_TEST_TLS_CA="$PWD/test/vault/tls/generated/vault-ca.pem"
# Service account tokens for the kubernetes auth tests
export VAULT_TEST_K8S_TOKENS="$PWD/test/vault/k8s/generated"
# The extension falls back to these; make sure only the explicit test settings are used
unset VAULT_ADDR VAULT_TOKEN VAULT_NAMESPACE VAULT_USERNAME VAULT_PASSWORD VAULT_ROLE VAULT_JWT || true

echo "--- Running integration tests"
"$UNITTEST" "test/sql/integration/*"

echo "--- Checking the layout of secrets stored in Vault"
python3 scripts/check_vault_format.py
