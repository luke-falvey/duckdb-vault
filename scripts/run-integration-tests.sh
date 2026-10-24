#!/usr/bin/env bash
# Runs the integration tests against a real Vault server started with docker compose.
#
#   make                                # build first
#   ./scripts/run-integration-tests.sh  # or: make integration-test
#
# Environment:
#   BUILD=release|debug|reldebug   which build to test (default: release)
#   VAULT_PORT=8200                host port for Vault
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

cleanup() {
	if [ "${KEEP_VAULT:-0}" != "1" ]; then
		docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

echo "--- Starting Vault"
docker compose up -d --wait vault lldap
docker compose run --rm lldap-bootstrap
docker compose run --rm --no-deps vault-setup

export VAULT_TEST_ADDR="http://127.0.0.1:${VAULT_PORT}"
export VAULT_TEST_TOKEN=root
# The extension falls back to these; make sure only the explicit test settings are used
unset VAULT_ADDR VAULT_TOKEN VAULT_NAMESPACE VAULT_USERNAME VAULT_PASSWORD VAULT_ROLE VAULT_JWT VAULT_CACERT || true

echo "--- Running integration tests"
"$UNITTEST" "test/sql/integration/*"

echo "--- Checking the layout of secrets stored in Vault"
python3 scripts/check_vault_format.py
