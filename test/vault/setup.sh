#!/bin/sh
# Configures the dev Vault server for the integration tests. Idempotent: safe to run more than once.
set -eu

echo "Configuring Vault at $VAULT_ADDR"

# --- Policies ---------------------------------------------------------------
vault policy write duckdb-rw - <<'POLICY'
path "secret/data/*"     { capabilities = ["create", "read", "update", "delete"] }
path "secret/metadata/*" { capabilities = ["read", "list", "delete"] }
path "kv-alt/data/*"     { capabilities = ["create", "read", "update", "delete"] }
path "kv-alt/metadata/*" { capabilities = ["read", "list", "delete"] }
POLICY

vault policy write duckdb-ro - <<'POLICY'
path "secret/data/*"     { capabilities = ["read"] }
path "secret/metadata/*" { capabilities = ["read", "list"] }
POLICY

# --- Extra KV v2 mount (tests vault_kv_mount) ------------------------------
vault secrets list -format=json | grep -q '"kv-alt/"' || vault secrets enable -path=kv-alt -version=2 kv

# --- userpass ---------------------------------------------------------------
vault auth list -format=json | grep -q '"userpass/"' || vault auth enable userpass
vault write auth/userpass/users/duckdb password=duckdb-password token_policies=duckdb-rw
vault write auth/userpass/users/readonly password=readonly-password token_policies=duckdb-ro
# Tokens that expire quickly, to test re-login
vault write auth/userpass/users/shortlived password=shortlived-password token_policies=duckdb-rw \
	token_ttl=3s token_max_ttl=3s

# userpass mounted at a custom path (tests vault_auth_mount)
vault auth list -format=json | grep -q '"corp-users/"' || vault auth enable -path=corp-users userpass
vault write auth/corp-users/users/alice password=alice-password token_policies=duckdb-rw

# --- ldap (directory served by the lldap container) ------------------------
vault auth list -format=json | grep -q '"ldap/"' || vault auth enable ldap
vault write auth/ldap/config \
	url=ldap://lldap:3890 \
	binddn=uid=admin,ou=people,dc=example,dc=com \
	bindpass=lldap-admin-password \
	userdn=ou=people,dc=example,dc=com \
	userattr=uid \
	groupdn=ou=groups,dc=example,dc=com \
	groupattr=cn \
	groupfilter='(&(objectClass=groupOfUniqueNames)(member={{.UserDN}}))'
# Members of the LDAP group duckdb-users get read/write access; other LDAP users only get "default"
vault write auth/ldap/groups/duckdb-users policies=duckdb-rw

# --- jwt --------------------------------------------------------------------
vault auth list -format=json | grep -q '"jwt/"' || vault auth enable jwt
vault write auth/jwt/config jwt_validation_pubkeys=@/setup/jwt_public.pem bound_issuer=duckdb-vault-test
vault write auth/jwt/role/duckdb role_type=jwt bound_audiences=duckdb-vault user_claim=sub \
	token_policies=duckdb-rw

# --- Seed data: entries written by hand, the way an operator would ---------
vault kv put secret/it_handwritten/manual_http \
	duckdb_type=http \
	duckdb_scope='https://api.example.com,https://other.example.com' \
	duckdb_types='{"verify_ssl":"BOOLEAN"}' \
	bearer_token=hand-written-token \
	verify_ssl=false
# Not a DuckDB secret (no duckdb_type): must be ignored
vault kv put secret/it_handwritten/not_a_duckdb_secret foo=bar
# Soft-deleted entry: must not show up
vault kv put secret/it_handwritten/deleted_http duckdb_type=http bearer_token=gone
vault kv delete secret/it_handwritten/deleted_http

echo "Vault configured"
