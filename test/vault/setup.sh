#!/bin/sh
# Configures the dev Vault server for the integration tests. Idempotent: safe to run more than once.
set -eu

echo "Configuring Vault at $VAULT_ADDR"

# --- Policies ---------------------------------------------------------------
vault policy write duckdb-rw - <<'POLICY'
path "secret/data/*"     { capabilities = ["create", "read", "update", "delete"] }
path "secret/metadata/*" { capabilities = ["create", "read", "update", "list", "delete"] }
path "kv-alt/data/*"     { capabilities = ["create", "read", "update", "delete"] }
path "kv-alt/metadata/*" { capabilities = ["create", "read", "update", "list", "delete"] }
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

# --- kubernetes (service accounts and tokens from test/vault/k8s/bootstrap.sh) ---
K8S=/setup/k8s/generated
vault auth list -format=json | grep -q '"kubernetes/"' || vault auth enable kubernetes
vault write auth/kubernetes/config \
	kubernetes_host=https://k3s:6443 \
	kubernetes_ca_cert=@$K8S/ca.crt \
	token_reviewer_jwt=@$K8S/reviewer.jwt \
	disable_local_ca_jwt=true
vault write auth/kubernetes/role/duckdb \
	bound_service_account_names=duckdb \
	bound_service_account_namespaces=default \
	audience=https://kubernetes.default.svc.cluster.local \
	token_policies=duckdb-rw

# --- jwt --------------------------------------------------------------------
vault auth list -format=json | grep -q '"jwt/"' || vault auth enable jwt
vault write auth/jwt/config jwt_validation_pubkeys=@/setup/jwt_public.pem bound_issuer=duckdb-vault-test
vault write auth/jwt/role/duckdb role_type=jwt bound_audiences=duckdb-vault user_claim=sub \
	token_policies=duckdb-rw

# --- Seed data: entries written by hand, the way an operator would ---------
# DuckDB secrets carry the custom metadata duckdb=true
mark() {
	vault kv metadata put -custom-metadata=duckdb=true "$1"
}
# Written with key=value pairs: every value is a string
vault kv put secret/it_handwritten/manual_http \
	type=http \
	scope='https://api.example.com,https://other.example.com' \
	bearer_token=hand-written-token \
	verify_ssl=false
mark secret/it_handwritten/manual_http
# Written as JSON: native boolean and a map of headers
vault kv put secret/it_handwritten/manual_json - <<'JSON'
{
  "type": "http",
  "scope": ["https://json.example.com"],
  "bearer_token": "json-token",
  "verify_ssl": false,
  "extra_http_headers": {"X-From-Vault": "yes"}
}
JSON
mark secret/it_handwritten/manual_json
# Soft-deleted DuckDB secret: must not show up, and can be created again
vault kv put secret/it_handwritten/deleted_http type=http bearer_token=gone
mark secret/it_handwritten/deleted_http
vault kv delete secret/it_handwritten/deleted_http

# Entries of other applications (no marker): never listed, overwritten or deleted by DuckDB
vault kv put secret/it_handwritten/not_a_duckdb_secret foo=bar
# Looks exactly like a DuckDB secret, but is not marked
vault kv put secret/it_handwritten/foreign_s3 type=s3 key_id=app-key secret=app-secret region=eu-west-1
vault kv put secret/it_handwritten/foreign_deleted type=http bearer_token=app
vault kv delete secret/it_handwritten/foreign_deleted

echo "Vault configured"
