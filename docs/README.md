# DuckDB Vault extension

Store DuckDB [secrets](https://duckdb.org/docs/stable/configuration/secrets_manager) in
[HashiCorp Vault](https://developer.hashicorp.com/vault) instead of DuckDB's local secret directory
(`~/.duckdb/stored_secrets`).

The extension adds a persistent secret storage called `vault`. Secrets created in it are written to a Vault
KV v2 secrets engine and read back from there by every DuckDB process pointed at the same Vault.

```sql
LOAD vault;   -- also loads httpfs, which the extension uses to talk to Vault

SET vault_addr = 'https://vault.example.com:8200';
-- token taken from VAULT_TOKEN or ~/.vault-token, see "Authentication" below

CREATE PERSISTENT SECRET my_s3 IN vault (
    TYPE s3, KEY_ID 'AKIA...', SECRET '...', REGION 'eu-west-1', SCOPE 's3://my-bucket'
);

-- Used automatically, like any other secret
SELECT * FROM 's3://my-bucket/data.parquet';

FROM duckdb_secrets();                 -- storage = 'vault'
DROP PERSISTENT SECRET my_s3 FROM vault;

-- Make Vault the default for all persistent secrets
SET default_secret_storage = 'vault';
CREATE PERSISTENT SECRET my_gcs (TYPE gcs, KEY_ID '...', SECRET '...');
```

When `vault_addr` is not set (and `VAULT_ADDR` is not in the environment), the `vault` storage is empty
and DuckDB behaves exactly as without the extension.

## Settings

All settings are global (`SET` or `SET GLOBAL`). Settings left empty fall back to the standard Vault
environment variables.

| Setting | Default | Description |
|---|---|---|
| `vault_addr` | `$VAULT_ADDR` | Vault address, e.g. `https://vault:8200` |
| `vault_namespace` | `$VAULT_NAMESPACE` | Vault Enterprise namespace |
| `vault_auth_method` | `token` | `token`, `userpass`, `ldap`, `kubernetes` or `jwt` |
| `vault_auth_mount` | method name | Mount path of the auth method, e.g. `corp-ldap` |
| `vault_token` | `$VAULT_TOKEN`, then `~/.vault-token` | Token for the `token` method |
| `vault_username` / `vault_password` | `$VAULT_USERNAME` / `$VAULT_PASSWORD` | For `userpass` and `ldap` |
| `vault_role` | `$VAULT_ROLE` | Role for `kubernetes` and `jwt` |
| `vault_jwt` | `$VAULT_JWT` | JWT for `kubernetes` and `jwt` |
| `vault_jwt_path` | kubernetes: `/var/run/secrets/kubernetes.io/serviceaccount/token` | File to read the JWT from |
| `vault_kv_mount` | `secret` | Mount path of the KV v2 engine |
| `vault_kv_prefix` | `duckdb` | Path inside the mount under which secrets are stored |
| `vault_cache_ttl_seconds` | `60` | How long secrets read from Vault are cached. `0` reads Vault on every lookup |

Settings, including `vault_token` and `vault_password`, are visible in `duckdb_settings()`. Prefer the
environment variables for credentials.

`vault_status()` shows the resolved configuration and whether DuckDB can log in:

```sql
SELECT * FROM vault_status();
-- address | namespace | auth_method | kv_path | authenticated | display_name | policies | token_ttl | error
```

## HTTP and TLS

Requests to Vault go through DuckDB's HTTP stack, which the [httpfs](https://duckdb.org/docs/stable/core_extensions/httpfs/overview)
extension provides. The vault extension loads httpfs on first use (with DuckDB's default extension autoloading); if
autoloading is disabled, run `INSTALL httpfs; LOAD httpfs;` first.

TLS and proxies are therefore configured the same way as for any other HTTP access in DuckDB:

```sql
-- Trust a private CA (e.g. Vault's own certificate authority)
SET ca_cert_file = '/etc/vault/ca.pem';

-- Use an HTTP proxy
SET http_proxy = 'proxy.internal:3128';

-- Turn off certificate verification for the Vault address only (insecure)
CREATE SECRET vault_tls (TYPE http, VERIFY_SSL false, SCOPE 'https://vault.example.com:8200');
```

`http` secrets used for the Vault connection itself are only looked up in the other secret storages, never in Vault.

## Authentication

```sql
-- Token (default): vault_token, else VAULT_TOKEN, else ~/.vault-token
SET vault_auth_method = 'token';

-- Username and password
SET vault_auth_method = 'userpass';     -- or 'ldap'
SET vault_username = 'alice';           -- password from VAULT_PASSWORD

-- Kubernetes service account (inside a pod)
SET vault_auth_method = 'kubernetes';
SET vault_role = 'duckdb';

-- Any JWT, e.g. GitHub Actions OIDC
SET vault_auth_method = 'jwt';
SET vault_role = 'duckdb';
SET vault_jwt_path = '/path/to/token.jwt';
```

Tokens from logins are cached and renewed by logging in again shortly before they expire, or after Vault
rejects them.

## Storage format

Each DuckDB secret is one KV v2 entry at `<vault_kv_mount>/<vault_kv_prefix>/<secret name>` (secret names are
lower-case). With the defaults, `CREATE PERSISTENT SECRET my_s3 IN vault (...)` writes `secret/duckdb/my_s3`:

```
$ vault kv get secret/duckdb/my_s3
========== Data ==========
Key                      Value
---                      -----
duckdb_format_version    1
duckdb_provider          config
duckdb_redact_keys       [secret session_token]
duckdb_scope             [s3://my-bucket]
duckdb_type              s3
duckdb_types             map[use_ssl:BOOLEAN]
key_id                   AKIA...
region                   eu-west-1
secret                   wJalr...
use_ssl                  true
```

| Field | Content |
|---|---|
| `duckdb_type` | Secret type (`s3`, `gcs`, `http`, …). **Required**: entries without it are ignored |
| `duckdb_provider` | Secret provider, default `config` |
| `duckdb_scope` | List of scope prefixes |
| `duckdb_types` | Map of key → DuckDB type, for values that are not `VARCHAR` |
| `duckdb_redact_keys` | Keys shown as `redacted` in `duckdb_secrets()` |
| `duckdb_format_version` | `1` |
| any other field | One secret value, as a string |

Values are plain strings so other tools can use them directly (for example, Vault Agent templates or
applications reading the same credentials). Non-string values are stored as their DuckDB text form and converted
back using `duckdb_types`, e.g. `MAP {'X-Key': 'v'}` is stored as `{X-Key=v}` with type `MAP(VARCHAR, VARCHAR)`.

### Writing secrets with the Vault CLI

Entries can be written by hand. Only `duckdb_type` is required. Lists may be written as comma-separated text
and maps as JSON text:

```sh
vault kv put secret/duckdb/analytics_s3 \
    duckdb_type=s3 \
    duckdb_scope='s3://analytics,s3://analytics-archive' \
    duckdb_types='{"use_ssl": "BOOLEAN"}' \
    key_id=AKIA... secret=... region=eu-west-1 use_ssl=true
```

Without `duckdb_redact_keys`, every value is redacted except well-known non-sensitive keys (`region`,
`endpoint`, `url_style`, `use_ssl`, `account_name`, …). Keys starting with `duckdb_` are reserved.

### Behaviour

- `CREATE` uses KV check-and-set, so it fails if the secret already exists. `IF NOT EXISTS` and `OR REPLACE` work
  as usual. A soft-deleted entry (`vault kv delete`) can be created again.
- `DROP` deletes the entry's metadata, which removes all its versions.
- Changes made directly in Vault are picked up after `vault_cache_ttl_seconds`.
- Writes go to Vault right away and are not rolled back with the DuckDB transaction, the same as local
  persistent secrets.
- Only key/value secrets can be stored. All built-in DuckDB secret types are key/value secrets.
- When Vault is configured but unreachable, statements that look up secrets fail with the connection error.

### Vault policy

DuckDB needs these capabilities on its KV path (defaults shown):

```hcl
path "secret/data/duckdb/*"     { capabilities = ["create", "read", "update"] }
path "secret/metadata/duckdb/*" { capabilities = ["read", "list", "delete"] }
path "secret/metadata/duckdb"   { capabilities = ["list"] }
```

Read-only access (`read` on `data/`, `read`/`list` on `metadata/`) is enough to use secrets without creating or
dropping them.

## Building

```sh
git submodule update --init --recursive
make            # build/release/duckdb with the extension statically linked
make test       # unit tests (no Vault needed)
```

The extension itself has no external dependencies: it uses DuckDB's HTTP stack and the JSON library bundled with
DuckDB. The build also compiles httpfs (pinned in `extension_config.cmake` to the version DuckDB v2.0.0 uses) so the
tests can load it; httpfs needs OpenSSL and curl (from vcpkg in CI, or e.g. `libssl-dev` and `libcurl4-openssl-dev`
locally).

## Integration tests

The tests in `test/sql/integration/` run against a real Vault dev server started by `docker-compose.yml`,
together with a second Vault serving HTTPS with a self-signed certificate, an [lldap](https://github.com/lldap/lldap)
LDAP directory for the `ldap` auth method and a [k3s](https://k3s.io) Kubernetes API server (no nodes) for the
`kubernetes` auth method.
`test/vault/setup.sh` configures Vault: policies, userpass users (including one with short-lived tokens), a custom
auth mount, LDAP auth with group-based policies (users and groups in `test/vault/ldap/`), Kubernetes auth with
service accounts created by `test/vault/k8s/bootstrap.sh` (fresh tokens on every run), JWT auth with a test key,
a second KV mount, and hand-written entries.

```sh
make                      # build first
make integration-test     # starts Vault with docker compose, runs the tests, stops Vault
```

`scripts/run-integration-tests.sh` also checks the raw Vault entry against the format above
(`scripts/check_vault_format.py`). Set `KEEP_VAULT=1` to leave Vault running afterwards
(`http://127.0.0.1:8200`, token `root`). The JWT fixtures can be regenerated with `test/vault/generate-jwt.sh`.

To run a single test against a running Vault:

```sh
mkdir -p test/vault/k8s/generated
docker compose up -d --wait vault lldap k3s && docker compose run --rm vault-setup
VAULT_TEST_ADDR=http://127.0.0.1:8200 VAULT_TEST_TOKEN=root VAULT_TEST_K8S_TOKENS=$PWD/test/vault/k8s/generated \
    build/release/test/unittest test/sql/integration/vault_auth.test
```

Without `VAULT_TEST_ADDR` the integration tests are skipped, so `make test` works without Docker.
`test/sql/vault_settings.test` and `test/sql/vault_client.test` expect `VAULT_ADDR` and `VAULT_TOKEN` to be unset.

The Kubernetes tests pass the service account token through `vault_jwt_path`. The default path inside a pod
(`/var/run/secrets/kubernetes.io/serviceaccount/token`) is not exercised, since the tests do not run in a pod.
