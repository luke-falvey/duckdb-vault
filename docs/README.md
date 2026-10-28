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
environment variables. Credentials from the environment or from files (`$VAULT_TOKEN`, `~/.vault-token`,
`$VAULT_USERNAME`, `$VAULT_PASSWORD`, `$VAULT_JWT`, the Kubernetes service account token) are only used when the
Vault address also comes from `$VAULT_ADDR` (or `vault_addr` is set to the same address). Pointing `vault_addr`
somewhere else never sends them there.

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
| `vault_max_parallel_requests` | `8` | Maximum number of secrets read from Vault at the same time. `1` reads them one by one |

Settings, including `vault_token` and `vault_password`, are visible in `duckdb_settings()`. Prefer the
environment variables or a `vault` secret (below) for credentials.

`vault_jwt_path` and `~/.vault-token` are read through DuckDB's file system, so `enable_external_access` and
`allowed_directories` apply to them.

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

### Credentials in a secret (optional)

Instead of the credential settings, the credentials can be kept in a DuckDB secret of type `vault`. Secrets are
redacted in `duckdb_secrets()` and are not shown by `duckdb_settings()`:

```sql
CREATE SECRET vault_login (TYPE vault, TOKEN 'hvs.…');
-- or: (TYPE vault, USERNAME 'alice', PASSWORD '…'), (TYPE vault, ROLE 'duckdb', JWT '…')

-- Only for one Vault server
CREATE SECRET vault_prod (TYPE vault, TOKEN 'hvs.…', SCOPE 'https://vault.example.com:8200');
```

This is opt-in: nothing changes unless such a secret exists. When a `vault` secret matches `vault_addr`, its
`token`, `username`, `password` and `jwt` replace the credential settings and the environment, and its `role`
(if set) replaces `vault_role`. `vault_auth_method` still selects how to log in. A `vault` secret can be temporary
or persistent in DuckDB's local storage, but not stored in Vault itself.

## Storage format

Each DuckDB secret is one KV v2 entry at `<vault_kv_mount>/<vault_kv_prefix>/<secret name>` (secret names are
lower-case and cannot contain `/` or be `.` or `..`; the mount and prefix cannot contain `.` or `..` segments). With the defaults, `CREATE PERSISTENT SECRET my_s3 IN vault (...)` writes `secret/duckdb/my_s3`:

```
$ vault kv get -format=json secret/duckdb/my_s3 | jq .data.data
{
  "type": "s3",
  "provider": "config",
  "scope": ["s3://my-bucket"],
  "key_id": "AKIA...",
  "secret": "wJalr...",
  "region": "eu-west-1",
  "use_ssl": true
}
```

**DuckDB's folder.** The folder `<vault_kv_mount>/<vault_kv_prefix>/` (default `secret/duckdb/`) belongs to DuckDB: every entry in it is
treated as a DuckDB secret, and entries without a `type` field are skipped. Keep other applications' entries under
other paths. Vault lists folders without filtering and its policies are path-based, so separate folders are also how
access is controlled: give each DuckDB user a policy for its folder only (see [Vault policy](#vault-policy)).
Sub-folders are ignored.

| Field | Content |
|---|---|
| `type` | Secret type (`s3`, `gcs`, `http`, …). **Required** |
| `provider` | Secret provider, default `config` |
| `scope` | List of scope prefixes |
| any other field | One secret value, stored as the matching JSON type (below) |

| DuckDB value | JSON | Read back as |
|---|---|---|
| `VARCHAR` | string | `VARCHAR` |
| `BOOLEAN` | `true` / `false` | `BOOLEAN` |
| integer types | number | `BIGINT` |
| `FLOAT`, `DOUBLE` | number | `DOUBLE` |
| `MAP(VARCHAR, VARCHAR)`, e.g. `extra_http_headers` | object of strings | `MAP(VARCHAR, VARCHAR)` |
| `NULL` | `null` | `NULL` |

These cover every parameter of DuckDB's built-in secret types. A secret with a value of any other type (for example
a `STRUCT` or a `DATE`) cannot be stored in Vault. `type`, `provider` and `scope` are reserved: a secret with a value
under one of those names cannot be stored either.

### Writing secrets with the Vault CLI

Entries can be written by hand. Only `type` is required.
`vault kv put key=value` stores every value as a string, which works for text and for booleans (`use_ssl=true`);
`scope` may be comma-separated:

```sh
vault kv put secret/duckdb/analytics_s3 \
    type=s3 scope='s3://analytics,s3://analytics-archive' \
    key_id=AKIA... secret=... region=eu-west-1 use_ssl=true
```

Maps such as `extra_http_headers` must be JSON objects, so write those entries as JSON:

```sh
vault kv put secret/duckdb/api - <<'EOF'
{"type": "http", "bearer_token": "...", "extra_http_headers": {"X-Api-Key": "..."}}
EOF
```

`duckdb_secrets()` shows every value as `redacted` except well-known non-sensitive keys (`region`, `endpoint`,
`url_style`, `use_ssl`, `account_name`, …).

### Behaviour

- `CREATE` fails if the secret already exists; `IF NOT EXISTS` and `OR REPLACE` work as usual. Writes use KV
  check-and-set against the version DuckDB just read, so a concurrent change makes the statement fail rather than
  being overwritten. A soft-deleted DuckDB secret (`vault kv delete`) can be created again.
- `DROP` deletes the entry's metadata, which removes all its versions.
- Secrets are read in parallel, up to `vault_max_parallel_requests` (default 8) at a time. Lower it to reduce the
  load on Vault, for example under a Vault rate limit quota.
- Entries the token may not read (HTTP 403) are skipped, so a policy can hide single secrets in the folder. A 403 on
  listing the folder itself is an error.
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

Read-only access (`read` on `data/`, `read`/`list`
on `metadata/`) is enough to use secrets without creating or dropping them.

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

`scripts/run-integration-tests.sh` also runs `test/sql/env/` with `VAULT_ADDR`/`VAULT_TOKEN` in the environment, to
check that environment credentials only go to that address, and checks the raw Vault entries against the format above
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
