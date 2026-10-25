#!/usr/bin/env python3
"""Checks the raw Vault KV entry written by test/sql/integration/vault_format.test.

This pins down the storage format documented in README.md, as seen by other Vault clients.
Uses VAULT_TEST_ADDR / VAULT_TEST_TOKEN (set by scripts/run-integration-tests.sh).
"""
import json
import os
import sys
import urllib.request

addr = os.environ.get("VAULT_TEST_ADDR", "http://127.0.0.1:8200")
token = os.environ.get("VAULT_TEST_TOKEN", "root")
path = "secret/data/it_format_check/format_check"

request = urllib.request.Request(f"{addr}/v1/{path}", headers={"X-Vault-Token": token})
with urllib.request.urlopen(request) as response:
    data = json.load(response)["data"]["data"]

expected = {
    "duckdb_type": "http",
    "duckdb_provider": "config",
    "duckdb_format_version": "1",
    "duckdb_scope": ["https://format.example.com"],
    "duckdb_types": {"verify_ssl": "BOOLEAN", "extra_http_headers": "MAP(VARCHAR, VARCHAR)"},
    "bearer_token": "format-token",
    "verify_ssl": "true",
    "extra_http_headers": "{X-A=b}",
}
errors = []
for key, value in expected.items():
    if data.get(key) != value:
        errors.append(f"  {key}: expected {value!r}, got {data.get(key)!r}")

redact = set(data.get("duckdb_redact_keys", []))
if not {"bearer_token", "extra_http_headers"} <= redact:
    errors.append(f"  duckdb_redact_keys: expected bearer_token and extra_http_headers, got {sorted(redact)}")

extra = set(data) - set(expected) - {"duckdb_redact_keys"}
if extra:
    errors.append(f"  unexpected fields: {sorted(extra)}")

if errors:
    print(f"Vault entry {path} does not match the documented format:")
    print("\n".join(errors))
    print(json.dumps(data, indent=2))
    sys.exit(1)
print(f"Vault entry {path} matches the documented format")
