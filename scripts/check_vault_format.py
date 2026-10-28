#!/usr/bin/env python3
"""Checks raw Vault KV entries after test/sql/integration/vault_format.test has run.

This pins down the storage format documented in README.md, as seen by other Vault clients.
Uses VAULT_TEST_ADDR / VAULT_TEST_TOKEN (set by scripts/run-integration-tests.sh).
"""
import json
import os
import sys
import urllib.request

addr = os.environ.get("VAULT_TEST_ADDR", "http://127.0.0.1:8200")
token = os.environ.get("VAULT_TEST_TOKEN", "root")


def read(path):
    request = urllib.request.Request(f"{addr}/v1/secret/data/{path}", headers={"X-Vault-Token": token})
    with urllib.request.urlopen(request) as response:
        result = json.load(response)["data"]
    return result["data"]


def compare(path, actual, expected, errors):
    for key, value in expected.items():
        if actual.get(key) != value:
            errors.append(f"  {path}: {key}: expected {value!r}, got {actual.get(key)!r}")
    extra = set(actual) - set(expected)
    if extra:
        errors.append(f"  {path}: unexpected fields: {sorted(extra)}")


errors = []

# Written by DuckDB: plain fields with JSON-typed values
path = "it_format_check/format_check"
compare(
    path,
    read(path),
    {
        "type": "http",
        "provider": "config",
        "scope": ["https://format.example.com"],
        "bearer_token": "format-token",
        "verify_ssl": True,
        "extra_http_headers": {"X-A": "b"},
    },
    errors,
)

# Not a DuckDB secret (no type): skipped and left alone
path = "it_handwritten/not_a_duckdb_secret"
compare(path, read(path), {"foo": "bar"}, errors)

if errors:
    print("Vault entries do not match the documented format:")
    print("\n".join(errors))
    sys.exit(1)
print("Vault entries match the documented format")
