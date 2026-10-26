#!/usr/bin/env python3
"""Checks raw Vault KV entries after test/sql/integration/vault_format.test has run.

This pins down the storage format documented in README.md, as seen by other Vault clients, and that entries of
other applications under the same path were left alone.
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
    return result["data"], result["metadata"].get("custom_metadata") or {}


def compare(path, actual, expected, errors):
    for key, value in expected.items():
        if actual.get(key) != value:
            errors.append(f"  {path}: {key}: expected {value!r}, got {actual.get(key)!r}")
    extra = set(actual) - set(expected)
    if extra:
        errors.append(f"  {path}: unexpected fields: {sorted(extra)}")


errors = []

# Written by DuckDB: plain fields, JSON-typed values, marked as a DuckDB secret
path = "it_format_check/format_check"
data, custom_metadata = read(path)
compare(
    path,
    data,
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
if custom_metadata.get("duckdb") != "true":
    errors.append(f"  {path}: custom_metadata: expected duckdb=true, got {custom_metadata!r}")

# Entries of other applications: untouched and unmarked
for path, expected in [
    (
        "it_handwritten/foreign_s3",
        {"type": "s3", "key_id": "app-key", "secret": "app-secret", "region": "eu-west-1"},
    ),
    ("it_handwritten/not_a_duckdb_secret", {"foo": "bar"}),
]:
    data, custom_metadata = read(path)
    compare(path, data, expected, errors)
    if "duckdb" in custom_metadata:
        errors.append(f"  {path}: must not be marked as a DuckDB secret, got {custom_metadata!r}")

if errors:
    print("Vault entries do not match the documented format:")
    print("\n".join(errors))
    sys.exit(1)
print("Vault entries match the documented format")
