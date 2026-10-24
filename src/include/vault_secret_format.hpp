#pragma once

#include "duckdb.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "vault_json.hpp"

namespace duckdb {

//! Conversion between DuckDB secrets and the fields of a Vault KV v2 entry.
//!
//! Layout of the KV "data" object:
//!   duckdb_type            secret type (required)
//!   duckdb_provider        secret provider (default "config")
//!   duckdb_scope           array of scope prefixes
//!   duckdb_types           object key -> DuckDB type, for values that are not VARCHAR
//!   duckdb_redact_keys     array of keys to redact when displaying the secret
//!   duckdb_format_version  "1"
//!   <any other field>      one secret value, stored as a string
//!
//! The reserved fields also accept the string forms a person would type with `vault kv put`
//! (comma-separated lists or JSON text).
struct VaultSecretFormat {
	static constexpr const char *TYPE_FIELD = "duckdb_type";
	static constexpr const char *PROVIDER_FIELD = "duckdb_provider";
	static constexpr const char *SCOPE_FIELD = "duckdb_scope";
	static constexpr const char *TYPES_FIELD = "duckdb_types";
	static constexpr const char *REDACT_FIELD = "duckdb_redact_keys";
	static constexpr const char *VERSION_FIELD = "duckdb_format_version";
	static constexpr const char *FORMAT_VERSION = "1";
	static constexpr const char *RESERVED_PREFIX = "duckdb_";

	//! Write the secret's fields into the JSON object `target`. Throws for secrets that are not key/value secrets.
	static void Serialize(const BaseSecret &secret, JSONBuilder &builder, JSONBuilder::mut_t target);

	//! Build a secret from a KV "data" object. Returns nullptr when the entry is not a DuckDB secret (no duckdb_type).
	static unique_ptr<BaseSecret> Deserialize(const string &name, JSONReader::val_t data,
	                                          optional_ptr<ClientContext> context);

	//! Keys displayed in clear text when an entry does not list its redacted keys
	static bool IsNonSensitiveKey(const string &key);
};

} // namespace duckdb
