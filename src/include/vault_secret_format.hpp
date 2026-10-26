#pragma once

#include "duckdb.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "vault_json.hpp"

namespace duckdb {

//! Conversion between DuckDB secrets and the fields of a Vault KV v2 entry.
//!
//! Layout of the KV "data" object:
//!   type             secret type (required)
//!   provider         secret provider (default "config")
//!   scope            array of scope prefixes
//!   types            object key -> DuckDB type, for values that are not VARCHAR
//!   <any other field> one secret value, stored as a string
//!
//! When displayed, every value is redacted except well-known non-sensitive keys.
//!
//! The reserved fields also accept the string forms a person would type with `vault kv put`
//! (comma-separated lists or JSON text).
struct VaultSecretFormat {
	static constexpr const char *TYPE_FIELD = "type";
	static constexpr const char *PROVIDER_FIELD = "provider";
	static constexpr const char *SCOPE_FIELD = "scope";
	static constexpr const char *TYPES_FIELD = "types";

	//! Write the secret's fields into the JSON object `target`. Throws for secrets that are not key/value secrets.
	static void Serialize(const BaseSecret &secret, JSONBuilder &builder, JSONBuilder::mut_t target);

	//! Build a secret from a KV "data" object. Returns nullptr when the entry is not a DuckDB secret (no type).
	static unique_ptr<BaseSecret> Deserialize(const string &name, JSONReader::val_t data);

	//! Keys displayed in clear text by duckdb_secrets()
	static bool IsNonSensitiveKey(const string &key);
	//! Redact every value of the secret except the non-sensitive ones
	static void SetRedactKeys(KeyValueSecret &secret);

	//! Whether a field holds the secret's metadata rather than one of its values
	static bool IsReservedField(const string &key);
};

} // namespace duckdb
