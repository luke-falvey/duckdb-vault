#pragma once

#include "duckdb.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "vault_json.hpp"

namespace duckdb {

//! Conversion between DuckDB secrets and the fields of a Vault KV v2 entry.
//!
//! Only entries whose KV custom metadata contains duckdb=true are DuckDB secrets: other applications can keep
//! their own entries under the same path.
//! Layout of the KV "data" object:
//!   type             secret type (required)
//!   provider         secret provider (default "config")
//!   scope            array of scope prefixes
//!   <any other field> one secret value as the matching JSON type: string, boolean, number, or an object of strings
//!                    for MAP(VARCHAR, VARCHAR)
//!
//! When displayed, every value is redacted except well-known non-sensitive keys.
//!
//! scope also accepts the string forms a person would type with `vault kv put`: comma-separated text or JSON array
//! text.
struct VaultSecretFormat {
	static constexpr const char *TYPE_FIELD = "type";
	static constexpr const char *PROVIDER_FIELD = "provider";
	static constexpr const char *SCOPE_FIELD = "scope";
	//! KV custom metadata marking an entry as a DuckDB secret
	static constexpr const char *MARKER_KEY = "duckdb";
	static constexpr const char *MARKER_VALUE = "true";

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
