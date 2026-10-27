#pragma once

#include "duckdb.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/main/secret/secret_storage.hpp"
#include "vault_client.hpp"

#include <chrono>

namespace duckdb {

//! Persistent secret storage backed by a HashiCorp Vault KV v2 secrets engine.
//!
//! Every DuckDB secret is one KV entry at <vault_kv_mount>/<vault_kv_prefix>/<secret name>; that folder belongs to
//! DuckDB. Secrets are listed and read lazily (in parallel) and cached for vault_cache_ttl_seconds. Entries the token
//! may not read are skipped. When Vault is not configured (no vault_addr), the storage is empty and lookups silently
//! find nothing, so DuckDB keeps working normally.
class VaultSecretStorage : public SecretStorage {
public:
	static constexpr const char *STORAGE_NAME = "vault";
	//! Tie-break offset; must differ from the built-in storages (0, 5, 10, 20)
	static constexpr int64_t VAULT_STORAGE_OFFSET = 30;

	explicit VaultSecretStorage(DatabaseInstance &db);

	unique_ptr<SecretEntry> StoreSecret(unique_ptr<const BaseSecret> secret, OnCreateConflict on_conflict,
	                                    optional_ptr<CatalogTransaction> transaction = nullptr) override;
	vector<SecretEntry> AllSecrets(optional_ptr<CatalogTransaction> transaction = nullptr) override;
	void DropSecretByName(const Identifier &name, OnEntryNotFound on_entry_not_found,
	                      optional_ptr<CatalogTransaction> transaction = nullptr) override;
	SecretMatch LookupSecret(const string &path, const string &type,
	                         optional_ptr<CatalogTransaction> transaction = nullptr) override;
	unique_ptr<SecretEntry> GetSecretByName(const string &name,
	                                        optional_ptr<CatalogTransaction> transaction = nullptr) override;

private:
	//! Get a client for the current settings. Returns nullptr when Vault is not configured, unless `required`.
	//! Discards the cached token and secrets when the settings changed. Caller must hold `lock`.
	optional_ptr<VaultClient> Connect(optional_ptr<ClientContext> context, bool required);
	//! Maximum number of secrets read from Vault at the same time
	static constexpr idx_t MAX_PARALLEL_REQUESTS = 8;

	//! (Re)load all secrets from Vault if the cache is stale, reading them in parallel. Caller must hold `lock`.
	void EnsureLoaded(VaultClient &client);
	//! Turn the response to reading one secret into an entry: nullptr if it is missing, not readable by this token
	//! (403) or not a DuckDB secret
	unique_ptr<SecretEntry> ParseSecret(const string &name, const string &path, const VaultResponse &response);
	//! What is stored at the secret's path, from its KV metadata
	struct EntryState {
		//! The latest version exists and is not deleted
		bool exists = false;
		int64_t current_version = 0;
	};
	EntryState ReadEntryState(VaultClient &client, const string &name);
	//! Write the secret. Returns false when it already exists and replace is false.
	bool WriteSecret(VaultClient &client, const BaseSecret &secret, const string &name, bool replace);

	string DataPath(const VaultConfig &config, const string &name) const;
	string MetadataPath(const VaultConfig &config, const string &name) const;
	static string NormalizeName(const string &name);
	unique_ptr<SecretEntry> MakeEntry(const BaseSecret &secret) const;

	static optional_ptr<ClientContext> GetContext(optional_ptr<CatalogTransaction> transaction) {
		return transaction ? transaction->context : nullptr;
	}

	DatabaseInstance &db;
	mutex lock;
	string fingerprint;
	unique_ptr<VaultClient> client;
	//! Secrets read from Vault, keyed by (lower-case) name
	case_insensitive_map_t<unique_ptr<SecretEntry>> cache;
	bool cache_loaded = false;
	int64_t cache_ttl_seconds = 60;
	std::chrono::steady_clock::time_point cache_loaded_at;
};

} // namespace duckdb
