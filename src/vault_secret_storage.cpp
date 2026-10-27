#include "vault_secret_storage.hpp"

#include "vault_json.hpp"
#include "vault_secret_format.hpp"

#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"

#include <atomic>
#include <thread>

namespace duckdb {

VaultSecretStorage::VaultSecretStorage(DatabaseInstance &db_p)
    : SecretStorage(STORAGE_NAME, VAULT_STORAGE_OFFSET), db(db_p) {
	persistent = true;
}

static string EncodePath(const string &path) {
	vector<string> parts;
	for (auto &part : StringUtil::Split(path, '/')) {
		if (!part.empty()) {
			parts.push_back(VaultClient::EncodePathSegment(part));
		}
	}
	return StringUtil::Join(parts, "/");
}

static string KVPath(const VaultConfig &config, const char *kind, const string &name) {
	auto path = EncodePath(config.kv_mount) + "/" + kind;
	auto prefix = EncodePath(config.kv_prefix);
	if (!prefix.empty()) {
		path += "/" + prefix;
	}
	return path + "/" + VaultClient::EncodePathSegment(name);
}

string VaultSecretStorage::DataPath(const VaultConfig &config, const string &name) const {
	return KVPath(config, "data", name);
}

string VaultSecretStorage::MetadataPath(const VaultConfig &config, const string &name) const {
	return KVPath(config, "metadata", name);
}

string VaultSecretStorage::NormalizeName(const string &name) {
	auto result = StringUtil::Lower(name);
	// '.' and '..' would be resolved as path segments and address another entry
	if (result.empty() || result == "." || result == ".." || result.find('/') != string::npos) {
		throw InvalidInputException("Secret name '%s' cannot be stored in Vault: names must be non-empty, must not "
		                            "be '.' or '..' and must not contain '/'",
		                            name);
	}
	return result;
}

unique_ptr<SecretEntry> VaultSecretStorage::MakeEntry(const BaseSecret &secret) const {
	auto entry = make_uniq<SecretEntry>(secret.Clone());
	entry->persist_type = SecretPersistType::PERSISTENT;
	entry->storage_mode = storage_name;
	return entry;
}

optional_ptr<VaultClient> VaultSecretStorage::Connect(optional_ptr<ClientContext> context, bool required) {
	if (!context) {
		// No connection to read settings from (e.g. a background lookup): reuse the last known configuration
		if (!client && required) {
			throw InvalidConfigurationException("Vault secret storage cannot be used without a client connection");
		}
		if (client) {
			client->SetContext(nullptr);
		}
		return client.get();
	}
	auto config = VaultConfig::FromContext(*context);
	if (!config.IsConfigured()) {
		if (required) {
			throw InvalidConfigurationException("Vault secret storage is not configured: set the vault_addr setting "
			                                    "(or the VAULT_ADDR environment variable)");
		}
		return nullptr;
	}
	// The TTL and parallelism are not part of the fingerprint: changing them must not force a re-login
	cache_ttl_seconds = config.cache_ttl_seconds;
	max_parallel_requests = config.max_parallel_requests;
	auto new_fingerprint = config.Fingerprint();
	if (!client || new_fingerprint != fingerprint) {
		client = make_uniq<VaultClient>(db, std::move(config));
		fingerprint = new_fingerprint;
		cache.clear();
		cache_loaded = false;
	}
	client->SetContext(context);
	return client.get();
}

unique_ptr<SecretEntry> VaultSecretStorage::ParseSecret(const string &name, const string &path,
                                                        const VaultResponse &response) {
	// 404: deleted since it was listed. 403: a policy hides this entry from the token, so it is not one of ours.
	if (response.status == 404 || response.status == 403) {
		return nullptr;
	}
	if (!response.Ok()) {
		VaultClient::ThrowError("read secret '" + name + "'", path, response);
	}
	auto doc = JSONReader::Parse(response.body);
	auto secret = VaultSecretFormat::Deserialize(name, JSONReader::Get(JSONReader::Get(doc.Root(), "data"), "data"));
	if (!secret) {
		return nullptr;
	}
	return MakeEntry(*secret);
}

//! Run `task(i)` for every i in [0, count) on up to `max_threads` threads; rethrows the first error
template <class TASK>
static void RunParallel(idx_t count, idx_t max_threads, TASK &&task) {
	auto thread_count = MinValue<idx_t>(count, max_threads);
	if (thread_count <= 1) {
		for (idx_t i = 0; i < count; i++) {
			task(i);
		}
		return;
	}
	std::atomic<idx_t> next(0);
	mutex error_lock;
	ErrorData error;
	auto worker = [&]() {
		while (true) {
			auto i = next++;
			if (i >= count) {
				return;
			}
			try {
				task(i);
			} catch (std::exception &ex) {
				lock_guard<mutex> guard(error_lock);
				if (!error.HasError()) {
					error = ErrorData(ex);
				}
				next = count; // stop handing out work
			}
		}
	};
	vector<std::thread> threads;
	for (idx_t t = 0; t < thread_count; t++) {
		threads.emplace_back(worker);
	}
	for (auto &thread : threads) {
		thread.join();
	}
	if (error.HasError()) {
		error.Throw();
	}
}

VaultSecretStorage::EntryState VaultSecretStorage::ReadEntryState(VaultClient &vault, const string &name) {
	EntryState state;
	auto path = MetadataPath(vault.Config(), name);
	auto response = vault.Request("GET", path);
	if (response.status == 404) {
		return state;
	}
	if (!response.Ok()) {
		VaultClient::ThrowError("read metadata of secret '" + name + "'", path, response);
	}
	auto doc = JSONReader::Parse(response.body);
	auto data = JSONReader::Get(doc.Root(), "data");
	state.current_version = JSONReader::GetInt(data, "current_version", 0);
	auto latest = JSONReader::Get(JSONReader::Get(data, "versions"), std::to_string(state.current_version).c_str());
	state.exists = latest && JSONReader::GetString(latest, "deletion_time").empty() &&
	               !duckdb_yyjson::yyjson_is_true(JSONReader::Get(latest, "destroyed"));
	return state;
}

void VaultSecretStorage::EnsureLoaded(VaultClient &vault) {
	auto now = std::chrono::steady_clock::now();
	auto ttl = std::chrono::seconds(cache_ttl_seconds);
	if (cache_loaded && now - cache_loaded_at < ttl) {
		return;
	}

	auto &config = vault.Config();
	auto list_path = EncodePath(config.kv_mount) + "/metadata/";
	auto prefix = EncodePath(config.kv_prefix);
	if (!prefix.empty()) {
		list_path += prefix + "/";
	}
	auto response = vault.Request("GET", list_path + "?list=true");
	vector<string> keys;
	if (response.status != 404) { // 404: nothing stored yet
		if (!response.Ok()) {
			VaultClient::ThrowError("list secrets", list_path, response);
		}
		auto doc = JSONReader::Parse(response.body);
		keys = JSONReader::GetStringArray(JSONReader::Get(JSONReader::Get(doc.Root(), "data"), "keys"));
	}

	vector<string> names;
	for (auto &key : keys) {
		if (!key.empty() && key.back() != '/') { // skip sub-folders
			names.push_back(key);
		}
	}

	// Requests are prepared here, where the client connection may be used, and only sent in parallel. The listing
	// above went through Request, which already logged in again if the token was no longer valid.
	vault.EnsureAuthenticated();
	vector<string> paths;
	vector<VaultHTTPRequest> requests;
	for (auto &name : names) {
		paths.push_back(DataPath(config, name));
		requests.push_back(vault.Prepare("GET", paths.back()));
	}
	vector<VaultResponse> responses(names.size());
	RunParallel(names.size(), NumericCast<idx_t>(max_parallel_requests),
	            [&](idx_t i) { responses[i] = vault.Execute(requests[i]); });

	case_insensitive_map_t<unique_ptr<SecretEntry>> new_cache;
	for (idx_t i = 0; i < names.size(); i++) {
		auto entry = ParseSecret(names[i], paths[i], responses[i]);
		if (entry) {
			new_cache[names[i]] = std::move(entry);
		}
	}
	cache = std::move(new_cache);
	cache_loaded = true;
	cache_loaded_at = now;
}

bool VaultSecretStorage::WriteSecret(VaultClient &vault, const BaseSecret &secret, const string &name, bool replace) {
	auto path = DataPath(vault.Config(), name);
	auto state = ReadEntryState(vault, name);
	if (state.exists && !replace) {
		return false;
	}

	// Check-and-set against the version just read, so a concurrent change fails instead of being overwritten
	JSONBuilder body;
	auto options = body.NewObject();
	body.AddInt(options, "cas", state.current_version);
	body.AddValue(body.Root(), "options", options);
	auto data = body.NewObject();
	VaultSecretFormat::Serialize(secret, body, data);
	body.AddValue(body.Root(), "data", data);
	auto response = vault.Request("POST", path, body.ToString());
	if (!response.Ok()) {
		VaultClient::ThrowError("write secret '" + name + "'", path, response);
	}
	return true;
}

unique_ptr<SecretEntry> VaultSecretStorage::StoreSecret(unique_ptr<const BaseSecret> secret,
                                                        OnCreateConflict on_conflict,
                                                        optional_ptr<CatalogTransaction> transaction) {
	if (StringUtil::CIEquals(secret->GetType().GetIdentifierName(), VaultConfig::SECRET_TYPE)) {
		throw InvalidInputException("Secrets of type '%s' hold the credentials for Vault and cannot be stored in Vault",
		                            VaultConfig::SECRET_TYPE);
	}
	lock_guard<mutex> guard(lock);
	auto vault = Connect(GetContext(transaction), true);
	auto name = NormalizeName(secret->GetName().GetIdentifierName());

	if (on_conflict == OnCreateConflict::ALTER_ON_CONFLICT) {
		throw InternalException("unknown OnCreateConflict found while registering secret");
	}
	if (!WriteSecret(*vault, *secret, name, on_conflict == OnCreateConflict::REPLACE_ON_CONFLICT)) {
		if (on_conflict == OnCreateConflict::IGNORE_ON_CONFLICT) {
			return nullptr;
		}
		throw InvalidInputException("Persistent secret with name %s already exists in secret storage '%s'!", name,
		                            storage_name);
	}

	// Keep the name as stored in Vault so that listing and lookups agree
	auto stored = secret->Clone();
	auto kv_secret = dynamic_cast<const KeyValueSecret *>(stored.get());
	unique_ptr<SecretEntry> entry;
	if (kv_secret) {
		KeyValueSecret renamed(kv_secret->GetScope(), kv_secret->GetType(), kv_secret->GetProvider(), Identifier(name));
		renamed.secret_map = kv_secret->secret_map;
		// Redact the same way as when the secret is read back from Vault
		VaultSecretFormat::SetRedactKeys(renamed);
		entry = MakeEntry(renamed);
	} else {
		entry = MakeEntry(*stored);
	}
	if (cache_loaded) {
		cache[name] = make_uniq<SecretEntry>(*entry);
	}
	return entry;
}

vector<SecretEntry> VaultSecretStorage::AllSecrets(optional_ptr<CatalogTransaction> transaction) {
	if (VaultClient::RequestInProgress()) {
		// Re-entered while talking to Vault (HTTP secret lookup for the Vault URL): Vault cannot answer that
		return {};
	}
	lock_guard<mutex> guard(lock);
	vector<SecretEntry> result;
	auto vault = Connect(GetContext(transaction), false);
	if (!vault) {
		return result;
	}
	EnsureLoaded(*vault);
	for (auto &entry : cache) {
		result.push_back(*entry.second);
	}
	return result;
}

void VaultSecretStorage::DropSecretByName(const Identifier &name_p, OnEntryNotFound on_entry_not_found,
                                          optional_ptr<CatalogTransaction> transaction) {
	lock_guard<mutex> guard(lock);
	auto vault = Connect(GetContext(transaction), true);
	auto name = NormalizeName(name_p.GetIdentifierName());

	auto state = ReadEntryState(*vault, name);
	if (!state.exists) {
		cache.erase(name);
		if (on_entry_not_found == OnEntryNotFound::THROW_EXCEPTION) {
			throw InvalidInputException("Failed to remove non-existent persistent secret '%s' in secret storage '%s'",
			                            name, storage_name);
		}
		return;
	}
	// Deleting the metadata removes all versions, so the name can be re-created with check-and-set
	auto path = MetadataPath(vault->Config(), name);
	auto response = vault->Request("DELETE", path);
	if (!response.Ok() && response.status != 404) {
		VaultClient::ThrowError("delete secret '" + name + "'", path, response);
	}
	cache.erase(name);
}

SecretMatch VaultSecretStorage::LookupSecret(const string &path, const string &type,
                                             optional_ptr<CatalogTransaction> transaction) {
	// Vault credentials are looked up while connecting to Vault, and are never stored in it
	if (VaultClient::RequestInProgress() || StringUtil::CIEquals(type, VaultConfig::SECRET_TYPE)) {
		// Re-entered while talking to Vault (HTTP secret lookup for the Vault URL): Vault cannot answer that
		return SecretMatch();
	}
	lock_guard<mutex> guard(lock);
	SecretMatch best;
	auto vault = Connect(GetContext(transaction), false);
	if (!vault) {
		return best;
	}
	EnsureLoaded(*vault);
	for (auto &item : cache) {
		auto &entry = *item.second;
		if (!StringUtil::CIEquals(entry.secret->GetType().GetIdentifierName(), type)) {
			continue;
		}
		auto score = entry.secret->MatchScore(path);
		if (score == NumericLimits<int64_t>::Minimum()) {
			continue;
		}
		// Same scoring as the built-in storages: longest matching prefix, then storage offset, then name
		score = 100 * score - tie_break_offset;
		if (score > best.score || (score == best.score && entry.secret->GetName().GetIdentifierName() <
		                                                      best.GetSecret().GetName().GetIdentifierName())) {
			best = SecretMatch(entry, score);
		}
	}
	return best;
}

unique_ptr<SecretEntry> VaultSecretStorage::GetSecretByName(const string &name,
                                                            optional_ptr<CatalogTransaction> transaction) {
	if (VaultClient::RequestInProgress()) {
		// Re-entered while talking to Vault (HTTP secret lookup for the Vault URL): Vault cannot answer that
		return nullptr;
	}
	lock_guard<mutex> guard(lock);
	auto vault = Connect(GetContext(transaction), false);
	if (!vault) {
		return nullptr;
	}
	EnsureLoaded(*vault);
	auto entry = cache.find(StringUtil::Lower(name));
	if (entry == cache.end()) {
		return nullptr;
	}
	return make_uniq<SecretEntry>(*entry->second);
}

} // namespace duckdb
