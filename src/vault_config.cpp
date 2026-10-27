#include "vault_config.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

#include <cstdlib>

namespace duckdb {

static string GetEnv(const char *name) {
	auto value = std::getenv(name);
	return value ? string(value) : string();
}

static string GetStringSetting(ClientContext &context, const char *name) {
	Value value;
	if (!context.TryGetCurrentSetting(Identifier(name), value) || value.IsNull()) {
		return string();
	}
	return value.ToString();
}

//! Setting value if set, otherwise the environment variable
static string SettingOrEnv(ClientContext &context, const char *name, const char *env) {
	auto value = GetStringSetting(context, name);
	if (value.empty() && env) {
		value = GetEnv(env);
	}
	return value;
}

string VaultConfig::AuthMethodToString(VaultAuthMethod method) {
	switch (method) {
	case VaultAuthMethod::TOKEN:
		return "token";
	case VaultAuthMethod::USERPASS:
		return "userpass";
	case VaultAuthMethod::LDAP:
		return "ldap";
	case VaultAuthMethod::KUBERNETES:
		return "kubernetes";
	case VaultAuthMethod::JWT:
		return "jwt";
	default:
		throw InternalException("Unknown VaultAuthMethod");
	}
}

VaultAuthMethod VaultConfig::AuthMethodFromString(const string &method_p) {
	auto method = StringUtil::Lower(method_p);
	StringUtil::Trim(method);
	if (method.empty() || method == "token") {
		return VaultAuthMethod::TOKEN;
	}
	if (method == "userpass") {
		return VaultAuthMethod::USERPASS;
	}
	if (method == "ldap") {
		return VaultAuthMethod::LDAP;
	}
	if (method == "kubernetes") {
		return VaultAuthMethod::KUBERNETES;
	}
	if (method == "jwt" || method == "oidc") {
		return VaultAuthMethod::JWT;
	}
	throw InvalidInputException(
	    "Unknown vault_auth_method '%s'. Supported methods: token, userpass, ldap, kubernetes, jwt", method_p);
}

static void ValidateAuthMethod(ClientContext &context, SetScope scope, Value &parameter) {
	if (!parameter.IsNull()) {
		VaultConfig::AuthMethodFromString(parameter.ToString());
	}
}

static void ValidateCacheTTL(ClientContext &context, SetScope scope, Value &parameter) {
	if (!parameter.IsNull() && parameter.GetValue<int64_t>() < 0) {
		throw InvalidInputException("vault_cache_ttl_seconds must be >= 0");
	}
}

static void ValidateMaxParallelRequests(ClientContext &context, SetScope scope, Value &parameter) {
	if (!parameter.IsNull() && parameter.GetValue<int64_t>() < 1) {
		throw InvalidInputException("vault_max_parallel_requests must be >= 1");
	}
}

string VaultConfig::Fingerprint() const {
	// Includes credentials so that changing e.g. the token forces a re-login. Never displayed.
	return StringUtil::Join(vector<string> {addr, vault_namespace, AuthMethodToString(auth_method), auth_mount, token,
	                                        username, password, role, jwt, jwt_path, kv_mount, kv_prefix},
	                        "\x1f");
}

void VaultConfig::RegisterSettings(DBConfig &config) {
	auto add = [&](const char *name, const char *description, LogicalType type, Value default_value,
	               set_option_callback_t callback = nullptr) {
		config.AddExtensionOption(Identifier(name), description, std::move(type), default_value, callback,
		                          SetScope::GLOBAL);
	};
	add("vault_addr", "Address of the Vault server, e.g. https://vault:8200 (falls back to VAULT_ADDR)",
	    LogicalType::VARCHAR, Value(""));
	add("vault_namespace", "Vault Enterprise namespace (falls back to VAULT_NAMESPACE)", LogicalType::VARCHAR,
	    Value(""));
	add("vault_auth_method", "Vault auth method: token, userpass, ldap, kubernetes or jwt", LogicalType::VARCHAR,
	    Value("token"), ValidateAuthMethod);
	add("vault_auth_mount", "Mount path of the Vault auth method (defaults to the method name)", LogicalType::VARCHAR,
	    Value(""));
	add("vault_token", "Vault token for the token auth method (falls back to VAULT_TOKEN, then ~/.vault-token)",
	    LogicalType::VARCHAR, Value(""));
	add("vault_username", "Username for the userpass/ldap auth methods (falls back to VAULT_USERNAME)",
	    LogicalType::VARCHAR, Value(""));
	add("vault_password", "Password for the userpass/ldap auth methods (falls back to VAULT_PASSWORD)",
	    LogicalType::VARCHAR, Value(""));
	add("vault_role", "Role for the kubernetes/jwt auth methods (falls back to VAULT_ROLE)", LogicalType::VARCHAR,
	    Value(""));
	add("vault_jwt", "JWT for the kubernetes/jwt auth methods (falls back to VAULT_JWT)", LogicalType::VARCHAR,
	    Value(""));
	add("vault_jwt_path",
	    "File containing the JWT for the kubernetes/jwt auth methods (kubernetes defaults to the service account "
	    "token)",
	    LogicalType::VARCHAR, Value(""));
	add("vault_kv_mount", "Mount path of the KV v2 secrets engine that stores DuckDB secrets", LogicalType::VARCHAR,
	    Value("secret"));
	add("vault_kv_prefix", "Path prefix inside the KV mount under which DuckDB secrets are stored",
	    LogicalType::VARCHAR, Value("duckdb"));
	add("vault_cache_ttl_seconds", "How long secrets read from Vault are cached before re-reading (0 disables)",
	    LogicalType::BIGINT, Value::BIGINT(60), ValidateCacheTTL);
	add("vault_max_parallel_requests",
	    "Maximum number of secrets read from Vault at the same time (1 reads one by one)", LogicalType::BIGINT,
	    Value::BIGINT(8), ValidateMaxParallelRequests);
}

static string TrimAddress(string value) {
	StringUtil::Trim(value);
	while (!value.empty() && value.back() == '/') {
		value.pop_back();
	}
	return value;
}

static string TrimSlashes(string value) {
	StringUtil::Trim(value);
	while (!value.empty() && value.back() == '/') {
		value.pop_back();
	}
	while (!value.empty() && value.front() == '/') {
		value.erase(0, 1);
	}
	return value;
}

string VaultConfig::ReadCredentialFile(FileSystem &fs, const string &path) {
	// Through DuckDB's file system, so enable_external_access and allowed_directories apply
	auto handle = fs.OpenFile(path, FileFlags::FILE_FLAGS_READ);
	auto size = handle->GetFileSize();
	if (size > MAX_CREDENTIAL_FILE_SIZE) {
		throw InvalidConfigurationException("Credential file '%s' is too large (%llu bytes)", path, size);
	}
	string result(size, '\0');
	handle->Read(&result[0], size);
	StringUtil::Trim(result);
	return result;
}

//! Fill the credentials from a secret of type vault matching the address. Returns false if there is none.
static bool CredentialsFromSecret(ClientContext &context, VaultConfig &config) {
	auto &manager = SecretManager::Get(context);
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
	auto match = manager.LookupSecret(transaction, config.addr, VaultConfig::SECRET_TYPE);
	if (!match.HasMatch()) {
		return false;
	}
	auto &secret = match.GetSecret().Cast<KeyValueSecret>();
	auto get = [&](const char *key) {
		Value value;
		return secret.TryGetValue(key, value) && !value.IsNull() ? value.ToString() : string();
	};
	config.token = get("token");
	config.username = get("username");
	config.password = get("password");
	config.jwt = get("jwt");
	auto role = get("role");
	if (!role.empty()) {
		config.role = role;
	}
	return true;
}

VaultConfig VaultConfig::FromContext(ClientContext &context) {
	VaultConfig result;
	auto addr_setting = GetStringSetting(context, "vault_addr");
	auto env_addr = GetEnv("VAULT_ADDR");
	result.addr = TrimAddress(addr_setting.empty() ? env_addr : addr_setting);
	// Credentials from the environment or files belong to the environment's Vault: only send them there
	bool env_credentials = !result.addr.empty() && result.addr == TrimAddress(env_addr);

	result.vault_namespace = TrimSlashes(SettingOrEnv(context, "vault_namespace", "VAULT_NAMESPACE"));
	result.auth_method = AuthMethodFromString(GetStringSetting(context, "vault_auth_method"));
	result.auth_mount = TrimSlashes(GetStringSetting(context, "vault_auth_mount"));
	if (result.auth_mount.empty()) {
		result.auth_mount = AuthMethodToString(result.auth_method);
	}
	result.role = SettingOrEnv(context, "vault_role", "VAULT_ROLE");
	result.jwt_path = GetStringSetting(context, "vault_jwt_path");

	// Opt-in: a vault secret replaces the credential settings and the environment
	bool credentials_from_secret = !result.addr.empty() && CredentialsFromSecret(context, result);
	if (!credentials_from_secret) {
		auto setting_or_env = [&](const char *setting, const char *env) {
			auto value = GetStringSetting(context, setting);
			return value.empty() && env_credentials ? GetEnv(env) : value;
		};
		switch (result.auth_method) {
		case VaultAuthMethod::TOKEN:
			result.token = setting_or_env("vault_token", "VAULT_TOKEN");
			if (result.token.empty() && env_credentials) {
				auto &fs = FileSystem::GetFileSystem(context);
				auto token_file = fs.ExpandPath("~/.vault-token");
				if (fs.FileExists(token_file)) {
					result.token = ReadCredentialFile(fs, token_file);
				}
			}
			break;
		case VaultAuthMethod::USERPASS:
		case VaultAuthMethod::LDAP:
			result.username = setting_or_env("vault_username", "VAULT_USERNAME");
			result.password = setting_or_env("vault_password", "VAULT_PASSWORD");
			break;
		case VaultAuthMethod::KUBERNETES:
		case VaultAuthMethod::JWT:
			result.jwt = setting_or_env("vault_jwt", "VAULT_JWT");
			if (result.jwt_path.empty() && env_credentials && result.auth_method == VaultAuthMethod::KUBERNETES) {
				result.jwt_path = DEFAULT_KUBERNETES_JWT_PATH;
			}
			break;
		}
	}

	result.kv_mount = TrimSlashes(GetStringSetting(context, "vault_kv_mount"));
	if (result.kv_mount.empty()) {
		result.kv_mount = "secret";
	}
	result.kv_prefix = TrimSlashes(GetStringSetting(context, "vault_kv_prefix"));
	for (auto &path : {result.kv_mount, result.kv_prefix}) {
		for (auto &segment : StringUtil::Split(path, '/')) {
			if (segment == "." || segment == "..") {
				throw InvalidConfigurationException("vault_kv_mount and vault_kv_prefix must not contain '.' or '..' "
				                                    "path segments, got '%s'",
				                                    path);
			}
		}
	}

	Value ttl;
	if (context.TryGetCurrentSetting(Identifier("vault_cache_ttl_seconds"), ttl) && !ttl.IsNull()) {
		result.cache_ttl_seconds = ttl.GetValue<int64_t>();
	}
	Value max_parallel;
	if (context.TryGetCurrentSetting(Identifier("vault_max_parallel_requests"), max_parallel) &&
	    !max_parallel.IsNull()) {
		result.max_parallel_requests = max_parallel.GetValue<int64_t>();
	}
	return result;
}

} // namespace duckdb
