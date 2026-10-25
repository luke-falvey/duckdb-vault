#include "vault_config.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/config.hpp"

#include <cstdlib>
#include <fstream>
#include <sstream>

namespace duckdb {

static string GetEnv(const char *name) {
	auto value = std::getenv(name);
	return value ? string(value) : string();
}

static string ReadFileTrimmed(const string &path) {
	std::ifstream in(path);
	if (!in.good()) {
		return string();
	}
	std::stringstream buffer;
	buffer << in.rdbuf();
	auto result = buffer.str();
	StringUtil::Trim(result);
	return result;
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

VaultConfig VaultConfig::FromContext(ClientContext &context) {
	VaultConfig result;
	result.addr = SettingOrEnv(context, "vault_addr", "VAULT_ADDR");
	StringUtil::Trim(result.addr);
	while (!result.addr.empty() && result.addr.back() == '/') {
		result.addr.pop_back();
	}
	result.vault_namespace = TrimSlashes(SettingOrEnv(context, "vault_namespace", "VAULT_NAMESPACE"));
	result.auth_method = AuthMethodFromString(GetStringSetting(context, "vault_auth_method"));
	result.auth_mount = TrimSlashes(GetStringSetting(context, "vault_auth_mount"));
	if (result.auth_mount.empty()) {
		result.auth_mount = AuthMethodToString(result.auth_method);
	}

	switch (result.auth_method) {
	case VaultAuthMethod::TOKEN:
		result.token = SettingOrEnv(context, "vault_token", "VAULT_TOKEN");
		if (result.token.empty()) {
			auto home = GetEnv("HOME");
			if (!home.empty()) {
				result.token = ReadFileTrimmed(home + "/.vault-token");
			}
		}
		break;
	case VaultAuthMethod::USERPASS:
	case VaultAuthMethod::LDAP:
		result.username = SettingOrEnv(context, "vault_username", "VAULT_USERNAME");
		result.password = SettingOrEnv(context, "vault_password", "VAULT_PASSWORD");
		break;
	case VaultAuthMethod::KUBERNETES:
	case VaultAuthMethod::JWT:
		result.role = SettingOrEnv(context, "vault_role", "VAULT_ROLE");
		result.jwt = SettingOrEnv(context, "vault_jwt", "VAULT_JWT");
		result.jwt_path = GetStringSetting(context, "vault_jwt_path");
		if (result.jwt_path.empty() && result.auth_method == VaultAuthMethod::KUBERNETES) {
			result.jwt_path = "/var/run/secrets/kubernetes.io/serviceaccount/token";
		}
		break;
	}

	result.kv_mount = TrimSlashes(GetStringSetting(context, "vault_kv_mount"));
	if (result.kv_mount.empty()) {
		result.kv_mount = "secret";
	}
	result.kv_prefix = TrimSlashes(GetStringSetting(context, "vault_kv_prefix"));

	Value ttl;
	if (context.TryGetCurrentSetting(Identifier("vault_cache_ttl_seconds"), ttl) && !ttl.IsNull()) {
		result.cache_ttl_seconds = ttl.GetValue<int64_t>();
	}
	return result;
}

} // namespace duckdb
