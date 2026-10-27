#pragma once

#include "duckdb.hpp"

namespace duckdb {

class DBConfig;
class FileSystem;

//! Supported Vault authentication methods
enum class VaultAuthMethod : uint8_t { TOKEN, USERPASS, LDAP, KUBERNETES, JWT };

//! Fully resolved Vault connection settings (DuckDB settings with environment-variable fallbacks applied)
struct VaultConfig {
	//! Base address, e.g. https://vault.example.com:8200 (no trailing slash)
	string addr;
	//! Vault Enterprise namespace (sent as X-Vault-Namespace)
	string vault_namespace;

	VaultAuthMethod auth_method = VaultAuthMethod::TOKEN;
	//! Mount path of the auth method, e.g. "userpass" -> auth/userpass/login
	string auth_mount;
	string token;
	string username;
	string password;
	string role;
	//! JWT given inline; takes precedence over jwt_path
	string jwt;
	string jwt_path;

	//! KV v2 mount and the path prefix under which DuckDB secrets are kept
	string kv_mount;
	string kv_prefix;

	int64_t cache_ttl_seconds = 60;

	bool IsConfigured() const {
		return !addr.empty();
	}

	//! Identity of the connection/credentials: if this changes, cached tokens and secrets are discarded
	string Fingerprint() const;

	//! Secret type that can hold the credentials (opt-in, instead of the credential settings)
	static constexpr const char *SECRET_TYPE = "vault";
	static constexpr const char *DEFAULT_KUBERNETES_JWT_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token";
	static constexpr idx_t MAX_CREDENTIAL_FILE_SIZE = 1024 * 1024;

	//! Read a token or JWT file through DuckDB's file system (so file access settings apply)
	static string ReadCredentialFile(FileSystem &fs, const string &path);

	static string AuthMethodToString(VaultAuthMethod method);
	static VaultAuthMethod AuthMethodFromString(const string &method);

	//! Register all vault_* settings
	static void RegisterSettings(DBConfig &config);
	//! Resolve the settings visible to a client context
	static VaultConfig FromContext(ClientContext &context);
};

} // namespace duckdb
