#pragma once

#include "vault_config.hpp"

#include <chrono>

namespace duckdb {

class DatabaseInstance;

struct VaultResponse {
	int status = 0;
	string body;

	bool Ok() const {
		return status >= 200 && status < 300;
	}
};

//! Information about the token in use, from auth/token/lookup-self
struct VaultTokenInfo {
	string display_name;
	vector<string> policies;
	int64_t ttl = 0;
};

//! Minimal Vault HTTP API client on top of DuckDB's HTTP stack, which the httpfs extension provides. Handles
//! authentication and re-authentication. Not thread-safe: callers serialize.
class VaultClient {
public:
	//! Loads httpfs if needed; throws if it is not available
	VaultClient(DatabaseInstance &db, VaultConfig config);

	const VaultConfig &Config() const {
		return config;
	}

	//! The connection requests are made for, if any: its settings (proxy, httpfs TLS options) apply
	void SetContext(optional_ptr<ClientContext> context_p) {
		context = context_p;
	}

	//! Perform an authenticated request against /v1/<path>. Logs in when needed and retries once on 403 for
	//! login-based auth methods (the token may have expired or been revoked).
	VaultResponse Request(const string &method, const string &path, const string &body = string());

	//! Make sure a usable token is available (logs in if necessary)
	void EnsureAuthenticated();

	VaultTokenInfo LookupSelf();

	//! Throw a DuckDB exception describing a failed Vault call
	[[noreturn]] static void ThrowError(const string &action, const string &path, const VaultResponse &response);
	//! Extract the "errors" array of a Vault error response as a single string
	static string ErrorMessage(const VaultResponse &response);

	//! Whether this thread is currently inside a Vault request
	static bool RequestInProgress();

	//! Percent-encode a single path segment
	static string EncodePathSegment(const string &segment);

private:
	VaultResponse Send(const string &method, const string &path, const string &body, bool with_token);
	void Login();
	bool UsesLogin() const {
		return config.auth_method != VaultAuthMethod::TOKEN;
	}

	DatabaseInstance &db;
	optional_ptr<ClientContext> context;
	VaultConfig config;
	string token;
	bool has_expiry = false;
	std::chrono::steady_clock::time_point token_expiry;
};

} // namespace duckdb
