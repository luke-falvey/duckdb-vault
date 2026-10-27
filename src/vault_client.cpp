#include "vault_client.hpp"
#include "vault_json.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension_helper.hpp"
#include "duckdb/main/http/http_util.hpp"

namespace duckdb {

//! Set while this thread is inside a Vault HTTP request
static thread_local bool request_in_progress = false;

bool VaultClient::RequestInProgress() {
	return request_in_progress;
}

VaultClient::VaultClient(DatabaseInstance &db_p, VaultConfig config_p) : db(db_p), config(std::move(config_p)) {
	if (!config.IsConfigured()) {
		throw InvalidConfigurationException(
		    "Vault is not configured: set the vault_addr setting (or the VAULT_ADDR environment variable)");
	}
	if (!StringUtil::StartsWith(config.addr, "http://") && !StringUtil::StartsWith(config.addr, "https://")) {
		throw InvalidConfigurationException("vault_addr must start with http:// or https://, got '%s'", config.addr);
	}
	// DuckDB's built-in HTTP client only supports GET requests and plain HTTP: Vault needs httpfs
	if (!ExtensionHelper::TryAutoLoadExtension(db, "httpfs")) {
		throw MissingExtensionException("The vault extension needs the httpfs extension to talk to Vault. Install and "
		                                "load it with: INSTALL httpfs; LOAD httpfs;");
	}
	if (config.auth_method == VaultAuthMethod::TOKEN) {
		token = config.token;
	}
}

string VaultClient::EncodePathSegment(const string &segment) {
	static const char *hex = "0123456789ABCDEF";
	string result;
	for (unsigned char c : segment) {
		if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
			result += static_cast<char>(c);
		} else {
			result += '%';
			result += hex[c >> 4];
			result += hex[c & 15];
		}
	}
	return result;
}

VaultResponse VaultClient::Send(const string &method, const string &path, const string &body, bool with_token) {
	auto url = config.addr + "/v1/" + path;
	// Setting up the request looks up HTTP secrets for the URL, which asks the vault storage again
	struct RequestScope {
		RequestScope() {
			request_in_progress = true;
		}
		~RequestScope() {
			request_in_progress = false;
		}
	} scope;
	auto &http_util = HTTPUtil::Get(db);
	// Parameters from the connection (when there is one) pick up its httpfs settings, e.g. ca_cert_file
	auto params = context ? http_util.InitializeParameters(*context, url) : http_util.InitializeParameters(db, url);

	HTTPHeaders headers(db);
	headers.Insert("X-Vault-Request", "true");
	if (with_token && !token.empty()) {
		headers.Insert("X-Vault-Token", token);
	}
	if (!config.vault_namespace.empty()) {
		headers.Insert("X-Vault-Namespace", config.vault_namespace);
	}

	unique_ptr<HTTPResponse> response;
	if (method == "GET") {
		GetRequestInfo request(url, headers, *params, nullptr, nullptr);
		request.try_request = true;
		response = http_util.Request(request);
	} else if (method == "POST") {
		headers.Insert("Content-Type", "application/json");
		PostRequestInfo request(url, headers, *params, const_data_ptr_cast(body.c_str()), body.size());
		request.try_request = true;
		response = http_util.Request(request);
		// httpfs returns the body of a POST response here
		response->body = std::move(request.buffer_out);
	} else if (method == "DELETE") {
		DeleteRequestInfo request(url, headers, *params);
		request.try_request = true;
		response = http_util.Request(request);
	} else {
		throw InternalException("Unsupported Vault HTTP method %s", method);
	}
	// try_request: failures come back as a response instead of an exception
	if (response->HasRequestError()) {
		throw IOException("Failed to connect to Vault at %s: %s", config.addr, response->GetRequestError());
	}
	VaultResponse result;
	result.status = static_cast<int>(response->status);
	result.body = std::move(response->body);
	return result;
}

void VaultClient::Login() {
	string path;
	JSONBuilder body;
	switch (config.auth_method) {
	case VaultAuthMethod::TOKEN:
		if (config.token.empty()) {
			throw InvalidConfigurationException(
			    "Vault auth method is 'token' but no token was found: set vault_token or a secret of type vault. "
			    "VAULT_TOKEN and ~/.vault-token are only used for the address in VAULT_ADDR");
		}
		token = config.token;
		has_expiry = false;
		return;
	case VaultAuthMethod::USERPASS:
	case VaultAuthMethod::LDAP:
		if (config.username.empty() || config.password.empty()) {
			throw InvalidConfigurationException(
			    "Vault auth method '%s' requires vault_username and vault_password (or a secret of type vault)",
			    VaultConfig::AuthMethodToString(config.auth_method));
		}
		path = "auth/" + config.auth_mount + "/login/" + EncodePathSegment(config.username);
		body.AddString(body.Root(), "password", config.password);
		break;
	case VaultAuthMethod::KUBERNETES:
	case VaultAuthMethod::JWT: {
		if (config.role.empty()) {
			throw InvalidConfigurationException("Vault auth method '%s' requires vault_role",
			                                    VaultConfig::AuthMethodToString(config.auth_method));
		}
		auto jwt = config.jwt;
		if (jwt.empty()) {
			if (config.jwt_path.empty()) {
				throw InvalidConfigurationException(
				    "Vault auth method '%s' requires vault_jwt, vault_jwt_path or a secret of type vault",
				    VaultConfig::AuthMethodToString(config.auth_method));
			}
			auto &fs = context ? FileSystem::GetFileSystem(*context) : FileSystem::GetFileSystem(db);
			try {
				jwt = VaultConfig::ReadCredentialFile(fs, config.jwt_path);
			} catch (std::exception &ex) {
				throw InvalidConfigurationException("Could not read Vault JWT from file '%s': %s", config.jwt_path,
				                                    ErrorData(ex).RawMessage());
			}
		}
		path = "auth/" + config.auth_mount + "/login";
		body.AddString(body.Root(), "role", config.role);
		body.AddString(body.Root(), "jwt", jwt);
		break;
	}
	}

	auto response = Send("POST", path, body.ToString(), false);
	if (!response.Ok()) {
		ThrowError("log in with auth method '" + VaultConfig::AuthMethodToString(config.auth_method) + "'", path,
		           response);
	}
	auto doc = JSONReader::Parse(response.body);
	auto auth = JSONReader::Get(doc.Root(), "auth");
	auto client_token = JSONReader::GetString(auth, "client_token");
	if (client_token.empty()) {
		throw IOException("Vault login at '%s' did not return a client token", path);
	}
	token = client_token;
	auto lease = JSONReader::GetInt(auth, "lease_duration", 0);
	has_expiry = lease > 0;
	if (has_expiry) {
		// Renew a little ahead of the actual expiry
		auto margin = MinValue<int64_t>(30, lease / 10);
		token_expiry = std::chrono::steady_clock::now() + std::chrono::seconds(lease - margin);
	}
}

void VaultClient::EnsureAuthenticated() {
	if (token.empty() || (has_expiry && std::chrono::steady_clock::now() >= token_expiry)) {
		Login();
	}
}

VaultResponse VaultClient::Request(const string &method, const string &path, const string &body) {
	EnsureAuthenticated();
	auto response = Send(method, path, body, true);
	if (response.status == 403 && UsesLogin()) {
		// The token may have been revoked or expired early: log in again and retry once
		Login();
		response = Send(method, path, body, true);
	}
	return response;
}

VaultTokenInfo VaultClient::LookupSelf() {
	const string path = "auth/token/lookup-self";
	auto response = Request("GET", path);
	if (!response.Ok()) {
		ThrowError("look up the current token", path, response);
	}
	VaultTokenInfo info;
	auto doc = JSONReader::Parse(response.body);
	auto data = JSONReader::Get(doc.Root(), "data");
	info.display_name = JSONReader::GetString(data, "display_name");
	info.ttl = JSONReader::GetInt(data, "ttl", 0);
	info.policies = JSONReader::GetStringArray(JSONReader::Get(data, "policies"));
	return info;
}

string VaultClient::ErrorMessage(const VaultResponse &response) {
	try {
		auto doc = JSONReader::Parse(response.body);
		auto errors = JSONReader::GetStringArray(JSONReader::Get(doc.Root(), "errors"));
		if (!errors.empty()) {
			return StringUtil::Join(errors, "; ");
		}
	} catch (std::exception &) {
		// not JSON
	}
	auto body = response.body;
	StringUtil::Trim(body);
	return body.empty() ? "no error message" : body;
}

void VaultClient::ThrowError(const string &action, const string &path, const VaultResponse &response) {
	auto message = StringUtil::Format("Vault: failed to %s (HTTP %d on '%s'): %s", action, response.status, path,
	                                  ErrorMessage(response));
	if (response.status == 401 || response.status == 403) {
		throw PermissionException(message);
	}
	throw IOException(message);
}

} // namespace duckdb
