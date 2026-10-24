#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.hpp"

#include "vault_client.hpp"
#include "vault_json.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"

#include <fstream>
#include <sstream>

namespace duckdb {

namespace httplib = duckdb_httplib_openssl;

struct VaultHTTP {
	explicit VaultHTTP(const VaultConfig &config) : client(config.addr) {
		client.set_connection_timeout(10);
		client.set_read_timeout(30);
		client.set_write_timeout(30);
		client.set_keep_alive(true);
		if (!config.ca_cert.empty()) {
			client.set_ca_cert_path(config.ca_cert);
		}
		client.enable_server_certificate_verification(!config.tls_skip_verify);
	}

	httplib::Client client;
};

VaultClient::VaultClient(VaultConfig config_p) : config(std::move(config_p)) {
	if (!config.IsConfigured()) {
		throw InvalidConfigurationException(
		    "Vault is not configured: set the vault_addr setting (or the VAULT_ADDR environment variable)");
	}
	if (!StringUtil::StartsWith(config.addr, "http://") && !StringUtil::StartsWith(config.addr, "https://")) {
		throw InvalidConfigurationException("vault_addr must start with http:// or https://, got '%s'", config.addr);
	}
	http = make_uniq<VaultHTTP>(config);
	if (!http->client.is_valid()) {
		throw InvalidConfigurationException("Invalid vault_addr '%s'", config.addr);
	}
	if (config.auth_method == VaultAuthMethod::TOKEN) {
		token = config.token;
	}
}

VaultClient::~VaultClient() = default;

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
	httplib::Headers headers;
	headers.emplace("X-Vault-Request", "true");
	if (with_token && !token.empty()) {
		headers.emplace("X-Vault-Token", token);
	}
	if (!config.vault_namespace.empty()) {
		headers.emplace("X-Vault-Namespace", config.vault_namespace);
	}
	auto full_path = "/v1/" + path;
	httplib::Result result;
	if (method == "GET") {
		result = http->client.Get(full_path, headers);
	} else if (method == "POST") {
		result = http->client.Post(full_path, headers, body, "application/json");
	} else if (method == "DELETE") {
		result = http->client.Delete(full_path, headers);
	} else {
		throw InternalException("Unsupported Vault HTTP method %s", method);
	}
	if (!result) {
		throw IOException("Failed to connect to Vault at %s: %s", config.addr, httplib::to_string(result.error()));
	}
	VaultResponse response;
	response.status = result->status;
	response.body = result->body;
	return response;
}

static string ReadJWTFile(const string &path) {
	std::ifstream in(path);
	if (!in.good()) {
		throw InvalidConfigurationException("Could not read Vault JWT from file '%s'", path);
	}
	std::stringstream buffer;
	buffer << in.rdbuf();
	auto result = buffer.str();
	StringUtil::Trim(result);
	return result;
}

void VaultClient::Login() {
	string path;
	JSONBuilder body;
	switch (config.auth_method) {
	case VaultAuthMethod::TOKEN:
		if (config.token.empty()) {
			throw InvalidConfigurationException("Vault auth method is 'token' but no token was found: set vault_token, "
			                                    "the VAULT_TOKEN environment variable or ~/.vault-token");
		}
		token = config.token;
		has_expiry = false;
		return;
	case VaultAuthMethod::USERPASS:
	case VaultAuthMethod::LDAP:
		if (config.username.empty() || config.password.empty()) {
			throw InvalidConfigurationException("Vault auth method '%s' requires vault_username and vault_password",
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
				throw InvalidConfigurationException("Vault auth method 'jwt' requires vault_jwt or vault_jwt_path");
			}
			jwt = ReadJWTFile(config.jwt_path);
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
