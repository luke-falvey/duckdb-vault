#define DUCKDB_EXTENSION_MAIN

#include "vault_extension.hpp"
#include "vault_client.hpp"
#include "vault_config.hpp"
#include "vault_secret_storage.hpp"

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

namespace duckdb {

//===--------------------------------------------------------------------===//
// vault_status(): the resolved configuration and whether we can authenticate
//===--------------------------------------------------------------------===//
struct VaultStatusState : public GlobalTableFunctionState {
	bool done = false;
};

static unique_ptr<FunctionData> VaultStatusBind(ClientContext &context, TableFunctionBindInput &input,
                                                vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto add = [&](const char *name, LogicalType type) {
		names.emplace_back(name);
		return_types.push_back(std::move(type));
	};
	add("address", LogicalType::VARCHAR);
	add("namespace", LogicalType::VARCHAR);
	add("auth_method", LogicalType::VARCHAR);
	add("kv_path", LogicalType::VARCHAR);
	add("authenticated", LogicalType::BOOLEAN);
	add("display_name", LogicalType::VARCHAR);
	add("policies", LogicalType::LIST(LogicalType::VARCHAR));
	add("token_ttl", LogicalType::BIGINT);
	add("error", LogicalType::VARCHAR);
	return nullptr;
}

static unique_ptr<GlobalTableFunctionState> VaultStatusInit(ClientContext &context, TableFunctionInitInput &input) {
	return make_uniq<VaultStatusState>();
}

static void VaultStatusFunction(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<VaultStatusState>();
	if (state.done) {
		return;
	}
	state.done = true;

	auto config = VaultConfig::FromContext(context);
	auto kv_path = config.kv_mount + (config.kv_prefix.empty() ? "" : "/" + config.kv_prefix);
	output.data[0].Append(config.addr.empty() ? Value() : Value(config.addr));
	output.data[1].Append(config.vault_namespace.empty() ? Value() : Value(config.vault_namespace));
	output.data[2].Append(Value(VaultConfig::AuthMethodToString(config.auth_method)));
	output.data[3].Append(Value(kv_path));

	VaultTokenInfo info;
	string error;
	try {
		VaultClient client(DatabaseInstance::GetDatabase(context), config);
		client.SetContext(context);
		info = client.LookupSelf();
	} catch (std::exception &ex) {
		error = ErrorData(ex).RawMessage();
	}
	bool authenticated = error.empty();
	vector<Value> policies;
	for (auto &policy : info.policies) {
		policies.emplace_back(policy);
	}
	output.data[4].Append(Value::BOOLEAN(authenticated));
	output.data[5].Append(authenticated ? Value(info.display_name) : Value());
	output.data[6].Append(authenticated ? Value::LIST(LogicalType::VARCHAR, std::move(policies))
	                                    : Value(LogicalType::LIST(LogicalType::VARCHAR)));
	output.data[7].Append(authenticated ? Value::BIGINT(info.ttl) : Value(LogicalType::BIGINT));
	output.data[8].Append(authenticated ? Value() : Value(error));
}

static void LoadInternal(ExtensionLoader &loader) {
	auto &db = loader.GetDatabaseInstance();
	VaultConfig::RegisterSettings(DBConfig::GetConfig(db));
	SecretManager::Get(db).LoadSecretStorage(make_uniq<VaultSecretStorage>(db));

	loader.RegisterFunction(TableFunction("vault_status", {}, VaultStatusFunction, VaultStatusBind, VaultStatusInit));
	loader.SetDescription("Store and read DuckDB secrets in HashiCorp Vault");
}

void VaultExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}

std::string VaultExtension::Name() {
	return "vault";
}

std::string VaultExtension::Version() const {
#ifdef EXT_VERSION_VAULT
	return EXT_VERSION_VAULT;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(vault, loader) {
	duckdb::LoadInternal(loader);
}
}
