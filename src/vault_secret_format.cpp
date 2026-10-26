#include "vault_secret_format.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/type_visitor.hpp"

namespace duckdb {

void VaultSecretFormat::Serialize(const BaseSecret &secret, JSONBuilder &builder, JSONBuilder::mut_t target) {
	auto kv_secret = dynamic_cast<const KeyValueSecret *>(&secret);
	if (!kv_secret) {
		throw NotImplementedException("Secret '%s' of type '%s' cannot be stored in Vault: only key/value secrets are "
		                              "supported",
		                              secret.GetName().GetIdentifierName(), secret.GetType().GetIdentifierName());
	}

	builder.AddString(target, TYPE_FIELD, secret.GetType().GetIdentifierName());
	builder.AddString(target, PROVIDER_FIELD, secret.GetProvider().GetIdentifierName());

	auto scope = builder.NewArray();
	for (auto &prefix : secret.GetScope()) {
		builder.Append(scope, prefix);
	}
	builder.AddValue(target, SCOPE_FIELD, scope);

	auto types = builder.NewObject();
	for (auto &entry : kv_secret->secret_map) {
		auto key = StringUtil::Lower(entry.first.GetIdentifierName());
		if (IsReservedField(key)) {
			throw InvalidInputException("Secret key '%s' cannot be stored in Vault: the field name is reserved", key);
		}
		auto &value = entry.second;
		if (value.type().id() != LogicalTypeId::VARCHAR) {
			builder.AddString(types, key, value.type().ToString());
		}
		if (value.IsNull()) {
			builder.AddNull(target, key);
		} else {
			builder.AddString(target, key, value.ToString());
		}
	}
	builder.AddValue(target, TYPES_FIELD, types);
}

//! Parse a reserved list field: JSON array, JSON array text, or comma-separated text
static vector<string> ParseList(JSONReader::val_t val) {
	if (!val) {
		return {};
	}
	if (JSONReader::IsString(val)) {
		auto text = JSONReader::AsString(val);
		StringUtil::Trim(text);
		if (text.empty()) {
			return {};
		}
		if (text[0] == '[') {
			auto doc = JSONReader::Parse(text);
			return JSONReader::GetStringArray(doc.Root());
		}
		vector<string> result;
		for (auto &item : StringUtil::Split(text, ',')) {
			auto trimmed = item;
			StringUtil::Trim(trimmed);
			if (!trimmed.empty()) {
				result.push_back(trimmed);
			}
		}
		return result;
	}
	return JSONReader::GetStringArray(val);
}

//! Parse the types field: JSON object or JSON object text
static case_insensitive_map_t<string> ParseTypes(JSONReader::val_t val) {
	case_insensitive_map_t<string> result;
	if (!val) {
		return result;
	}
	auto collect = [&](JSONReader::val_t obj) {
		using namespace duckdb_yyjson; // NOLINT: the foreach macro uses unqualified names
		if (!obj || !yyjson_is_obj(obj)) {
			throw InvalidInputException("Vault field '%s' must be a JSON object", VaultSecretFormat::TYPES_FIELD);
		}
		size_t idx, max;
		yyjson_val *key, *type;
		yyjson_obj_foreach(obj, idx, max, key, type) {
			if (JSONReader::IsString(type)) {
				result[JSONReader::AsString(key)] = JSONReader::AsString(type);
			}
		}
	};
	if (JSONReader::IsString(val)) {
		auto text = JSONReader::AsString(val);
		StringUtil::Trim(text);
		if (!text.empty()) {
			auto doc = JSONReader::Parse(text);
			collect(doc.Root());
		}
	} else {
		collect(val);
	}
	return result;
}

//! Secrets only hold built-in types, so no catalog (and no client context lock) is needed to parse them
static LogicalType ParseType(const string &type) {
	auto result = UnboundType::TryParseAndDefaultBind(type);
	if (TypeVisitor::Contains(result, LogicalTypeId::UNBOUND)) {
		throw InvalidInputException("Type \"%s\" is not a built-in type", type);
	}
	return result;
}

//! Convert one stored field into a DuckDB value
static Value ToValue(JSONReader::val_t val, const string *declared_type) {
	using namespace duckdb_yyjson; // NOLINT
	Value result;
	if (yyjson_is_null(val)) {
		result = Value();
	} else if (yyjson_is_str(val)) {
		result = Value(JSONReader::AsString(val));
	} else if (yyjson_is_bool(val)) {
		result = Value::BOOLEAN(yyjson_get_bool(val));
	} else if (yyjson_is_int(val)) {
		result = yyjson_is_uint(val) ? Value::UBIGINT(yyjson_get_uint(val)) : Value::BIGINT(yyjson_get_sint(val));
	} else if (yyjson_is_real(val)) {
		result = Value::DOUBLE(yyjson_get_real(val));
	} else {
		// arrays/objects written by hand: keep the JSON text
		result = Value(JSONReader::Write(val));
	}
	if (!declared_type) {
		return result;
	}
	auto type = ParseType(*declared_type);
	if (result.IsNull()) {
		return Value(type);
	}
	if (result.type() == type) {
		return result;
	}
	// Go through VARCHAR so that every stored representation (string, number, bool) casts the same way
	return Value(result.ToString()).DefaultCastAs(type, true);
}

bool VaultSecretFormat::IsReservedField(const string &key) {
	return key == TYPE_FIELD || key == PROVIDER_FIELD || key == SCOPE_FIELD || key == TYPES_FIELD;
}

void VaultSecretFormat::SetRedactKeys(KeyValueSecret &secret) {
	secret.redact_keys.clear();
	for (auto &entry : secret.secret_map) {
		if (!IsNonSensitiveKey(entry.first.GetIdentifierName())) {
			secret.redact_keys.insert(entry.first);
		}
	}
}

bool VaultSecretFormat::IsNonSensitiveKey(const string &key) {
	static const case_insensitive_set_t non_sensitive {"region",
	                                                   "endpoint",
	                                                   "url_style",
	                                                   "use_ssl",
	                                                   "url_compatibility_mode",
	                                                   "account_name",
	                                                   "kms_key_id",
	                                                   "requester_pays",
	                                                   "http_proxy",
	                                                   "verify_ssl",
	                                                   "storage_account_name",
	                                                   "refresh",
	                                                   "validation",
	                                                   "chain",
	                                                   "profile",
	                                                   "service_principal_id",
	                                                   "tenant_id"};
	return non_sensitive.count(key) > 0;
}

unique_ptr<BaseSecret> VaultSecretFormat::Deserialize(const string &name, JSONReader::val_t data) {
	using namespace duckdb_yyjson; // NOLINT
	if (!data || !yyjson_is_obj(data)) {
		return nullptr;
	}
	auto type = JSONReader::GetString(data, TYPE_FIELD);
	StringUtil::Trim(type);
	if (type.empty()) {
		return nullptr;
	}
	auto provider = JSONReader::GetString(data, PROVIDER_FIELD);
	StringUtil::Trim(provider);
	if (provider.empty()) {
		provider = "config";
	}
	auto scope = ParseList(JSONReader::Get(data, SCOPE_FIELD));
	auto types = ParseTypes(JSONReader::Get(data, TYPES_FIELD));

	auto result = make_uniq<KeyValueSecret>(scope, Identifier(StringUtil::Lower(type)),
	                                        Identifier(StringUtil::Lower(provider)), Identifier(name));

	size_t idx, max;
	yyjson_val *key_val, *field;
	yyjson_obj_foreach(data, idx, max, key_val, field) {
		auto key = StringUtil::Lower(JSONReader::AsString(key_val));
		if (IsReservedField(key)) {
			continue;
		}
		auto type_entry = types.find(key);
		try {
			result->secret_map[Identifier(key)] =
			    ToValue(field, type_entry == types.end() ? nullptr : &type_entry->second);
		} catch (std::exception &ex) {
			ErrorData error(ex);
			throw InvalidInputException("Vault secret '%s': could not read field '%s': %s", name, key,
			                            error.RawMessage());
		}
	}
	SetRedactKeys(*result);
	return std::move(result);
}

} // namespace duckdb
