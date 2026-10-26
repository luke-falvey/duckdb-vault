#include "vault_secret_format.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"

namespace duckdb {

//! Store a secret value as the matching JSON type
static void AddJSONValue(JSONBuilder &builder, JSONBuilder::mut_t target, const string &key, const Value &value,
                         const string &secret_name) {
	if (value.IsNull()) {
		builder.AddNull(target, key);
		return;
	}
	auto &type = value.type();
	switch (type.id()) {
	case LogicalTypeId::VARCHAR:
		builder.AddString(target, key, StringValue::Get(value));
		return;
	case LogicalTypeId::BOOLEAN:
		builder.AddBool(target, key, BooleanValue::Get(value));
		return;
	case LogicalTypeId::TINYINT:
	case LogicalTypeId::SMALLINT:
	case LogicalTypeId::INTEGER:
	case LogicalTypeId::BIGINT:
		builder.AddInt(target, key, value.GetValue<int64_t>());
		return;
	case LogicalTypeId::UTINYINT:
	case LogicalTypeId::USMALLINT:
	case LogicalTypeId::UINTEGER:
	case LogicalTypeId::UBIGINT:
		builder.AddUInt(target, key, value.GetValue<uint64_t>());
		return;
	case LogicalTypeId::FLOAT:
	case LogicalTypeId::DOUBLE:
		builder.AddDouble(target, key, value.GetValue<double>());
		return;
	case LogicalTypeId::MAP:
		if (MapType::KeyType(type).id() == LogicalTypeId::VARCHAR &&
		    MapType::ValueType(type).id() == LogicalTypeId::VARCHAR) {
			auto map = builder.NewObject();
			for (auto &entry : MapValue::GetChildren(value)) {
				auto &key_value = StructValue::GetChildren(entry);
				auto map_key = StringValue::Get(key_value[0]);
				if (key_value[1].IsNull()) {
					builder.AddNull(map, map_key);
				} else {
					builder.AddString(map, map_key, StringValue::Get(key_value[1]));
				}
			}
			builder.AddValue(target, key, map);
			return;
		}
		break;
	default:
		break;
	}
	throw NotImplementedException("Secret '%s' cannot be stored in Vault: value '%s' has type %s, which has no JSON "
	                              "equivalent",
	                              secret_name, key, type.ToString());
}

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

	for (auto &entry : kv_secret->secret_map) {
		auto key = StringUtil::Lower(entry.first.GetIdentifierName());
		if (IsReservedField(key)) {
			throw InvalidInputException("Secret key '%s' cannot be stored in Vault: the field name is reserved", key);
		}
		AddJSONValue(builder, target, key, entry.second, secret.GetName().GetIdentifierName());
	}
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

//! Convert one stored field into a DuckDB value, by JSON type
static Value ToValue(JSONReader::val_t val) {
	using namespace duckdb_yyjson; // NOLINT
	if (yyjson_is_null(val)) {
		return Value();
	}
	if (yyjson_is_str(val)) {
		return Value(JSONReader::AsString(val));
	}
	if (yyjson_is_bool(val)) {
		return Value::BOOLEAN(yyjson_get_bool(val));
	}
	if (yyjson_is_sint(val)) {
		return Value::BIGINT(yyjson_get_sint(val));
	}
	if (yyjson_is_uint(val)) {
		auto number = yyjson_get_uint(val);
		return number <= static_cast<uint64_t>(NumericLimits<int64_t>::Maximum())
		           ? Value::BIGINT(static_cast<int64_t>(number))
		           : Value::UBIGINT(number);
	}
	if (yyjson_is_real(val)) {
		return Value::DOUBLE(yyjson_get_real(val));
	}
	if (yyjson_is_obj(val)) {
		vector<Value> keys;
		vector<Value> values;
		size_t idx, max;
		yyjson_val *key, *entry;
		yyjson_obj_foreach(val, idx, max, key, entry) {
			keys.emplace_back(JSONReader::AsString(key));
			if (yyjson_is_null(entry)) {
				values.emplace_back(LogicalType::VARCHAR);
			} else if (yyjson_is_str(entry)) {
				values.emplace_back(JSONReader::AsString(entry));
			} else {
				throw InvalidInputException("map values must be strings");
			}
		}
		return Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(keys), std::move(values));
	}
	throw InvalidInputException("JSON arrays are not supported as secret values");
}

bool VaultSecretFormat::IsReservedField(const string &key) {
	return key == TYPE_FIELD || key == PROVIDER_FIELD || key == SCOPE_FIELD;
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

	auto result = make_uniq<KeyValueSecret>(scope, Identifier(StringUtil::Lower(type)),
	                                        Identifier(StringUtil::Lower(provider)), Identifier(name));

	size_t idx, max;
	yyjson_val *key_val, *field;
	yyjson_obj_foreach(data, idx, max, key_val, field) {
		auto key = StringUtil::Lower(JSONReader::AsString(key_val));
		if (IsReservedField(key)) {
			continue;
		}
		try {
			result->secret_map[Identifier(key)] = ToValue(field);
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
