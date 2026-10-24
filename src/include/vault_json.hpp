#pragma once

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "yyjson.hpp"

#include <cstdlib>

namespace duckdb {

//! Read-only JSON document (thin RAII wrapper around yyjson)
class JSONReader {
public:
	using val_t = duckdb_yyjson::yyjson_val *;

	JSONReader() = default;
	JSONReader(const JSONReader &) = delete;
	JSONReader(JSONReader &&other) noexcept : doc(other.doc) {
		other.doc = nullptr;
	}
	~JSONReader() {
		if (doc) {
			duckdb_yyjson::yyjson_doc_free(doc);
		}
	}

	static JSONReader Parse(const string &text) {
		JSONReader result;
		duckdb_yyjson::yyjson_read_err err;
		result.doc = duckdb_yyjson::yyjson_read_opts(const_cast<char *>(text.c_str()), text.size(), 0, nullptr, &err);
		if (!result.doc) {
			throw IOException("Invalid JSON from Vault: %s", err.msg ? err.msg : "parse error");
		}
		return result;
	}

	val_t Root() const {
		return duckdb_yyjson::yyjson_doc_get_root(doc);
	}

	//! Object member (nullptr if obj is not an object or the key is missing)
	static val_t Get(val_t obj, const char *key) {
		if (!obj || !duckdb_yyjson::yyjson_is_obj(obj)) {
			return nullptr;
		}
		return duckdb_yyjson::yyjson_obj_get(obj, key);
	}

	static bool IsString(val_t val) {
		return val && duckdb_yyjson::yyjson_is_str(val);
	}

	static string AsString(val_t val) {
		return string(duckdb_yyjson::yyjson_get_str(val), duckdb_yyjson::yyjson_get_len(val));
	}

	static string GetString(val_t obj, const char *key) {
		auto val = Get(obj, key);
		return IsString(val) ? AsString(val) : string();
	}

	static int64_t GetInt(val_t obj, const char *key, int64_t default_value) {
		auto val = Get(obj, key);
		if (!val || !duckdb_yyjson::yyjson_is_num(val)) {
			return default_value;
		}
		return static_cast<int64_t>(duckdb_yyjson::yyjson_get_num(val));
	}

	static vector<string> GetStringArray(val_t arr) {
		using namespace duckdb_yyjson; // NOLINT: the foreach macro uses unqualified names
		vector<string> result;
		if (!arr || !duckdb_yyjson::yyjson_is_arr(arr)) {
			return result;
		}
		size_t idx, max;
		val_t item;
		yyjson_arr_foreach(arr, idx, max, item) {
			if (IsString(item)) {
				result.push_back(AsString(item));
			}
		}
		return result;
	}

	//! Serialize any value back to JSON text
	static string Write(val_t val) {
		size_t len;
		auto data = duckdb_yyjson::yyjson_val_write(val, 0, &len);
		if (!data) {
			return string();
		}
		string result(data, len);
		free(data);
		return result;
	}

private:
	duckdb_yyjson::yyjson_doc *doc = nullptr;
};

//! Mutable JSON document builder
class JSONBuilder {
public:
	using mut_t = duckdb_yyjson::yyjson_mut_val *;

	JSONBuilder() {
		doc = duckdb_yyjson::yyjson_mut_doc_new(nullptr);
		root = duckdb_yyjson::yyjson_mut_obj(doc);
		duckdb_yyjson::yyjson_mut_doc_set_root(doc, root);
	}
	JSONBuilder(const JSONBuilder &) = delete;
	~JSONBuilder() {
		duckdb_yyjson::yyjson_mut_doc_free(doc);
	}

	mut_t Root() {
		return root;
	}
	mut_t NewObject() {
		return duckdb_yyjson::yyjson_mut_obj(doc);
	}
	mut_t NewArray() {
		return duckdb_yyjson::yyjson_mut_arr(doc);
	}
	void AddString(mut_t obj, const string &key, const string &value) {
		duckdb_yyjson::yyjson_mut_obj_add(obj, Key(key),
		                                  duckdb_yyjson::yyjson_mut_strncpy(doc, value.c_str(), value.size()));
	}
	void AddInt(mut_t obj, const string &key, int64_t value) {
		duckdb_yyjson::yyjson_mut_obj_add(obj, Key(key), duckdb_yyjson::yyjson_mut_sint(doc, value));
	}
	void AddNull(mut_t obj, const string &key) {
		duckdb_yyjson::yyjson_mut_obj_add(obj, Key(key), duckdb_yyjson::yyjson_mut_null(doc));
	}
	void AddValue(mut_t obj, const string &key, mut_t value) {
		duckdb_yyjson::yyjson_mut_obj_add(obj, Key(key), value);
	}
	void Append(mut_t arr, const string &value) {
		duckdb_yyjson::yyjson_mut_arr_append(arr, duckdb_yyjson::yyjson_mut_strncpy(doc, value.c_str(), value.size()));
	}
	//! Serialize a (sub-)value to compact JSON
	string Write(mut_t val) {
		size_t len;
		auto data = duckdb_yyjson::yyjson_mut_val_write(val, 0, &len);
		if (!data) {
			throw InternalException("Failed to serialize JSON");
		}
		string result(data, len);
		free(data);
		return result;
	}
	string ToString() {
		return Write(root);
	}

private:
	mut_t Key(const string &key) {
		return duckdb_yyjson::yyjson_mut_strncpy(doc, key.c_str(), key.size());
	}

	duckdb_yyjson::yyjson_mut_doc *doc;
	mut_t root;
};

} // namespace duckdb
