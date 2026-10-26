# This file is included by DuckDB's build system. It specifies which extension to load

# Extension from this repo
duckdb_extension_load(vault
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
)

# httpfs provides the HTTP client the vault extension talks to Vault with. It is built here (at the version pinned by
# DuckDB v2.0.0) so the tests can load it; it is not linked into the vault extension.
# The clang-tidy run only analyses this repository's sources and its environment has no curl, so it skips httpfs.
if(NOT CLANG_TIDY)
    duckdb_extension_load(httpfs
        GIT_URL https://github.com/duckdb/duckdb-httpfs
        GIT_TAG 77392a72077a85897db2519fae11e2c0da972b8a
    )
endif()
