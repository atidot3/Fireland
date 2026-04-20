# ============================================================================
# authserver — Firelands Authentication Server
# ============================================================================

set(headers_files
    Network/AuthSession.h
    Realm/Realm.h
)

set(sources_files
    Network/AuthSession.cpp
    Realm/Realm.cpp
    main.cpp
)

add_executable(authserver
    ${headers_files}
    ${sources_files}
)

target_link_libraries(authserver
    PRIVATE
        firelands_compiler_options
        firelands_utils
        firelands_crypto
        firelands_network
        firelands_database
)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${headers_files} ${sources_files})

set_target_properties(authserver PROPERTIES FOLDER "Server")
