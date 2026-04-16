# ============================================================================
# authserver — Fireland Authentication Server
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
        fireland_compiler_options
        fireland_utils
        fireland_crypto
        fireland_network
        fireland_database
)

set_target_properties(authserver PROPERTIES FOLDER "Server")
