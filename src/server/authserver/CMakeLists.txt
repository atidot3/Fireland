# ============================================================================
# authserver — Fireland Authentication Server
# ============================================================================

set(headers_files
    AuthOpcode.h
    AuthPacket.hpp
    AuthSession.h
    Realm.h
)

set(sources_files
    AuthSession.cpp
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
)

set_target_properties(authserver PROPERTIES FOLDER "Server")
