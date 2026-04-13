# ============================================================================
# authserver — Fireland Authentication Server
# ============================================================================

set(headers_files
    AuthOpcode.h
    AuthSession.h
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
)

set_target_properties(authserver PROPERTIES FOLDER "Server")
