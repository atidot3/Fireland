# ============================================================================
# authserver — Fireland Authentication Server
# ============================================================================

set(headers_files
)

set(sources_files
  main.cpp
)

add_executable(authserver
  ${headers_files}
  ${sources_files}
)

target_link_libraries(authserver
  PRIVATE
    fireland_compiler_options
    fireland_network
)

set_target_properties(authserver PROPERTIES FOLDER "Server")
