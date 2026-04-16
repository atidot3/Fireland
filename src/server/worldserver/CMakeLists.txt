# ============================================================================
# worldserver — Fireland World Server
# ============================================================================

set(headers_files
    WorldSession.h
)

set(sources_files
  WorldSession.cpp
  main.cpp
)

add_executable(worldserver
  ${headers_files}
  ${sources_files}
)

target_link_libraries(worldserver
  PRIVATE
    fireland_compiler_options
    fireland_crypto
    fireland_network
    fireland_database
)

set_target_properties(worldserver PROPERTIES FOLDER "Server")
