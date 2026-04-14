# ============================================================================
# worldserver — Fireland World Server
# ============================================================================

set(headers_files
    WorldOpcode.h
    WorldPacket.h
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
)

set_target_properties(worldserver PROPERTIES FOLDER "Server")
