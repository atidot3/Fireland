# ============================================================================
# worldserver — Fireland World Server
# ============================================================================

set(headers_files
    
)

set(sources_files
  main.cpp
)

add_executable(worldserver
  ${headers_files}
  ${sources_files}
)

target_link_libraries(worldserver
  PRIVATE
    fireland_compiler_options
    fireland_network
)

set_target_properties(worldserver PROPERTIES FOLDER "Server")
