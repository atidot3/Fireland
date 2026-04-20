# ============================================================================
# worldserver — Firelands World Server
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
    firelands_compiler_options
    firelands_crypto
    firelands_network
    firelands_database
    firelands_game
)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${headers_files} ${sources_files})

set_target_properties(worldserver PROPERTIES FOLDER "Server")
