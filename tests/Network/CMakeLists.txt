# ============================================================================
# Tests unitaires Network
# ============================================================================

set(sources_files
  main.cpp
  test_packet_buffer.cpp
)

add_executable(firelands_network_tests ${sources_files})

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${sources_files})

target_link_libraries(firelands_network_tests
  PRIVATE
    firelands_network
    firelands_utils
    Boost::unit_test_framework
)

target_include_directories(firelands_network_tests PRIVATE
  ${CMAKE_SOURCE_DIR}/src/common/Network/include
  ${CMAKE_SOURCE_DIR}/src/common/Utils/include
)

set_target_properties(firelands_network_tests PROPERTIES FOLDER "Tests/Network")

add_test(NAME firelands_network COMMAND firelands_network_tests)
