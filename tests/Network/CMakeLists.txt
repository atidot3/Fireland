# ============================================================================
# Tests unitaires Network
# ============================================================================

add_executable(fireland_network_tests
  main.cpp
  test_packet_buffer.cpp
)

target_link_libraries(fireland_network_tests
  PRIVATE
    fireland_network
    fireland_utils
    Boost::unit_test_framework
)

target_include_directories(fireland_network_tests PRIVATE
  ${CMAKE_SOURCE_DIR}/src/common/Network/include
  ${CMAKE_SOURCE_DIR}/src/common/Utils/include
)

set_target_properties(fireland_network_tests PROPERTIES FOLDER "Tests/Network")

add_test(NAME fireland_network COMMAND fireland_network_tests)
