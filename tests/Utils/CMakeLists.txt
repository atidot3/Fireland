# ============================================================================
# Tests unitaires Utils
# ============================================================================

add_executable(fireland_utils_tests
  main.cpp
  test_utils_describe.cpp
  test_string_utils.cpp
  test_bytebuffer.cpp
  test_Configuration.cpp
)

target_link_libraries(fireland_utils_tests
  PRIVATE
    fireland_utils
    Boost::unit_test_framework
)

target_include_directories(fireland_utils_tests PRIVATE
  ${CMAKE_SOURCE_DIR}/src/common/Utils/include
)

set_target_properties(fireland_utils_tests PROPERTIES FOLDER "Tests/Utils")

add_test(NAME fireland_utils COMMAND fireland_utils_tests)
