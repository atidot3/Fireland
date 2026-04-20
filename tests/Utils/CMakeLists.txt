# ============================================================================
# Tests unitaires Utils
# ============================================================================

set(sources_files
  main.cpp
  test_utils_describe.cpp
  test_string_utils.cpp
  test_bytebuffer.cpp
  test_Configuration.cpp
)

add_executable(firelands_utils_tests ${sources_files})

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${sources_files})

target_link_libraries(firelands_utils_tests
  PRIVATE
    firelands_utils
    Boost::unit_test_framework
)

target_include_directories(firelands_utils_tests PRIVATE
  ${CMAKE_SOURCE_DIR}/src/common/Utils/include
)

set_target_properties(firelands_utils_tests PROPERTIES FOLDER "Tests/Utils")

add_test(NAME firelands_utils COMMAND firelands_utils_tests)
