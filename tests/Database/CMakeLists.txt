# ============================================================================
# Tests unitaires Database
# ============================================================================

set(sources_files
  main.cpp
  test_database.cpp
)

add_executable(firelands_database_tests ${sources_files})

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${sources_files})

target_link_libraries(firelands_database_tests
  PRIVATE
    firelands_database
    firelands_crypto
    firelands_utils
    Boost::unit_test_framework
)

target_include_directories(firelands_database_tests PRIVATE
  ${CMAKE_SOURCE_DIR}/src/common/Database/include
  ${CMAKE_SOURCE_DIR}/src/common/Crypto/include
  ${CMAKE_SOURCE_DIR}/src/common/Utils/include
)

set_target_properties(firelands_database_tests PROPERTIES FOLDER "Tests/Database")

add_test(NAME firelands_database COMMAND firelands_database_tests)
