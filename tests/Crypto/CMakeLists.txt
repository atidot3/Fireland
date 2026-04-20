# ============================================================================
# Tests unitaires Crypto
# ============================================================================

set(sources_files
  main.cpp
  test_sha1.cpp
  test_world_crypt.cpp
)

add_executable(firelands_crypto_tests ${sources_files})

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${sources_files})

target_link_libraries(firelands_crypto_tests
  PRIVATE
    firelands_crypto
    firelands_utils
    Boost::unit_test_framework
)

target_include_directories(firelands_crypto_tests PRIVATE
  ${CMAKE_SOURCE_DIR}/src/common/Crypto/include
  ${CMAKE_SOURCE_DIR}/src/common/Utils/include
)

set_target_properties(firelands_crypto_tests PROPERTIES FOLDER "Tests/Crypto")

add_test(NAME firelands_crypto COMMAND firelands_crypto_tests)
