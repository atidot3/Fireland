# ============================================================================
# Tests unitaires Crypto
# ============================================================================

set(sources_files
  main.cpp
  test_sha1.cpp
  test_world_crypt.cpp
)

add_executable(fireland_crypto_tests ${sources_files})

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${sources_files})

target_link_libraries(fireland_crypto_tests
  PRIVATE
    fireland_crypto
    fireland_utils
    Boost::unit_test_framework
)

target_include_directories(fireland_crypto_tests PRIVATE
  ${CMAKE_SOURCE_DIR}/src/common/Crypto/include
  ${CMAKE_SOURCE_DIR}/src/common/Utils/include
)

set_target_properties(fireland_crypto_tests PROPERTIES FOLDER "Tests/Crypto")

add_test(NAME fireland_crypto COMMAND fireland_crypto_tests)
