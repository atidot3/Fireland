# ============================================================================
# Tests unitaires Crypto
# ============================================================================

add_executable(fireland_crypto_tests
  main.cpp
  test_sha1.cpp
  test_world_crypt.cpp
)

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
