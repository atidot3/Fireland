# ============================================================================
# common/Crypto — Cryptographic primitives (SHA1, BigNumber, SRP6)
#
# Uses Boost.Multiprecision (header-only) for big integer arithmetic
# and Boost.UUID's SHA1 implementation.  No external crypto library needed.
# ============================================================================

set(headers_files
    include/Crypto/ARC4.h
    include/Crypto/BigNumber.h
    include/Crypto/HMAC.h
    include/Crypto/SHA1.h
    include/Crypto/SRP6.h
    include/Crypto/WorldCrypt.h
)

set(sources_files
    src/BigNumber.cpp
    src/SRP6.cpp
)

add_library(fireland_crypto STATIC
    ${headers_files}
    ${sources_files}
)

target_include_directories(fireland_crypto
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/>
    $<INSTALL_INTERFACE:include/>
)

target_link_libraries(fireland_crypto
    PUBLIC
        fireland_compiler_options
        Boost::headers
        Boost::multiprecision
        Boost::uuid
)

# includes for internal use
target_include_directories(fireland_crypto PRIVATE 
  include/
  src/
)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${headers_files} ${sources_files})

set_target_properties(fireland_crypto PROPERTIES FOLDER "Common")
