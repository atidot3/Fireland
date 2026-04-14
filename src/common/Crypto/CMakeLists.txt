# ============================================================================
# common/Crypto — Cryptographic primitives (SHA1, BigNumber, SRP6)
#
# Uses Boost.Multiprecision (header-only) for big integer arithmetic
# and Boost.UUID's SHA1 implementation.  No external crypto library needed.
# ============================================================================

set(headers_files
    ARC4.h
    BigNumber.h
    HMAC.h
    SHA1.h
    SRP6.h
    WorldCrypt.h
)

set(sources_files
    BigNumber.cpp
    SRP6.cpp
)

add_library(fireland_crypto STATIC
    ${headers_files}
    ${sources_files}
)

target_include_directories(fireland_crypto
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/..   # allows #include <Crypto/SHA1.h>
)

target_link_libraries(fireland_crypto
    PUBLIC
        fireland_compiler_options
        Boost::headers
        Boost::multiprecision
        Boost::uuid
)

set_target_properties(fireland_crypto PROPERTIES FOLDER "Common")
