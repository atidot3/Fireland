// ============================================================================
// Tests unitaires Crypto::WorldCrypt et Crypto::ARC4
// ============================================================================
#include <boost/test/unit_test.hpp>
#include <Crypto/WorldCrypt.h>
#include <Crypto/ARC4.h>
#include <Crypto/HMAC.h>
#include <array>

using namespace Firelands::Crypto;

// ============================================================================
// ARC4 Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(arc4_init_test)
{
    ARC4 cipher;
    
    // Initialize with a simple key
    uint8_t key[] = {0x01, 0x02, 0x03, 0x04};
    cipher.Init(std::span<const uint8_t>(key));
    
    // Just verify it's initialized without throwing
    BOOST_TEST(true);
}

BOOST_AUTO_TEST_CASE(arc4_process_test)
{
    ARC4 cipher;
    
    // Initialize with a test key
    uint8_t key[] = {0xAA, 0xBB, 0xCC, 0xDD};
    cipher.Init(std::span<const uint8_t>(key));
    
    // Create test data
    uint8_t plaintext[] = {0x00, 0x00, 0x00, 0x00};
    uint8_t ciphertext[] = {0x00, 0x00, 0x00, 0x00};
    
    std::copy(plaintext, plaintext + 4, ciphertext);
    cipher.Process(std::span<uint8_t>(ciphertext));
    
    // Ciphertext should be different from plaintext
    bool different = false;
    for (int i = 0; i < 4; ++i) {
        if (ciphertext[i] != plaintext[i]) {
            different = true;
            break;
        }
    }
    BOOST_TEST(different);
}

BOOST_AUTO_TEST_CASE(arc4_drop_test)
{
    ARC4 cipher1, cipher2;
    uint8_t key[] = {0x11, 0x22, 0x33, 0x44};
    
    // Initialize both with the same key
    cipher1.Init(std::span<const uint8_t>(key));
    cipher2.Init(std::span<const uint8_t>(key));
    
    // Drop bytes in cipher1
    cipher1.Drop(100);
    
    // Encrypt same data with both
    uint8_t data1[] = {0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t data2[] = {0xFF, 0xFF, 0xFF, 0xFF};
    
    cipher1.Process(std::span<uint8_t>(data1));
    cipher2.Process(std::span<uint8_t>(data2));
    
    // Results should be different because cipher1 dropped bytes
    bool different = false;
    for (int i = 0; i < 4; ++i) {
        if (data1[i] != data2[i]) {
            different = true;
            break;
        }
    }
    BOOST_TEST(different);
}

BOOST_AUTO_TEST_CASE(arc4_symmetric_test)
{
    ARC4 encryptCipher, decryptCipher;
    uint8_t key[] = {0x12, 0x34, 0x56, 0x78};
    
    // Initialize both with the same key
    encryptCipher.Init(std::span<const uint8_t>(key));
    decryptCipher.Init(std::span<const uint8_t>(key));
    
    // Original data
    uint8_t plaintext[] = {0xAA, 0xBB, 0xCC, 0xDD};
    uint8_t encrypted[] = {0xAA, 0xBB, 0xCC, 0xDD};
    uint8_t decrypted[] = {0x00, 0x00, 0x00, 0x00};
    
    // Encrypt
    encryptCipher.Process(std::span<uint8_t>(encrypted));
    
    // Decrypt
    decryptCipher.Process(std::span<uint8_t>(encrypted));
    std::copy(encrypted, encrypted + 4, decrypted);
    
    // Should match original
    for (int i = 0; i < 4; ++i) {
        BOOST_TEST(decrypted[i] == plaintext[i]);
    }
}

// ============================================================================
// WorldCrypt Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(worldcrypt_init_test)
{
    WorldCrypt crypt;
    
    // Create a dummy session key (32 bytes for WoW auth)
    uint8_t sessionKey[32];
    for (int i = 0; i < 32; ++i)
        sessionKey[i] = static_cast<uint8_t>(i);
    
    crypt.Init(std::span<const uint8_t>(sessionKey));
    BOOST_TEST(crypt.IsInitialized());
}

BOOST_AUTO_TEST_CASE(worldcrypt_encrypt_decrypt_test)
{
    WorldCrypt crypt;
    
    // Session key
    uint8_t sessionKey[32];
    for (int i = 0; i < 32; ++i)
        sessionKey[i] = static_cast<uint8_t>(i);
    
    crypt.Init(std::span<const uint8_t>(sessionKey));
    
    // SMSG header (4 bytes: size + opcode)
    uint8_t header[] = {0x12, 0x34, 0x56, 0x78};
    uint8_t encrypted[] = {0x12, 0x34, 0x56, 0x78};
    
    // Encrypt
    crypt.EncryptSend(encrypted, 4);
    
    // Encrypted should be different from original
    bool different = false;
    for (int i = 0; i < 4; ++i) {
        if (encrypted[i] != header[i]) {
            different = true;
            break;
        }
    }
    BOOST_TEST(different);
}

BOOST_AUTO_TEST_CASE(worldcrypt_header_sizes_test)
{
    WorldCrypt crypt;
    
    uint8_t sessionKey[32];
    for (int i = 0; i < 32; ++i)
        sessionKey[i] = static_cast<uint8_t>(i);
    
    crypt.Init(std::span<const uint8_t>(sessionKey));
    
    // Test SMSG header (4 bytes)
    uint8_t smsgHeader[] = {0x00, 0x00, 0x00, 0x00};
    crypt.EncryptSend(smsgHeader, 4);
    
    // Test CMSG header (6 bytes)
    WorldCrypt crypt2;
    crypt2.Init(std::span<const uint8_t>(sessionKey));
    uint8_t cmsgHeader[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    crypt2.DecryptRecv(cmsgHeader, 6);
    
    BOOST_TEST(true); // Just verify it handles different sizes without crashing
}

BOOST_AUTO_TEST_CASE(worldcrypt_uninitialized_test)
{
    WorldCrypt crypt;
    
    // Try to encrypt without initialization
    uint8_t header[] = {0x12, 0x34, 0x56, 0x78};
    uint8_t original[] = {0x12, 0x34, 0x56, 0x78};
    
    crypt.EncryptSend(header, 4);
    
    // Should be unchanged since not initialized
    for (int i = 0; i < 4; ++i) {
        BOOST_TEST(header[i] == original[i]);
    }
}

BOOST_AUTO_TEST_CASE(hmac_sha1_test)
{
    // Test HMAC-SHA1 used for key derivation
    uint8_t key[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t data[] = {0x05, 0x06, 0x07, 0x08};
    
    auto hash = HMAC_SHA1(std::span<const uint8_t>(key), 
                          std::span<const uint8_t>(data));
    
    // Should produce a 20-byte hash
    BOOST_TEST(hash.size() == 20U);
    
    // Hash should not be all zeros
    bool nonzero = false;
    for (uint8_t byte : hash) {
        if (byte != 0) {
            nonzero = true;
            break;
        }
    }
    BOOST_TEST(nonzero);
}

BOOST_AUTO_TEST_CASE(worldcrypt_deterministic_test)
{
    // Test that same input produces same output
    uint8_t sessionKey[32];
    for (int i = 0; i < 32; ++i)
        sessionKey[i] = static_cast<uint8_t>(i);
    
    WorldCrypt crypt1, crypt2;
    crypt1.Init(std::span<const uint8_t>(sessionKey));
    crypt2.Init(std::span<const uint8_t>(sessionKey));
    
    uint8_t header1[] = {0xAA, 0xBB, 0xCC, 0xDD};
    uint8_t header2[] = {0xAA, 0xBB, 0xCC, 0xDD};
    
    crypt1.EncryptSend(header1, 4);
    crypt2.EncryptSend(header2, 4);
    
    // Same input with same key should produce same encrypted output
    for (int i = 0; i < 4; ++i) {
        BOOST_TEST(header1[i] == header2[i]);
    }
}
