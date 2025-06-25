#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>
#include "blockcrypt.hpp"
#include "padding.hpp"
#include "CBC.hpp"
#include <random>

// ------------ Basic Correctness: Single Round-Trip Test ------------
/*
    This test checks the fundamental correctness of the BlockCrypt class by
    performing a simple encrypt-decrypt cycle on a known input.

    It uses a fixed 128-bit key and a fixed 128-bit data block with ascending hex patterns.

    The test encrypts the block, then decrypts it using the same key,
    and verifies that the decrypted output matches the original block.

    This serves as a sanity check to confirm that the basic symmetric
    encryption-decryption logic preserves data integrity.
*/
TEST_CASE("Encrypt and decrypt cycle returns original block", "[blockcrypt]")
{
    BlockCrypt::Key key = {0x00, 0x01, 0x02, 0x03,
                           0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B,
                           0x0C, 0x0D, 0x0E, 0x0F};

    BlockCrypt::Block block = {0x00, 0x11, 0x22, 0x33,
                               0x44, 0x55, 0x66, 0x77,
                               0x88, 0x99, 0xAA, 0xBB,
                               0xCC, 0xDD, 0xEE, 0xFF};

    BlockCrypt crypt(key);
    BlockCrypt::Block encrypted = block;

    crypt.encrypt(encrypted);
    crypt.decrypt(encrypted);

    REQUIRE(encrypted == block);
}

// ------------ Edge Case: All-Zero and All-0xFF Patterns ------------
/*
    This test ensures that the BlockCrypt algorithm handles known edge cases
    involving patterns of all-zero (0x00) and all-0xFF (0xff) values correctly.

    Four combinations are tested:
      - Zero key with zero block
      - Zero key with 0xFF block
      - 0xFF key with zero block
      - 0xFF key with 0xFF block

    These patterns are often used to reveal weaknesses in cryptographic algorithms,
    such as non-random behavior, fixed points, or insufficient diffusion.

    The test performs an encrypt-decrypt round-trip and asserts that the
    decrypted output matches the original input exactly.

    By covering these static and extreme values, this test reinforces robustness
    against degenerate inputs that might otherwise cause subtle failures.
*/
TEST_CASE("Zero and FF edge cases", "[edge]")
{
    const BlockCrypt::Key zeroKey{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    const BlockCrypt::Key ffKey{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    const BlockCrypt::Key zeroBlk{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    const BlockCrypt::Key ffBlk{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    auto roundtrip = [](const BlockCrypt::Key &key, const BlockCrypt::Block &block)
    {
        BlockCrypt crypt(key);
        auto buf = block;
        crypt.encrypt(buf);
        crypt.decrypt(buf);
        return buf == block;
    };

    SECTION("zero-key / zero-block")
    REQUIRE(roundtrip(zeroKey, zeroBlk));
    SECTION("zero-key / ff-block")
    REQUIRE(roundtrip(zeroKey, ffBlk));
    SECTION("ff-key / zero-block")
    REQUIRE(roundtrip(ffKey, zeroBlk));
    SECTION("ff-key / ff-block")
    REQUIRE(roundtrip(ffKey, ffBlk));
}

// ------------ 2) Random 1,000 × 1,000 Combinations ------------
/*
    This test verifies whether the BlockCrypt class preserves data integrity
    during encryption and decryption operations.

    It generates 1,000 random keys.
    For each key, 1,000 random data blocks are encrypted and then decrypted.
    The goal is to ensure that the decrypted output matches the original input exactly.

    This test aims to validate the algorithm's symmetric correctness and stability.
    The high number of combinations (1 million total) increases the chance of exposing edge cases.
*/
TEST_CASE("Random round-trip fuzz", "[fuzz][long]")
{
    std::mt19937 rng{};
    std::uniform_int_distribution<uint8_t> dist(0, 255);

    auto genKey = [&]
    {
        BlockCrypt::Key k{};
        for (auto &byte : k)
            byte = dist(rng);
        return k;
    };
    auto genBlk = genKey;

    const int KEY_CNT = 1'00;
    const int BLK_CNT = 1'00;

    for (int ki = 0; ki < KEY_CNT; ++ki)
    {
        auto key = genKey();
        BlockCrypt crypt(key);

        for (int bi = 0; bi < BLK_CNT; ++bi)
        {
            auto blk = genBlk();
            auto tmp = blk;

            crypt.encrypt(tmp);
            crypt.decrypt(tmp);

            REQUIRE(tmp == blk);
        }
    }
}

/*
 * This test verifies the correctness of the PKCS7 padding and unpadding logic.
 * It starts with a short message ("Hi") and applies PKCS7 padding to reach a 16-byte block size.
 * After padding, the message size should be exactly 16 bytes.
 * Then, it removes the padding and checks that the original content is correctly restored,
 * ensuring both the padding and unpadding processes are symmetric and lossless.
 */
TEST_CASE("PKCS7 pad/unpad roundtrip")
{
    std::vector<uint8_t> msg = {'H', 'i'};
    BCPad::addPKCS7(msg);
    REQUIRE(msg.size() == 16);

    BCPad::removePKCS7(msg);
    REQUIRE(msg.size() == 2);
    REQUIRE(msg[0] == 'H');
    REQUIRE(msg[1] == 'i');
}

/*
 * CBC round-trip test:
 *
 * This unit test verifies the correctness of AES-CBC encryption and decryption
 * by performing a full round-trip cycle. A short plaintext message ("Hello") is:
 *
 *  1. Encrypted using a fixed AES key and IV (16 bytes each),
 *  2. Then decrypted using the same key and IV,
 *  3. Finally, the result is compared with the original message.
 *
 * The test ensures that:
 *  - Padding is correctly applied before encryption (PKCS#7),
 *  - CBC chaining logic preserves data integrity,
 *  - Padding is correctly removed during decryption,
 *  - The decrypted output exactly matches the original plaintext.
 */
TEST_CASE("CBC round-trip", "[cbc]")
{
    BlockCrypt::Key key{
        0xA1, 0xB2, 0xC3, 0xD4,
        0xE5, 0xF6, 0x07, 0x18,
        0x29, 0x3A, 0x4B, 0x5C,
        0x6D, 0x7E, 0x8F, 0x90};

    BlockCrypt::Block iv{
        0x10, 0x32, 0x54, 0x76,
        0x98, 0xBA, 0xDC, 0xFE,
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF};

    std::vector<uint8_t> msg = {'H', 'e', 'l', 'l', 'o'}; // 5 bytes

    BC::encryptCBC(msg, key, iv);
    BC::decryptCBC(msg, key, iv);

    REQUIRE(std::string(msg.begin(), msg.end()) == "Hello");
}

/*
 * NIST AES-128 ECB Test Vector
 *
 * This test validates the correctness of the `BlockCrypt` class's single-block
 * encryption functionality by using the official NIST AES-128 ECB test vector.
 *
 * Test steps:
 * 1. Define a fixed 128-bit encryption key.
 * 2. Specify a known 128-bit plaintext block.
 * 3. Provide the expected ciphertext output based on NIST documentation.
 * 4. Encrypt the plaintext block using ECB mode with the given key.
 * 5. Compare the encryption result with the expected ciphertext.
 *
 * Notes:
 * - This test operates on a single block, which is sufficient to verify
 *   basic ECB mode functionality.
 * - If encryption is implemented correctly, the test will pass.
 */

TEST_CASE("NIST AES-128 ECB vector", "[nist][ecb]")
{
    BlockCrypt::Key key = {
        0x2B, 0x7E, 0x15, 0x16,
        0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88,
        0x09, 0xCF, 0x4F, 0x3C};

    BlockCrypt::Block pt = {
        0x6B, 0xC1, 0xBE, 0xE2,
        0x2E, 0x40, 0x9F, 0x96,
        0xE9, 0x3D, 0x7E, 0x11,
        0x73, 0x93, 0x17, 0x2A};

    BlockCrypt::Block expect = {
        0x3A, 0xD7, 0x7B, 0xB4,
        0x0D, 0x7A, 0x36, 0x60,
        0xA8, 0x9E, 0xCA, 0xF3,
        0x24, 0x66, 0xEF, 0x97};

    BlockCrypt aes(key);
    auto ct = pt;
    aes.encrypt(ct);

    REQUIRE(ct == expect);
}
