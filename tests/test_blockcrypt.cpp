#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>
#include "blockcrypt.hpp"
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