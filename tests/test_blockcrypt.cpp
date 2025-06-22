#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>
#include "blockcrypt.hpp"
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