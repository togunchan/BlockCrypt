#ifndef BLOCKCRYPT_HPP
#define BLOCKCRYPT_HPP

#include <array>
#include <cstdint>

const uint8_t BLOCK_SIZE = 16;
const uint8_t KEY_SIZE = 16;

class BlockCrypt
{
public:
    using Block = std::array<uint8_t, BLOCK_SIZE>;
    using Key = std::array<uint8_t, KEY_SIZE>;

    BlockCrypt(const Key &key);

    Block encrypt(const Block &plaintext);  // function to crypt
    Block decrypt(const Block &ciphertext); // function to decrypt

private:
    Key roundKeys[11];
    void keyExpansion(const Key &key);
};

#endif // BLOCKCRYPT_HPP