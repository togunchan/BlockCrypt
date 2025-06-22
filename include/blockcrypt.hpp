#ifndef BLOCKCRYPT_HPP
#define BLOCKCRYPT_HPP

#include <array>
#include <cstdint>
#include "../constants/BlockCryptConstants.hpp"

class BlockCrypt
{
public:
    using Block = std::array<uint8_t, BLOCK_SIZE>;
    using Key = std::array<uint8_t, KEY_SIZE>;

    BlockCrypt(const Key &key);

    void encrypt(Block &plaintext);  // function to crypt
    void decrypt(Block &ciphertext); // function to decrypt
    void printBlock(Block &block, const std::string &message) const;

private:
    std::array<Key, 11> roundKeys;
    void keyExpansion(const Key &key);
    void addRoundKey(Block &block, const Key &roundKey) const;
    void printRoundKeys() const;
    void shiftRows(Block &block) const;
    void subBytes(Block &block) const;
    void mixColumns(Block &block) const;
    void invShiftRows(Block &block) const;
    void invSubBytes(Block &block) const;
    void invMixColumns(Block &block) const;

    uint8_t gmul(uint8_t a, uint8_t b) const;
};

#endif // BLOCKCRYPT_HPP