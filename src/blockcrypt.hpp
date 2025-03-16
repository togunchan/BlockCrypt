#ifndef BLOCKCRYPT_HPP
#define BLOCKCRYPT_HPP

#include <array>
#include <cstdint>
#include "BlockCryptConstants.hpp"

class BlockCrypt
{
public:
    using Block = std::array<uint8_t, BLOCK_SIZE>;
    using Key = std::array<uint8_t, KEY_SIZE>;

    BlockCrypt(const Key &key);

    Block encrypt(const Block &plaintext);  // function to crypt
    Block decrypt(const Block &ciphertext); // function to decrypt

    void printRoundKeys() const;

private:
    Key roundKeys[11];
    void keyExpansion(const Key &key);
    void subBytes(Block &block) const;
    void shiftRows(Block &block) const;
    void printBlock(Block &block, const std::string &message) const;
    void mixColumns(Block &block) const;
    void addRoundKey(Block &block, const Key &roundKey) const;
};

#endif // BLOCKCRYPT_HPP