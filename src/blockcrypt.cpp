#include "../include/blockcrypt.hpp"
#include <iostream>
#include <iomanip>

BlockCrypt::BlockCrypt(const Key &key)
{
    keyExpansion(key);
}

void BlockCrypt::keyExpansion(const Key &key)
{
    // This function implements the key expansion phase of the AES algorithm.
    // It takes the initial cipher key and generates all round keys required for encryption or decryption.
    // AES requires 44 words (each word = 4 bytes) for the key schedule:
    // Round 0 key is directly copied from the input key.
    // Subsequent keys are calculated by performing transformations like RotWord, SubWord, and Rcon operations.

    // Fill the first round key (round 0) with the key
    for (int i = 0; i < KEY_SIZE; ++i)
    {
        roundKeys[0][i] = key[i];
    }

    uint8_t temp[4];
    uint8_t rconIndex = 1;

    // Expand for each word (44 words total, 0-3 already filled)
    for (int wordIdx = 4; wordIdx < 44; ++wordIdx)
    {
        // Store the previous word in temp
        int prevWord = wordIdx - 1;
        for (int j = 0; j < 4; ++j)
        {
            temp[j] = roundKeys[prevWord / 4][(prevWord % 4) * 4 + j];
        }

        // Apply transformation on every 4th word
        if (wordIdx % 4 == 0)
        {
            // RotWord
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // SubWord
            for (int j = 0; j < 4; ++j)
            {
                temp[j] = sBox[temp[j]];
            }

            // add Rcon
            if (rconIndex >= sizeof(rcon) / sizeof(rcon[0]))
            {
                throw std::runtime_error("Rcon index out of bounds during key expansion!");
            }
            std::cout << "Using rcon[" << static_cast<int>(rconIndex) << "] = " << std::hex << static_cast<int>(rcon[rconIndex]) << std::dec << std::endl;
            temp[0] ^= rcon[rconIndex++];
        }

        // Calculate the target position in the roundKeys matrix and XOR it with the value at the same position from 4 words ago
        for (int j = 0; j < 4; ++j)
        {
            int targetRound = wordIdx / 4;
            int targetPos = (wordIdx % 4) * 4 + j;

            int prevRound = (wordIdx - 4) / 4;
            int prevPos = ((wordIdx - 4) % 4) * 4 + j;

            roundKeys.at(targetRound).at(targetPos) =
                roundKeys.at(prevRound).at(prevPos) ^ temp[j];
        }
    }
}

void BlockCrypt::printRoundKeys() const
{
    std::cout << "Round Keys:\n";
    for (int round = 0; round < 11; ++round)
    {
        std::cout << "Round " << round << ": ";
        for (int i = 0; i < KEY_SIZE; ++i)
        {
            std::cout << std::hex << static_cast<int>(roundKeys[round][i]) << " ";
        }
        std::cout << std::endl;
    }
}

void BlockCrypt::subBytes(Block &block) const
{
    // This function performs the "SubBytes" step of AES encryption or decryption.
    // It replaces each byte in the block with the corresponding value from the S-Box (substitution box),
    // which is a lookup table designed for non-linear transformation and security enhancement.
    // The S-Box introduces confusion, making it harder for attackers to analyze the encryption process.
    // printBlock(block, "Before subBytes");

    for (int i = 0; i < BLOCK_SIZE; ++i)
    {
        block[i] = sBox[block[i]];
    }
    // printBlock(block, "After subBytes");
}

void BlockCrypt::invSubBytes(Block &block) const
{
    // This function performs the "InvSubBytes" step of AES decryption.
    // It replaces each byte in the block with the corresponding value from the inverse S-Box (invSBox),
    // which reverses the non-linear transformation introduced by the S-Box during encryption.
    for (int i = 0; i < BLOCK_SIZE; ++i)
    {
        block[i] = invSBox[block[i]]; // Replace each byte using the Inverse S-Box lookup table
    }
}

void BlockCrypt::printBlock(Block &block, const std::string &message) const
{
    std::cout << message << ": ";
    std::cout << std::endl;
    for (int row = 0; row < 4; ++row)
    {
        for (int col = 0; col < 4; ++col)
        {
            // Access elements in column-major order
            std::cout << std::setw(3) << std::hex << static_cast<int>(block[col * 4 + row]) << " ";
        }
        std::cout << std::endl;
    }
    std::cout << std::endl;
}

inline uint8_t & ::BlockCrypt::cell(Block &b, int row, int col)
{
    return b[col * 4 + row];
}
inline uint8_t BlockCrypt::cell(const Block &b, int row, int col)
{
    return b[col * 4 + row];
}

void BlockCrypt::shiftRows(Block &block) const
{
    /*  ⎡ S0  S4  S8  S12 ⎤       ⎡ S0   S4   S8   S12 ⎤
        ⎢ S1  S5  S9  S13 ⎥  →    ⎢ S5   S9   S13  S1  ⎥
        ⎢ S2  S6  S10 S14 ⎥       ⎢ S10  S14  S2   S6  ⎥
        ⎣ S3  S7  S11 S15 ⎦       ⎣ S15  S3   S7   S11 ⎦ */

    // Since the block is stored in a 4x4 matrix,
    // the 2nd row is shifted 1 position to the left,
    // the 3rd row is shifted 2 positions to the left,
    // and the 4th row is shifted 3 positions to the left.

    // printBlock(block, "Before shiftRows");

    // Row-1  (b1  b5  b9  b13) ─rotl1→ (b5  b9  b13 b1)
    uint8_t temp = cell(block, 1, 0);
    cell(block, 1, 0) = cell(block, 1, 1);
    cell(block, 1, 1) = cell(block, 1, 2);
    cell(block, 1, 2) = cell(block, 1, 3);
    cell(block, 1, 3) = temp;

    // (b2  b6  b10 b14) ─rotl2→ (b10 b14 b2  b6)
    std::swap(cell(block, 2, 0), cell(block, 2, 2));
    std::swap(cell(block, 2, 1), cell(block, 2, 3));

    // (b3  b7  b11 b15) ─rotl3→ (b15 b3  b7  b11)
    temp = cell(block, 3, 3);
    cell(block, 3, 3) = cell(block, 3, 2);
    cell(block, 3, 2) = cell(block, 3, 1);
    cell(block, 3, 1) = cell(block, 3, 0);
    cell(block, 3, 0) = temp;

    // printBlock(block, "After shiftRows: ");
}

void BlockCrypt::invShiftRows(Block &block) const
{
    /*  ⎡ S0   S4   S8   S12 ⎤       ⎡ S0  S4  S8  S12 ⎤
        ⎢ S5   S9   S13  S1  ⎥  →    ⎢ S1  S5  S9  S13 ⎥
        ⎢ S10  S14  S2   S6  ⎥       ⎢ S2  S6  S10 S14 ⎥
        ⎣ S15  S3   S7   S11 ⎦       ⎣ S3  S7  S11 S15 ⎦
    */

    // (b5  b9  b13 b1) ─rotr1→ (b1  b5  b9  b13)
    uint8_t temp = cell(block, 1, 3);
    cell(block, 1, 3) = cell(block, 1, 2);
    cell(block, 1, 2) = cell(block, 1, 1);
    cell(block, 1, 1) = cell(block, 1, 0);
    cell(block, 1, 0) = temp;

    // (b10 b14 b2  b6) ─rotr2→ (b2  b6  b10 b14)
    std::swap(cell(block, 2, 0), cell(block, 2, 2));
    std::swap(cell(block, 2, 1), cell(block, 2, 3));

    // (b15 b3  b7  b11)─rotr3→ (b3  b7  b11 b15)
    temp = cell(block, 3, 0);
    cell(block, 3, 0) = cell(block, 3, 1);
    cell(block, 3, 1) = cell(block, 3, 2);
    cell(block, 3, 2) = cell(block, 3, 3);
    cell(block, 3, 3) = temp;
}

void BlockCrypt::addRoundKey(Block &block, const Key &roundKey) const
{
    // This function applies the "AddRoundKey" step of AES encryption or decryption.
    // It XORs each byte of the current block with the corresponding byte of the round key.
    // The XOR operation ensures that the data is securely transformed while maintaining reversibility.
    for (int i = 0; i < BLOCK_SIZE; ++i)
    {
        block[i] ^= roundKey[i];
    }
}

/*
 * This function performs multiplication of two 8-bit numbers in the Galois Field GF(2^8),
 * which is widely used in cryptographic algorithms like AES.
 * The multiplication involves bitwise operations, modular addition (XOR),
 * and modular reduction using the AES-specific irreducible polynomial (0x1b).
 * Parameters:
 *   a - The first 8-bit number to be multiplied.
 *   b - The second 8-bit number to be multiplied.
 * Returns:
 *   The result of the multiplication in GF(2^8).
 */
uint8_t BlockCrypt::gmul(uint8_t a, uint8_t b) const
{
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i)
    {
        if (b & 1) // Check if the least significant bit of b is set
        {
            p ^= a;
        }
        bool high_bit = a & 0x80;
        a <<= 1;
        if (high_bit) // Check if the most significant bit of a is set
        {
            // If the most significant bit (MSB) was set before shifting (high_bit is true),
            // apply modular reduction by XORing 'a' with 0x1b (the AES irreducible polynomial).
            // This ensures the value remains within the boundaries of the Galois Field GF(2^8).
            a ^= 0x1b;
        }
        b >>= 1;
    }
    return p;
}

void BlockCrypt::mixColumns(Block &block) const
{
    // This function performs the "MixColumns" step of AES encryption or decryption.
    // printBlock(block, "Before mixColumns");
    for (int col = 0; col < 4; ++col)
    {
        uint8_t s0 = cell(block, 0, col);
        uint8_t s1 = cell(block, 1, col);
        uint8_t s2 = cell(block, 2, col);
        uint8_t s3 = cell(block, 3, col);

        // Apply the MixColumns transformation using the GF(2^8) constants

        cell(block, 0, col) = gmul(s0, 2) ^ gmul(s1, 3) ^ gmul(s2, 1) ^ gmul(s3, 1);
        cell(block, 1, col) = gmul(s0, 1) ^ gmul(s1, 2) ^ gmul(s2, 3) ^ gmul(s3, 1);
        cell(block, 2, col) = gmul(s0, 1) ^ gmul(s1, 1) ^ gmul(s2, 2) ^ gmul(s3, 3);
        cell(block, 3, col) = gmul(s0, 3) ^ gmul(s1, 1) ^ gmul(s2, 1) ^ gmul(s3, 2);
    }
    // printBlock(block, "After mixColumns");
}

void BlockCrypt::invMixColumns(Block &block) const
{
    // This function performs the "InvMixColumns" step of AES decryption.
    for (int col = 0; col < 4; ++col) // Iterate through each column
    {
        uint8_t s0 = cell(block, 0, col);
        uint8_t s1 = cell(block, 1, col);
        uint8_t s2 = cell(block, 2, col);
        uint8_t s3 = cell(block, 3, col);

        // Apply the inverse MixColumns transformation using the GF(2^8) constants
        cell(block, 0, col) = gmul(s0, 14) ^ gmul(s1, 11) ^ gmul(s2, 13) ^ gmul(s3, 9);
        cell(block, 1, col) = gmul(s0, 9) ^ gmul(s1, 14) ^ gmul(s2, 11) ^ gmul(s3, 13);
        cell(block, 2, col) = gmul(s0, 13) ^ gmul(s1, 9) ^ gmul(s2, 14) ^ gmul(s3, 11);
        cell(block, 3, col) = gmul(s0, 11) ^ gmul(s1, 13) ^ gmul(s2, 9) ^ gmul(s3, 14);
    }
}

void BlockCrypt::encrypt(Block &plaintext)
{
    addRoundKey(plaintext, roundKeys[0]);
    for (int round = 1; round < 10; ++round)
    {
        subBytes(plaintext);
        shiftRows(plaintext);
        mixColumns(plaintext);
        addRoundKey(plaintext, roundKeys[round]);
    }
    subBytes(plaintext);
    shiftRows(plaintext);
    addRoundKey(plaintext, roundKeys[10]);
}

void BlockCrypt::decrypt(Block &plaintext)
{
    addRoundKey(plaintext, roundKeys[10]);
    for (int round = 9; round > 0; --round)
    {
        invShiftRows(plaintext);
        invSubBytes(plaintext);
        addRoundKey(plaintext, roundKeys[round]);
        invMixColumns(plaintext);
    }
    invShiftRows(plaintext);
    invSubBytes(plaintext);
    addRoundKey(plaintext, roundKeys[0]);
}
