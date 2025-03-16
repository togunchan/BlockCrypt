#include "blockcrypt.hpp"
#include <iostream>
#include <iomanip>

BlockCrypt::BlockCrypt(const Key &key)
{
    keyExpansion(key);
}

void BlockCrypt::keyExpansion(const Key &key)
{
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

            // Rcon ekle
            temp[0] ^= rcon[rconIndex++];
        }

        // Calculate the target position in the roundKeys matrix and XOR it with the value at the same position from 4 words ago
        for (int j = 0; j < 4; ++j)
        {
            int targetRound = wordIdx / 4;
            int targetPos = (wordIdx % 4) * 4 + j;
            roundKeys[targetRound][targetPos] = roundKeys[(wordIdx - 4) / 4][((wordIdx - 4) % 4) * 4 + j] ^ temp[j];
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
    for (int i = 0; i < BLOCK_SIZE; ++i)
    {
        block[i] = sBox[block[i]];
    }
}

void BlockCrypt::printBlock(Block &block, const std::string &message) const
{
    std::cout << message << ": ";
    for (int row = 0; row < 4; ++row)
    {
        for (int col = 0; col < 4; ++col)
        {
            std::cout << std::setw(3) << std::hex << static_cast<int>(block[row * 4 + col]) << " ";
        }
        std::cout << std::endl;
    }
    std::cout << std::endl;
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

    printBlock(block, "Before shiftRows: ");

    uint8_t temp;

    // Second row (index 1, 5, 9, 13)
    temp = block[1];
    block[1] = block[5];
    block[5] = block[9];
    block[9] = block[13];
    block[13] = temp;

    // Third row (index 2, 6, 10, 14): shift left by 2
    temp = block[2];
    block[2] = block[10];
    block[10] = temp;
    temp = block[6];
    block[6] = block[14];
    block[14] = temp;

    // Fourth row (index 3, 7, 11, 15): shift left by 3
    temp = block[15];
    block[15] = block[11];
    block[11] = block[7];
    block[7] = block[3];
    block[3] = temp;

    printBlock(block, "After shiftRows: ");
}