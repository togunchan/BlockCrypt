#include "blockcrypt.hpp"
#include <iostream>

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

            std::cout << std::dec << "temp[" << j << "]: " << " roundKeys[" << prevWord / 4 << "][" << (prevWord % 4) * 4 + j << "]" << " = ";
            std::cout << std::hex << static_cast<uint16_t>(temp[j]) << std::endl;
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