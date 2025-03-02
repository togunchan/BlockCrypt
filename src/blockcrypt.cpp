#include "blockcrypt.hpp"

void BlockCrypt::keyExpansion(const Key &key)
{
    // Set the first 16 bytes (the key) as roundKeys[0]
    // This serves as the initial key for the key expansion process.
    for (int i = 0; i < KEY_SIZE; ++i)
    {
        roundKeys[0][i] = key[i];
    }

    uint8_t temp[4];       // Temporary array to hold 4 bytes for key schedule transformation
    uint8_t rconIndex = 1; // Index for the round constant (rcon) array used in key expansion

    /*
     * The initial key is stored in roundKeys[0] (bytes 0 to 15).
     *
     * The algorithm then continues in a flattened manner. When i starts at 16, that corresponds
     * to the beginning of the next 16-byte block (which will become roundKeys[1]).
     *
     * At i = 16, the code accesses roundKeys[i - 1], which is roundKeys[15] in the flattened view—
     * that is, the last byte of the first block.
     *
     * This is not actually the 15th round key, but rather the last byte of the first key block
     * in the contiguous key schedule. It’s used to compute the next word (4 bytes) in the expanded key.
     */
    for (int i = KEY_SIZE; i < 44 * 4; ++i)
    {
        for (int j = 0; j < 4; ++j)
        {
            temp[j] = roundKeys[i - 1][j];
        }

        /*
         * If the index is divisible by the key size (i % KEY_SIZE == 0),
         * perform a left circular shift (rotate) on the temp array.
         * This means shifting each byte in temp one position to the left, and moving the first byte to the last position.
         */
        if (i % KEY_SIZE == 0)
        {
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
        }

        for (int j = 0; j < 4; ++j)
        {
            // Substitute each byte in the temp array using the S-Box lookup table
            temp[j] = sBox[temp[j]];
        }

        temp[0] ^= rcon[rconIndex++]; // adding rcon

        for (int j = 0; j < 4; ++j)
        {
            // Compute the new round key by XORing the current key byte
            // with the byte from the key KEY_SIZE steps back and the transformed temp array byte
            roundKeys[i][j] = roundKeys[i - KEY_SIZE][j] ^ temp[j];
        }
    }
}
