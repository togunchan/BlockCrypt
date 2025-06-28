#pragma once

#include <vector>
#include "../include/blockcrypt.hpp"

namespace BC
{
    /**
     * Encrypts data using AES in CBC mode with PKCS#7 padding.
     *
     * @param data The plaintext buffer to encrypt. Modified in-place with padded ciphertext.
     * @param key The symmetric encryption key used by AES.
     * @param iv The initialization vector used to seed the first block in CBC mode.
     */
    void encryptCBC(std::vector<uint8_t> &data, const BlockCrypt::Key &key, const BlockCrypt::Block &iv, bool pad = true);

    /**
     * Decrypts CBC-mode AES ciphertext and removes PKCS#7 padding.
     *
     * @param data The encrypted input buffer (must be a multiple of 16 bytes). Modified in-place with plaintext.
     * @param key The symmetric AES key that was used to encrypt the original message.
     * @param iv The initialization vector used during encryption. Required for correct decryption of the first block.
     */
    void decryptCBC(std::vector<uint8_t> &data, const BlockCrypt::Key &key, const BlockCrypt::Block &iv, bool pad = true);
} // namespace BC (BlockCrypt)
