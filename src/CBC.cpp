#include "../include/CBC.hpp"
#include "../include/padding.hpp"
#include <algorithm>

namespace BC
{
    void encryptCBC(std::vector<uint8_t> &buf, const BlockCrypt::Key &key, const BlockCrypt::Block &iv, bool pad)
    {
        BlockCrypt aes(key);
        BlockCrypt::Block prev = iv;
        if (pad)
            BCPad::addPKCS7(buf);

        for (std::size_t i = 0; i < buf.size(); i += 16)
        {
            BlockCrypt::Block block;
            std::copy_n(buf.begin() + i, 16, block.begin());

            for (int b = 0; b < 16; b++)
            {
                block[b] ^= prev[b];
            }

            aes.encrypt(block);
            std::copy(block.begin(), block.end(), buf.begin() + i);
            prev = block;
        }
    }

    void decryptCBC(std::vector<uint8_t> &data, const BlockCrypt::Key &key, const BlockCrypt::Block &iv, bool pad)
    {
        BlockCrypt aes(key);
        BlockCrypt::Block prev = iv;
        for (std::size_t i = 0; i < data.size(); i += 16)
        {
            BlockCrypt::Block block;
            std::copy_n(data.begin() + i, 16, block.begin());

            BlockCrypt::Block temp = block;
            aes.decrypt(temp);

            for (int b = 0; b < 16; b++)
            {
                temp[b] ^= prev[b];
            }

            std::copy(temp.begin(), temp.end(), data.begin() + i);
            prev = block;
        }
        if (pad)
            BCPad::removePKCS7(data);
    }
}
