#include <iostream>
#include "blockcrypt.hpp"

int main()
{
    BlockCrypt::Key key = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                           0xab, 0xf7, 0x4d, 0x4d, 0x09, 0xcf, 0x4f, 0x3c};

    BlockCrypt cipher(key);

    cipher.printRoundKeys();

    // BlockCrypt::Block plaintext = {'H', 'e', 'l', 'l', 'o', 'B', 'l', 'o',
    //                                'c', 'k', 'C', 'r', 'y', 'p', 't', '!'};

    // BlockCrypt::Block encrypted = cipher.encrypt(plaintext);
    // BlockCrypt::Block decrypted = cipher.decrypt(encrypted);

    // std::cout << "Encryption and decryption completed!" << std::endl;

    return 0;
}