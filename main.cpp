#include <iostream>
#include <vector>
#include <string>
#include "blockcrypt.hpp"
#include "CBC.hpp"

int main()
{
    BlockCrypt::Key key = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x4d, 0x4d,
        0x09, 0xcf, 0x4f, 0x3c};

    BlockCrypt::Block iv = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f};

    std::string message = "Hello, BlockCrypt CBC Mode!";
    std::vector<uint8_t> data(message.begin(), message.end());

    std::cout << "[Original Message] " << message << "\n";

    BC::encryptCBC(data, key, iv);

    std::cout << "[Encrypted Bytes] ";
    for (auto byte : data)
        std::cout << std::hex << (int)byte << " ";
    std::cout << std::dec << "\n";

    BC::decryptCBC(data, key, iv);

    std::string decrypted(data.begin(), data.end());
    std::cout << "[Decrypted Message] " << decrypted << "\n";

    return 0;
}