#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include "blockcrypt.hpp"
#include "CBC.hpp"

using Byte = uint8_t;
using Block = BlockCrypt::Block;
using Key = BlockCrypt::Key;

// Convert hex string to byte vector, pads if odd length
std::vector<Byte> hex_to_bytes(const std::string &hex)
{
    std::vector<Byte> bytes;
    size_t len = hex.length();
    for (size_t i = 0; i + 1 < len; i += 2)
    {
        unsigned int byte;
        std::sscanf(hex.c_str() + i, "%2x", &byte);
        bytes.push_back(static_cast<Byte>(byte));
    }
    return bytes;
}

// Print detailed usage information
void print_usage(const char *prog)
{
    std::cerr << "Usage:\n"
              << "  " << prog << " encrypt [-k key_hex] [-i iv_hex] [-I infile] [-O outfile]\n"
              << "  " << prog << " decrypt [-k key_hex] [-i iv_hex] [-I infile] [-O outfile]\n"
              << "Options:\n"
              << "  -k, --key    AES key in hex (default: all zeros)\n"
              << "  -i, --iv     IV in hex (default: 000102030405060708090A0B0C0D0E0F)\n"
              << "  -I, --in     Input file (default: stdin)\n"
              << "  -O, --out    Output file (default: stdout)\n"
              << "  -h, --help   Show this help message\n";
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        print_usage(argv[0]);
        return 1;
    }

    bool do_encrypt = false;
    bool do_decrypt = false;

    std::string key_hex;
    std::string iv_hex = "000102030405060708090A0B0C0D0E0F";
    std::string infile;
    std::string outfile;

    // Determine subcommand
    if (std::strcmp(argv[1], "encrypt") == 0)
    {
        do_encrypt = true;
    }
    else if (std::strcmp(argv[1], "decrypt") == 0)
    {
        do_decrypt = true;
    }
    else if (std::strcmp(argv[1], "-h") == 0 || std::strcmp(argv[1], "--help") == 0)
    {
        print_usage(argv[0]);
        return 0;
    }
    else
    {
        std::cerr << "Unknown command: " << argv[1] << "\n";
        print_usage(argv[0]);
        return 1;
    }

    // parse flags
    for (int i = 2; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "-k" || arg == "--key")
        {
            if (i + 1 < argc)
                key_hex = argv[++i];
            else
            {
                std::cerr << "Missing key value\n";
                return 1;
            }
        }
        else if (arg == "-i" || arg == "--iv")
        {
            if (i + 1 < argc)
                iv_hex = argv[++i];
            else
            {
                std::cerr << "Missing iv value\n";
                return 1;
            }
        }
        else if (arg == "-I" || arg == "--in")
        {
            if (i + 1 < argc)
                infile = argv[++i];
            else
            {
                std::cerr << "Missing input file\n";
                return 1;
            }
        }
        else if (arg == "-O" || arg == "--out")
        {
            if (i + 1 < argc)
                outfile = argv[++i];
            else
            {
                std::cerr << "Missing output file\n";
                return 1;
            }
        }
        else if (arg == "-h" || arg == "--help")
        {
            print_usage(argv[0]);
            return 0;
        }
        else
        {
            std::cerr << "Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    // prepare key and iv
    auto key_bytes = hex_to_bytes(key_hex);
    if (key_bytes.size() != 16)
        key_bytes.assign(16, 0);
    Key key;
    std::copy_n(key_bytes.begin(), 16, key.begin());

    auto iv_bytes = hex_to_bytes(iv_hex);
    if (iv_bytes.size() != 16)
        iv_bytes.assign(16, 0);
    Block iv;
    std::copy_n(iv_bytes.begin(), 16, iv.begin());

    // read input
    std::vector<Byte> buffer;
    if (!infile.empty())
    {
        std::ifstream in(infile, std::ios::binary);
        buffer.assign(std::istreambuf_iterator<char>(in), {});
    }
    else
    {
        buffer.assign(std::istreambuf_iterator<char>(std::cin), {});
    }

    // perform operation
    try
    {
        if (do_encrypt)
            BC::encryptCBC(buffer, key, iv);
        if (do_decrypt)
            BC::decryptCBC(buffer, key, iv);
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
        return 2;
    }

    if (!outfile.empty())
    {
        std::ofstream out(outfile, std::ios::binary);
        out.write(reinterpret_cast<const char *>(buffer.data()), buffer.size());
    }
    else
    {
        std::cout.write(reinterpret_cast<const char *>(buffer.data()), buffer.size());
    }

    return 0;
}