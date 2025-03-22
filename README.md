# AES-128 Encryption/Decryption Implementation

A C++ implementation of the AES-128 (Advanced Encryption Standard) algorithm for encrypting and decrypting 128-bit data blocks. This project covers all AES operations, including key expansion, substitution, shifting rows, mixing columns, and adding round keys.

## Features
- **Key Expansion**: Generates 11 round keys from a 128-bit cipher key
- **Encryption**:
  - `SubBytes`: Non-linear byte substitution using S-Box
  - `ShiftRows`: Cyclic shifting of rows in the state matrix
  - `MixColumns`: Column mixing using Galois Field multiplication
  - `AddRoundKey`: XOR with the round key
- **Decryption**:
  - `InvSubBytes`: Inverse substitution using inverse S-Box
  - `InvShiftRows`: Reverse row shifting
  - `InvMixColumns`: Inverse column mixing
- **Galois Field Multiplication**: Optimized for AES operations
- **Debug Utilities**: Print round keys and block states for analysis

## Prerequisites
- C++ compiler (e.g., `g++`)
- Basic understanding of AES concepts

## Installation & Usage
1. **Clone the repository**:
```bash
git clone https://github.com/togunchan/BlockCrypt.git
cd BlockCrypt
```
2. **Compile (example with g++):**
```bash
g++ -std=c++17 main.cpp BlockCrypt.cpp BlockCryptConstants.cpp -o output
```

3. **Run:**
```bash
./aes
```

## Example Code
```cpp
#include "blockcrypt.hpp"
#include <iostream>

int main() {
    // Example key and plaintext (hex values)
    BlockCrypt::Key key = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x97, 0x99, 0x89, 0xcf, 0xab, 0x12
    };

    BlockCrypt::Block plaintext = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };

    BlockCrypt aes(key);
    
    // Encrypt
    aes.encrypt(plaintext);
    std::cout << "Encrypted Block:" << std::endl;
    aes.printBlock(plaintext, "Encrypted");

    // Decrypt
    aes.decrypt(plaintext);
    std::cout << "Decrypted Block:" << std::endl;
    aes.printBlock(plaintext, "Decrypted");

    return 0;
}
```

## Testing
Tested with custom test vectors. Use the `printRoundKeys()` and `printBlock()` functions to debug intermediate steps and validate the encryption/decryption process.

## References
References
- [FIPS 197: AES Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
- [AES: The Advanced Encryption Standard](https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf)

## License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Notes
- **Educational Purpose**: This implementation is for learning and educational purposes and is not optimized for production environments.
- **Extensions**: Can be extended to support AES-192/256 or other modes (e.g., CBC, CTR).

## Contact
Q#uestions? Reach out:  
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Your_Profile-blue.svg)](https://www.linkedin.com/in/togunchan/)
