# BlockCrypt: AES-128 Encryption & Decryption in C++

> A modular, testable, educational C++ implementation of AES-128 with CBC mode, PKCS#7 padding, and a command‑line tool.

---

## Features

- AES‑128 core encryption and decryption
- Round key generation (Key Expansion)
- ECB (single-block) mode & NIST AES‑128 ECB vectors
- CBC (multi-block) mode & NIST SP800‑38A CBC vectors
- PKCS#7 padding/unpadding
- Command‑line interface (`blockcrypt`) with `encrypt`/`decrypt` subcommands
- Manual `argc/argv` parsing, detailed usage help
- Modular architecture (Block, Key, Padding, CBC logic separated)
- Extensive unit tests with Catch2 (fuzz, edge cases, vectors)
- Educational debug output (printBlock, printRoundKeys)

---

## 📁 Project Structure

```
BlockCrypt/
├── build/                # CMake build output (ignored in git)
├── constants/            # AES constants: S-boxes, Rcon values
│   ├── BlockCryptConstants.cpp
│   └── BlockCryptConstants.hpp
├── include/              # Public headers
│   ├── blockcrypt.hpp
│   ├── CBC.hpp
│   └── padding.hpp
├── src/                  # Implementation files
│   ├── blockcrypt.cpp
│   ├── CBC.cpp
│   ├── padding.cpp
├── tests/                # Unit tests (Catch2)
│   ├── CMakeLists.txt
│   ├── test_blockcrypt.cpp
│   └── test_nist_cbc.cpp
├── third_party/          # External libraries (Catch2)
├── .gitignore
├── main.cpp              # Command‑line tool entry point
├── CMakeLists.txt
├── LICENSE
└── README.md
```

---

## Build & Run (CMake)

### Prerequisites

- C++17 compiler (e.g. g++, clang++)
- CMake 3.10 or newer

### Build Project

```bash
cmake -S . -B build
cmake --build build
```

### Run Tests

```bash
cd build
ctest --output-on-failure
```

### Command‑Line Tool

- **`blockcrypt`** is the executable for file encryption/decryption.

```bash
# Show usage/help
./build/blockcrypt --help

# Encrypt a file (AES‑CBC + PKCS#7)
./build/blockcrypt encrypt \
  -k 2b7e151628aed2a6abf7158809cf4f3c \
  -i 000102030405060708090A0B0C0D0E0F \
  -I plaintext.bin \
  -O ciphertext.bin

# Decrypt back
./build/blockcrypt decrypt \
  -k 2b7e151628aed2a6abf7158809cf4f3c \
  -i 000102030405060708090A0B0C0D0E0F \
  -I ciphertext.bin \
  -O decrypted.bin
``` 

By default, streams are used when `-I` or `-O` are omitted (stdin/stdout).

---

## Library Usage Example

```cpp
#include "blockcrypt.hpp"
#include "CBC.hpp"
#include "padding.hpp"

int main() {
    // Prepare key and IV
    BlockCrypt::Key key   = { /* 16‑byte key */ };
    BlockCrypt::Block iv  = { /* 16‑byte IV */ };

    // Sample plaintext bytes
    std::vector<uint8_t> data = { 'H','e','l','l','o' };

    // Encrypt in-place
    BC::encryptCBC(data, key, iv);

    // Decrypt back
    BC::decryptCBC(data, key, iv);

    std::string result(data.begin(), data.end());
    std::cout << result << std::endl;  // prints "Hello"
}
```

---

## AES‑128 Internals

### Encryption Flow

| Round | Operations                                               |
| ----- | -------------------------------------------------------- |
| 0     | AddRoundKey                                              |
| 1–9   | SubBytes → ShiftRows → MixColumns → AddRoundKey          |
| 10    | SubBytes → ShiftRows → AddRoundKey                       |

### Key Expansion

- Derive 11 round keys (16 bytes each) from the initial key
- Uses RotWord, SubWord (S‑Box), and Rcon constants

### Galois Field Multiplication

```cpp
uint8_t gmul(uint8_t a, uint8_t b) {
    // Multiply in GF(2^8) with polynomial 0x1B
}
```

---

## Testing Strategy

- ✅ Single-block encryption/decryption round-trip
- ✅ Edge cases: all-zero, all-0xFF keys/blocks
- ✅ Randomized fuzz (100×100 iterations)
- ✅ NIST AES‑128 ECB test vectors
- ✅ PKCS#7 padding/unpadding round-trip
- ✅ NIST AES‑128 CBC test vectors

Tests are implemented with Catch2 and run via CTest.

---

## References

- [FIPS 197: AES Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [NIST SP 800‑38A: CBC Test Vectors](https://csrc.nist.gov/publications/detail/sp/800-38a/final)
- [AES on Wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Contact

Questions, feedback, ideas?

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Your_Profile-blue.svg)](https://www.linkedin.com/in/togunchan/)
