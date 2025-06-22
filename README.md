# BlockCrypt: AES-128 Encryption & Decryption in C++

> A modular, testable, educational C++ implementation of the AES-128 algorithm with CBC mode and PKCS#7 padding.

---

## Features

* AES-128 core encryption and decryption
* Round key generation (Key Expansion)
* ECB (single-block) mode
* CBC (multi-block) mode
* PKCS#7 padding/unpadding
* Modular architecture (Block, Key, Padding, CBC logic separated)
* Extensive unit tests with Catch2
* Debug output for learning (printBlock, printRoundKeys)

---

## 📁 Project Structure

```
BlockCrypt/
├── build/                # CMake build output (ignored in git)
├── constants/            # AES constants: S-boxes, Rcon values
│   ├── BlockCryptConstants.cpp
│   └── BlockCryptConstants.hpp
├── include/              # Header files
│   ├── blockcrypt.hpp
│   ├── CBC.hpp
│   └── padding.hpp
├── src/                  # Source files
│   ├── blockcrypt.cpp
│   ├── CBC.cpp
│   ├── padding.cpp
├── tests/                # Unit tests with Catch2
│   ├── CMakeLists.txt
│   └── test_blockcrypt.cpp
├── third_party/          # External libraries
├── .gitignore
├── CMakeLists.txt
├── LICENSE
├── main.cpp
└── README.md
```

---

## Build & Run (CMake)

### Prerequisites

* C++17 compatible compiler (e.g. g++, clang++)
* CMake 3.10 or newer

### Build Project

```bash
cmake -B build
cmake --build build
```

### Run Executable

```bash
./build/blockcrypt      # Or your CMake target name
```

### Run Tests

```bash
./build/tests           # Runs Catch2 unit tests
```

---

## Example Usage

```cpp
#include "blockcrypt.hpp"
#include "CBC.hpp"
#include "padding.hpp"

int main()
{
    BlockCrypt::Key key = { /* 16-byte key */ };
    BlockCrypt::Block iv = { /* 16-byte IV */ };
    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};

    BC::encryptCBC(data, key, iv);  // In-place encryption
    BC::decryptCBC(data, key, iv);  // In-place decryption

    std::string decrypted(data.begin(), data.end());
    std::cout << decrypted << std::endl;
}
```

---

## CBC Mode Explained

> CBC (Cipher Block Chaining) encrypts multiple blocks securely.

### Encryption Steps:

1. XOR plaintext block with previous ciphertext block (or IV for first)
2. Encrypt with AES
3. Output becomes the "previous" for the next block

### Decryption Steps:

1. AES decrypt the ciphertext block
2. XOR result with previous ciphertext block (or IV)

---

## Concepts & Internals

### 1. What is AES-128 and how is it implemented here?

AES-128 is a symmetric block cipher with:

* 128-bit block size (16 bytes)
* 128-bit key (16 bytes)
* 10 transformation rounds

Implemented here with readable, debug-friendly modular code.

---

### 2. Step-by-step: AES-128 Encryption Flow

| Round | Operations                                              |
| ----- | ------------------------------------------------------- |
| 0     | `AddRoundKey` (XOR with key)                            |
| 1–9   | `SubBytes` → `ShiftRows` → `MixColumns` → `AddRoundKey` |
| 10    | `SubBytes` → `ShiftRows` → `AddRoundKey`                |

---

### 3. What is Key Expansion?

* Generates 11 keys from the initial 128-bit input key
* Each round uses a different 16-byte key
* Uses `RotWord`, `SubWord`, and `Rcon[]`
* Stored in `roundKeys[0..10]`

---

### 4. What does each AES step do?

| Step        | Purpose                                        |
| ----------- | ---------------------------------------------- |
| SubBytes    | Byte substitution (non-linear confusion)       |
| ShiftRows   | Row-wise permutation (diffusion)               |
| MixColumns  | Column-wise matrix multiplication over GF(2^8) |
| AddRoundKey | XOR with round key                             |
| Inv\*       | Reverse of each above for decryption           |

---

### 5. Galois Field Multiplication in Practice

* AES math uses GF(2^8), not normal integers
* `gmul(a, b)` uses shift, XOR, and 0x1B reduction

```cpp
if (a & 0x80) a ^= 0x1B;
```

Ensures byte values stay inside the field.

---

### 6. How Are Blocks and Keys Managed?

```cpp
using Block = std::array<uint8_t, 16>;  // 16-byte data
using Key   = std::array<uint8_t, 16>;  // 16-byte key
```

Simple, fixed-size types improve safety and clarity.

---

### 7. How to Inspect Internal States?

Use `printBlock()` at any step:

```cpp
aes.printBlock(state, "After SubBytes");
```

Each block prints in a 4x4 matrix format.

---

### 8. How Are roundKeys Used?

* `roundKeys[0]`: Pre-round XOR
* `roundKeys[1..9]`: Main round transformations
* `roundKeys[10]`: Final round XOR

---

### 9. Educational Design Notes

* Clean code, no premature optimization
* No lookup tables for GF math
* Debug printing is integrated
* Padding and CBC clearly separated from core

---

## Testing Strategy

* ✅ Single encrypt-decrypt cycle (basic test)
* ✅ All-zero and all-0xFF edge cases
* ✅ Random 100x100 key/block fuzzing
* ✅ CBC mode round-trip
* ✅ PKCS#7 pad/unpad round-trip

Tested with Catch2 (see `test_blockcrypt.cpp`).

---

## 🔗 References

* [FIPS 197: AES Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
* [Wikipedia: AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
* [Crypto StackExchange](https://crypto.stackexchange.com)

---

## 🔖 License

MIT License. See [LICENSE](LICENSE).

---

## ✉️ Contact

Questions, feedback, ideas?
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Your_Profile-blue.svg)](https://www.linkedin.com/in/togunchan/)
