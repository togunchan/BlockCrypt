#ifndef BLOCKCRYPT_CONSTANTS_HPP
#define BLOCKCRYPT_CONSTANTS_HPP

#include <cstdint>

extern const uint8_t sBox[256];
extern const uint8_t invSBox[256];

extern const uint8_t rcon[11];

constexpr uint8_t BLOCK_SIZE = 16;
constexpr uint8_t KEY_SIZE = 16;

#endif // BLOCKCRYPT_CONSTANTS_HPP
