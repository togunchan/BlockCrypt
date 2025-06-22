#pragma once

#include <cstdint>
#include <vector>

namespace BCPad
{
    /**
     * @brief Adds PKCS#7 padding to the given byte buffer.
     *
     * This function calculates how many padding bytes are required to reach
     * the next multiple of the specified block size and appends those bytes
     * to the buffer. Each padding byte has the same value as the padding length.
     *
     * Example:
     * - If the block size is 16 and the buffer has 13 bytes,
     *   3 bytes of `0x03` will be appended.
     * - If the buffer is already aligned (e.g., 16 bytes), a full block of
     *   16 padding bytes (`0x10`) is added.
     *
     * @param buf The buffer to pad (passed by reference).
     * @param blk The block size for padding. Default is 16.
     */
    void addPKCS7(std::vector<uint8_t> &buf, std::size_t blk = 16);

    /**
     * @brief Removes PKCS#7 padding from the given byte buffer.
     *
     * This function reads the last byte of the buffer to determine
     * the padding length, verifies the correctness of the padding bytes,
     * and removes them. Throws if the buffer is empty, the padding length
     * is invalid, or the padding bytes are inconsistent.
     *
     * Example:
     * - If the buffer ends with `0x03 0x03 0x03`, 3 bytes are removed.
     *
     * @param buf The buffer to unpad (passed by reference).
     * @param blk The block size used during padding. Default is 16.
     * @throws std::runtime_error if the padding is invalid or corrupt.
     */
    void removePKCS7(std::vector<uint8_t> &buf, std::size_t blk = 16);

} // namespace BCPad
