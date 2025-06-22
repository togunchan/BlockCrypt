#include "../include/padding.hpp"
#include <stdexcept>

namespace BCPad // BlockCrypt Padding
{
    void addPKCS7(std::vector<uint8_t> &buf, std::size_t blk)
    {
        std::size_t missing = blk - (buf.size() % blk);
        if (missing == 0)
            missing = blk;

        for (std::size_t i = 0; i < missing; i++)
        {
            buf.push_back(static_cast<uint8_t>(missing));
        };
    }

    void removePKCS7(std::vector<uint8_t> &buf, std::size_t blk)
    {
        if (buf.empty())
            throw std::runtime_error("Tried to remove PCKS7 padding from an Empty Buffer");

        uint8_t pad = buf.back();
        if (pad == 0 || pad > blk)
            throw std::runtime_error("Error while removing padding. Padding corrupt");

        for (std::size_t i = 0; i < pad; i++)
        {
            if (buf[buf.size() - i - 1] != pad)
                throw std::runtime_error("Error while removing padding. Padding corrupt");
        }
        buf.resize(buf.size() - pad);
    }
} // namespace BCPad
