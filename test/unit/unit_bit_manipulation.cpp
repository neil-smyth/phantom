/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include <iostream>
#include <limits>
#include <memory>
#include "./lest.hpp"
#include "core/bit_manipulation.hpp"

namespace phantom {
using namespace core;  // NOLINT

const lest::test specification[] =
{
    CASE("log base 2 - 8-bit")
    {
        uint8_t p = 2;
        for (uint32_t i=1; i < 8; i++) {
            uint8_t l = bit_manipulation::log2(static_cast<uint8_t>(p));
            EXPECT(i == l);
            p <<= 1;
        }

        p = 1;
        for (uint32_t i=0; i < 8; i++) {
            uint8_t l = bit_manipulation::log2(static_cast<uint8_t>(p));
            EXPECT(i == l);
            p = (p << 1) + 1;
        }
    },
    CASE("log base 2 - 16-bit")
    {
        uint16_t p = 2;
        for (uint32_t i=1; i < 16; i++) {
            uint16_t l = bit_manipulation::log2(static_cast<uint16_t>(p));
            EXPECT(i == l);
            p <<= 1;
        }

        p = 1;
        for (uint32_t i=0; i < 16; i++) {
            uint16_t l = bit_manipulation::log2(static_cast<uint16_t>(p));
            EXPECT(i == l);
            p = (p << 1) + 1;
        }
    },
    CASE("log base 2 - 32-bit")
    {
        uint32_t p = 2;
        for (uint32_t i=1; i < 32; i++) {
            uint32_t l = bit_manipulation::log2(static_cast<uint32_t>(p));
            EXPECT(i == l);
            p <<= 1;
        }

        p = 1;
        for (uint32_t i=0; i < 32; i++) {
            uint32_t l = bit_manipulation::log2(static_cast<uint32_t>(p));
            EXPECT(i == l);
            p = (p << 1) + 1;
        }
    },
    CASE("log base 2 - 64-bit")
    {
        uint64_t p = 2;
        for (uint32_t i=1; i < 64; i++) {
            uint64_t l = bit_manipulation::log2(static_cast<uint64_t>(p));
            EXPECT(i == l);
            p <<= 1;
        }

        p = 1;
        for (uint32_t i=0; i < 64; i++) {
            uint64_t l = bit_manipulation::log2(static_cast<uint64_t>(p));
            EXPECT(i == l);
            p = (p << 1) + 1;
        }
    },
    CASE("log base 2 ceiling - 8-bit")
    {
        uint8_t p = 2;
        for (uint32_t i=1; i < 8; i++) {
            uint8_t l = bit_manipulation::log2_ceil(static_cast<uint8_t>(p));
            EXPECT(i == l);
            p <<= 1;
        }

        p = 3;
        for (uint32_t i=2; i < 8; i++) {
            uint8_t l = bit_manipulation::log2_ceil(static_cast<uint8_t>(p));
            EXPECT(i == l);
            p = ((p - 1) << 1) + 1;
        }

        {
            uint8_t l = bit_manipulation::log2_ceil(static_cast<uint8_t>(1));
            EXPECT(0 == l);
        }

        p = 3;
        for (uint32_t i=1; i < 8; i++) {
            uint8_t l = bit_manipulation::log2_ceil(static_cast<uint8_t>(p));
            EXPECT(i == (l - 1U));
            p = (p << 1) + 1;
        }
    },
    CASE("log base 2 ceiling - 16-bit")
    {
        uint16_t p = 2;
        for (uint32_t i=1; i < 16; i++) {
            uint16_t l = bit_manipulation::log2_ceil(static_cast<uint16_t>(p));
            EXPECT(i == l);
            p <<= 1;
        }

        p = 3;
        for (uint32_t i=2; i < 16; i++) {
            uint16_t l = bit_manipulation::log2_ceil(static_cast<uint16_t>(p));
            EXPECT(i == l);
            p = ((p - 1) << 1) + 1;
        }

        {
            uint16_t l = bit_manipulation::log2_ceil(static_cast<uint16_t>(1));
            EXPECT(0 == l);
        }

        p = 3;
        for (uint32_t i=1; i < 16; i++) {
            uint16_t l = bit_manipulation::log2_ceil(static_cast<uint16_t>(p));
            EXPECT(i == (l - 1U));
            p = (p << 1) + 1;
        }
    },
    CASE("log base 2 ceiling - 32-bit")
    {
        uint32_t p = 2;
        for (uint32_t i=1; i < 32; i++) {
            uint32_t l = bit_manipulation::log2_ceil(static_cast<uint32_t>(p));
            EXPECT(i == l);
            p <<= 1;
        }

        p = 3;
        for (uint32_t i=2; i < 32; i++) {
            uint32_t l = bit_manipulation::log2_ceil(static_cast<uint32_t>(p));
            EXPECT(i == l);
            p = ((p - 1) << 1) + 1;
        }

        {
            uint32_t l = bit_manipulation::log2_ceil(static_cast<uint32_t>(1));
            EXPECT(0U == l);
        }

        p = 3;
        for (uint32_t i=1; i < 32; i++) {
            uint32_t l = bit_manipulation::log2_ceil(static_cast<uint32_t>(p));
            EXPECT(i == (l - 1U));
            p = (p << 1) + 1;
        }
    },
    CASE("log base 2 ceiling - 64-bit")
    {
        uint64_t p = 2;
        for (uint32_t i=1; i < 64; i++) {
            uint64_t l = bit_manipulation::log2_ceil(static_cast<uint64_t>(p));
            EXPECT(i == l);
            p <<= 1;
        }

        p = 3;
        for (uint32_t i=2; i < 64; i++) {
            uint64_t l = bit_manipulation::log2_ceil(static_cast<uint64_t>(p));
            EXPECT(i == l);
            p = ((p - 1) << 1) + 1;
        }

        {
            uint64_t l = bit_manipulation::log2_ceil(static_cast<uint64_t>(1));
            EXPECT(0U == l);
        }

        p = 3;
        for (uint32_t i=1; i < 64; i++) {
            uint64_t l = bit_manipulation::log2_ceil(static_cast<uint64_t>(p));
            EXPECT(i == (l - 1U));
            p = (p << 1) + 1;
        }
    },
    CASE("Count leading zeros - 8-bit")
    {
        uint8_t p = 0;
        for (uint32_t i=0; i <= 8; i++) {
            uint8_t c = bit_manipulation::clz(static_cast<uint8_t>(p));
            EXPECT((8 - i) == c);
            p = 1 << i;
        }
    },
    CASE("Count leading zeros - 16-bit")
    {
        uint16_t p = 0;
        for (uint32_t i=0; i <= 16; i++) {
            uint16_t c = bit_manipulation::clz(static_cast<uint16_t>(p));
            EXPECT((16 - i) == c);
            p = 1 << i;
        }
    },
    CASE("Count leading zeros - 32-bit")
    {
        uint32_t p = 0;
        for (uint32_t i=0; i <= 32; i++) {
            uint32_t c = bit_manipulation::clz(static_cast<uint32_t>(p));
            EXPECT((32 - i) == c);
            p = 1 << i;
        }
    },
    CASE("Count leading zeros - 64-bit")
    {
        uint64_t p = 0;
        for (uint32_t i=0; i <= 64; i++) {
            uint64_t c = bit_manipulation::clz(static_cast<uint64_t>(p));
            EXPECT((64 - i) == c);
            p = 1ULL << i;
        }
    },
    CASE("Count trailing zeros - 8-bit")
    {
        uint8_t p = 0x01;
        for (uint32_t i=0; i <= 8; i++) {
            uint8_t c = bit_manipulation::ctz(static_cast<uint8_t>(p));
            EXPECT(i == c);
            p = p << 1;
        }
    },
    CASE("Count trailing zeros - 16-bit")
    {
        uint16_t p = 0x0001;
        for (uint32_t i=0; i <= 16; i++) {
            uint16_t c = bit_manipulation::ctz(static_cast<uint16_t>(p));
            EXPECT(i == c);
            p = p << 1;
        }
    },
    CASE("Count trailing zeros - 32-bit")
    {
        uint32_t p = 0x00000001;
        for (uint32_t i=0; i <= 32; i++) {
            uint32_t c = bit_manipulation::ctz(static_cast<uint32_t>(p));
            EXPECT(i == c);
            p = p << 1;
        }
    },
    CASE("Count trailing zeros - 64-bit")
    {
        uint64_t p = 0x0000000000000001;
        for (uint32_t i=0; i <= 64; i++) {
            uint64_t c = bit_manipulation::ctz(static_cast<uint64_t>(p));
            EXPECT(i == c);
            p = p << 1ULL;
        }
    },
    CASE("Bit reversal - 8-bit")
    {
        uint8_t r;
        r = bit_manipulation::reverse(static_cast<uint8_t>(0x00));
        EXPECT(0x00 == r);
        r = bit_manipulation::reverse(static_cast<uint8_t>(0x01));
        EXPECT(0x80 == r);
        r = bit_manipulation::reverse(static_cast<uint8_t>(0x55));
        EXPECT(0xaa == r);
        r = bit_manipulation::reverse(static_cast<uint8_t>(0x81));
        EXPECT(0x81 == r);
        r = bit_manipulation::reverse(static_cast<uint8_t>(0x18));
        EXPECT(0x18 == r);
        r = bit_manipulation::reverse(static_cast<uint8_t>(0xaa));
        EXPECT(0x55 == r);
        r = bit_manipulation::reverse(static_cast<uint8_t>(0x80));
        EXPECT(0x01 == r);
        r = bit_manipulation::reverse(static_cast<uint8_t>(0xff));
        EXPECT(0xff == r);
    },
    CASE("Bit reversal - 16-bit")
    {
        uint16_t r;
        r = bit_manipulation::reverse(static_cast<uint16_t>(0x0000));
        EXPECT(0x0000 == r);
        r = bit_manipulation::reverse(static_cast<uint16_t>(0x0001));
        EXPECT(0x8000 == r);
        r = bit_manipulation::reverse(static_cast<uint16_t>(0x5555));
        EXPECT(0xaaaa == r);
        r = bit_manipulation::reverse(static_cast<uint16_t>(0x8001));
        EXPECT(0x8001 == r);
        r = bit_manipulation::reverse(static_cast<uint16_t>(0x1008));
        EXPECT(0x1008 == r);
        r = bit_manipulation::reverse(static_cast<uint16_t>(0xaaaa));
        EXPECT(0x5555 == r);
        r = bit_manipulation::reverse(static_cast<uint16_t>(0x8000));
        EXPECT(0x0001 == r);
        r = bit_manipulation::reverse(static_cast<uint16_t>(0xffff));
        EXPECT(0xffff == r);
    },
    CASE("Bit reversal - 32-bit")
    {
        uint32_t r;
        r = bit_manipulation::reverse(static_cast<uint32_t>(0x00000000));
        EXPECT(0x00000000UL == r);
        r = bit_manipulation::reverse(static_cast<uint32_t>(0x00000001));
        EXPECT(0x80000000UL == r);
        r = bit_manipulation::reverse(static_cast<uint32_t>(0x55555555));
        EXPECT(0xaaaaaaaaUL == r);
        r = bit_manipulation::reverse(static_cast<uint32_t>(0x80000001));
        EXPECT(0x80000001UL == r);
        r = bit_manipulation::reverse(static_cast<uint32_t>(0x10000008));
        EXPECT(0x10000008UL == r);
        r = bit_manipulation::reverse(static_cast<uint32_t>(0xaaaaaaaa));
        EXPECT(0x55555555UL == r);
        r = bit_manipulation::reverse(static_cast<uint32_t>(0x80000000));
        EXPECT(0x00000001UL == r);
        r = bit_manipulation::reverse(static_cast<uint32_t>(0xffffffff));
        EXPECT(0xffffffffUL == r);
    },
    CASE("Bit reversal - 64-bit")
    {
        uint64_t r;
        r = bit_manipulation::reverse(static_cast<uint64_t>(0x0000000000000000));
        EXPECT(0x0000000000000000ULL == r);
        r = bit_manipulation::reverse(static_cast<uint64_t>(0x0000000000000001));
        EXPECT(0x8000000000000000ULL == r);
        r = bit_manipulation::reverse(static_cast<uint64_t>(0x5555555555555555));
        EXPECT(0xaaaaaaaaaaaaaaaaULL == r);
        r = bit_manipulation::reverse(static_cast<uint64_t>(0x8000000000000001));
        EXPECT(0x8000000000000001ULL == r);
        r = bit_manipulation::reverse(static_cast<uint64_t>(0x1000000000000008));
        EXPECT(0x1000000000000008ULL == r);
        r = bit_manipulation::reverse(static_cast<uint64_t>(0xaaaaaaaaaaaaaaaa));
        EXPECT(0x5555555555555555ULL == r);
        r = bit_manipulation::reverse(static_cast<uint64_t>(0x8000000000000000));
        EXPECT(0x0000000000000001ULL == r);
        r = bit_manipulation::reverse(static_cast<uint64_t>(0xffffffffffffffff));
        EXPECT(0xffffffffffffffffULL == r);
    },
    CASE("Rotate left - 8-bit")
    {
        uint8_t r;
        r = bit_manipulation::rotl(uint8_t(0x00), size_t(0));
        EXPECT(0x00 == r);
        r = bit_manipulation::rotl(uint8_t(0x00), size_t(1));
        EXPECT(0x00 == r);
        r = bit_manipulation::rotl(uint8_t(0x01), size_t(1));
        EXPECT(0x02 == r);
        r = bit_manipulation::rotl(uint8_t(0x10), size_t(7));
        EXPECT(0x08 == r);
        r = bit_manipulation::rotl(uint8_t(0x01), size_t(8));
        EXPECT(0x01 == r);
        r = bit_manipulation::rotl(uint8_t(0x40), size_t(129));
        EXPECT(0x80 == r);
    },
    CASE("Rotate left - 16-bit")
    {
        uint16_t r;
        r = bit_manipulation::rotl(uint16_t(0x0000), size_t(0));
        EXPECT(0x0000 == r);
        r = bit_manipulation::rotl(uint16_t(0x0000), size_t(1));
        EXPECT(0x0000 == r);
        r = bit_manipulation::rotl(uint16_t(0x0001), size_t(1));
        EXPECT(0x0002 == r);
        r = bit_manipulation::rotl(uint16_t(0x1000), size_t(15));
        EXPECT(0x0800 == r);
        r = bit_manipulation::rotl(uint16_t(0x0001), size_t(16));
        EXPECT(0x0001 == r);
        r = bit_manipulation::rotl(uint16_t(0x4000), size_t(129));
        EXPECT(0x8000 == r);
    },
    CASE("Rotate left - 32-bit")
    {
        uint32_t r;
        r = bit_manipulation::rotl(uint32_t(0x00000000), size_t(0));
        EXPECT(0x00000000UL == r);
        r = bit_manipulation::rotl(uint32_t(0x00000000), size_t(1));
        EXPECT(0x00000000UL == r);
        r = bit_manipulation::rotl(uint32_t(0x00000001), size_t(1));
        EXPECT(0x00000002UL == r);
        r = bit_manipulation::rotl(uint32_t(0x10000000), size_t(31));
        EXPECT(0x08000000UL == r);
        r = bit_manipulation::rotl(uint32_t(0x00000001), size_t(32));
        EXPECT(0x00000001UL == r);
        r = bit_manipulation::rotl(uint32_t(0x40000000), size_t(129));
        EXPECT(0x80000000UL == r);
    },
    CASE("Rotate left - 64-bit")
    {
        uint64_t r;
        r = bit_manipulation::rotl(uint64_t(0x0000000000000000), size_t(0));
        EXPECT(0x0000000000000000ULL == r);
        r = bit_manipulation::rotl(uint64_t(0x0000000000000000), size_t(1));
        EXPECT(0x0000000000000000ULL == r);
        r = bit_manipulation::rotl(uint64_t(0x0000000000000001), size_t(1));
        EXPECT(0x0000000000000002ULL == r);
        r = bit_manipulation::rotl(uint64_t(0x1000000000000000), size_t(63));
        EXPECT(0x0800000000000000ULL == r);
        r = bit_manipulation::rotl(uint64_t(0x0000000000000001), size_t(64));
        EXPECT(0x0000000000000001ULL == r);
        r = bit_manipulation::rotl(uint64_t(0x4000000000000000), size_t(129));
        EXPECT(0x8000000000000000ULL == r);
    },
    CASE("Square root - 8-bit")
    {
        uint8_t r;
        r = bit_manipulation::sqrt(uint8_t(0x00));
        EXPECT(0 == r);
        r = bit_manipulation::sqrt(uint8_t(0x01));
        EXPECT(1 == r);
        r = bit_manipulation::sqrt(uint8_t(0x04));
        EXPECT(2 == r);
        r = bit_manipulation::sqrt(uint8_t(0x0f));
        EXPECT(3 == r);
        r = bit_manipulation::sqrt(uint8_t(0x20));
        EXPECT(5 == r);
        r = bit_manipulation::sqrt(uint8_t(0xff));
        EXPECT(0xf == r);
    },
    CASE("Square root - 16-bit")
    {
        uint16_t r;
        r = bit_manipulation::sqrt(uint16_t(0x0000));
        EXPECT(0 == r);
        r = bit_manipulation::sqrt(uint16_t(0x0001));
        EXPECT(1 == r);
        r = bit_manipulation::sqrt(uint16_t(0x0004));
        EXPECT(2 == r);
        r = bit_manipulation::sqrt(uint16_t(0x000f));
        EXPECT(3 == r);
        r = bit_manipulation::sqrt(uint16_t(0x2000));
        EXPECT(0x5a == r);
        r = bit_manipulation::sqrt(uint16_t(0xffff));
        EXPECT(0xff == r);
    },
    CASE("Square root - 32-bit")
    {
        uint32_t r;
        r = bit_manipulation::sqrt(uint32_t(0x00000000));
        EXPECT(0U == r);
        r = bit_manipulation::sqrt(uint32_t(0x00000001));
        EXPECT(1U == r);
        r = bit_manipulation::sqrt(uint32_t(0x00000004));
        EXPECT(2U == r);
        r = bit_manipulation::sqrt(uint32_t(0x0000000f));
        EXPECT(3U == r);
        r = bit_manipulation::sqrt(uint32_t(0x20000000));
        EXPECT(0x5a82U == r);
        r = bit_manipulation::sqrt(uint32_t(0xffffffff));
        EXPECT(0xffffU == r);
    },
    CASE("Square root - 64-bit")
    {
        uint64_t r;
        r = bit_manipulation::sqrt(uint64_t(0x0000000000000000));
        EXPECT(0U == r);
        r = bit_manipulation::sqrt(uint64_t(0x0000000000000001));
        EXPECT(1U == r);
        r = bit_manipulation::sqrt(uint64_t(0x0000000000000004));
        EXPECT(2U == r);
        r = bit_manipulation::sqrt(uint64_t(0x000000000000000f));
        EXPECT(3U == r);
        r = bit_manipulation::sqrt(uint64_t(0x2000000000000000));
        EXPECT(0x5a827999ULL == r);
        r = bit_manipulation::sqrt(uint64_t(0xffffffffffffffff));
        EXPECT(0xffffffffULL == r);
    },
    CASE("Square root - double")
    {
        double r;
        r = bit_manipulation::sqrt(static_cast<double>(0.0f));
        EXPECT(0 == r);
        r = bit_manipulation::sqrt(static_cast<double>(1.0));
        EXPECT(0 >= floor(r));
        EXPECT(1 <= std::round(r));
        r = bit_manipulation::sqrt(static_cast<double>(4.0));
        EXPECT(1 >= floor(r));
        EXPECT(2 <= std::round(r));
        r = bit_manipulation::sqrt(static_cast<double>(15.0));
        EXPECT(3 >= floor(r));
        EXPECT(4 <= std::round(r));
        r = bit_manipulation::sqrt(static_cast<double>(0x2000000000000000));
        EXPECT(0x5a827999 >= floor(r));
        EXPECT(std::round(r) <= (0x5a82799A + (0x5a827999/10000)));
        r = bit_manipulation::sqrt(static_cast<double>(0xffffffffffffffff));
        EXPECT(0xffffffff >= floor(r));
        EXPECT(std::round(r) <= (0x100000000ULL + (0xffffffffULL/10000)));
    },
    CASE("Square root - float")
    {
        float r;
        r = bit_manipulation::sqrt(static_cast<float>(0.0f));
        EXPECT(0 == r);
        r = bit_manipulation::sqrt(static_cast<float>(1.0));
        EXPECT(0 >= floor(r));
        EXPECT(1 <= std::round(r));
        r = bit_manipulation::sqrt(static_cast<float>(4.0));
        EXPECT(1 >= floor(r));
        EXPECT(2 <= std::round(r));
        r = bit_manipulation::sqrt(static_cast<float>(15.0));
        EXPECT(3 >= floor(r));
        EXPECT(4 <= std::round(r));
        r = bit_manipulation::sqrt(static_cast<float>(0x20000000));
        EXPECT(0x5a82 >= floor(r));
        EXPECT(std::round(r) <= (0x5a82 + (0x5a82/10000)));
        r = bit_manipulation::sqrt(static_cast<float>(0xffffffff));
        EXPECT(0xffff >= floor(r));
        EXPECT(std::round(r) <= (0x10000ULL + (0xffffULL/10000)));
    },
    CASE("Inverse square root - double")
    {
        double r;
        r = bit_manipulation::inv_sqrt(static_cast<double>(1.0f));
        EXPECT(0 >= floor(r));
        EXPECT(1 <= std::round(r));
        r = bit_manipulation::inv_sqrt(static_cast<double>(4.0f));
        EXPECT(0.499 <= r);
        EXPECT(0.501 >= r);
        r = bit_manipulation::inv_sqrt(-static_cast<double>(4.0f));
        EXPECT(std::isinf(r));
        EXPECT(r == -std::numeric_limits<double>::infinity());
        r = bit_manipulation::inv_sqrt(std::numeric_limits<double>::max());
        EXPECT(0.0 <= r);
        EXPECT(0.0000001 >= r);
        r = bit_manipulation::inv_sqrt(std::numeric_limits<double>::min());
        EXPECT(0.0 <= r);
        EXPECT(1.0e154 >= r);
        r = bit_manipulation::inv_sqrt(static_cast<double>(1.0e-32));
        EXPECT(0.99e16 <= r);
        EXPECT(1.01e16 >= r);
        r = bit_manipulation::inv_sqrt(static_cast<double>(1.0e32));
        EXPECT(0.99e-16 <= r);
        EXPECT(1.01e-16 >= r);
    },
    CASE("Inverse square root - float")
    {
        float r;
        r = bit_manipulation::inv_sqrt(static_cast<float>(1.0f));
        EXPECT(0 >= floor(r));
        EXPECT(1 <= std::round(r));
        r = bit_manipulation::inv_sqrt(static_cast<float>(4.0f));
        EXPECT(0.499 <= r);
        EXPECT(0.501 >= r);
        r = bit_manipulation::inv_sqrt(-static_cast<float>(4.0f));
        EXPECT(std::isinf(r));
        EXPECT(r == -std::numeric_limits<float>::infinity());
        r = bit_manipulation::inv_sqrt(std::numeric_limits<float>::max());
        EXPECT(0.0 <= r);
        EXPECT(0.0000001 >= r);
        r = bit_manipulation::inv_sqrt(std::numeric_limits<float>::min());
        EXPECT(0.0 <= r);
        EXPECT(1.0e20 >= r);
        r = bit_manipulation::inv_sqrt(static_cast<float>(1.0e-16));
        EXPECT(0.99e8 <= r);
        EXPECT(1.01e8 >= r);
        r = bit_manipulation::inv_sqrt(static_cast<float>(1.0e16));
        EXPECT(0.99e-8 <= r);
        EXPECT(1.01e-8 >= r);
    }
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

