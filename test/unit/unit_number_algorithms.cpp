/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include <iostream>
#include <memory>
#include "./lest.hpp"
#include "core/number.hpp"

namespace phantom {
using namespace core;  // NOLINT

const lest::test specification[] =
{
    CASE("Euclidean algorithm - 8-bit")
    {
        uint8_t q;
        q = number<uint8_t>::ugcd(uint8_t(0x01), uint8_t(0x01));
        EXPECT(q == 0x01);
        q = number<uint8_t>::ugcd(uint8_t(0x04), uint8_t(0x08));
        EXPECT(q == 0x04);
        q = number<uint8_t>::ugcd(uint8_t(0x10), uint8_t(0x04));
        EXPECT(q == 0x04);
        q = number<uint8_t>::ugcd(uint8_t(0x80), uint8_t(0xc0));
        EXPECT(q == 0x40);
    },
    CASE("Euclidean algorithm - 16-bit")
    {
        uint16_t q;
        q = number<uint16_t>::ugcd(uint16_t(0x0001), uint16_t(0x0001));
        EXPECT(q == 0x0001);
        q = number<uint16_t>::ugcd(uint16_t(0x0004), uint16_t(0x0008));
        EXPECT(q == 0x0004);
        q = number<uint16_t>::ugcd(uint16_t(0x1000), uint16_t(0x0400));
        EXPECT(q == 0x0400);
        q = number<uint16_t>::ugcd(uint16_t(0x8000), uint16_t(0xc000));
        EXPECT(q == 0x4000);
    },
    CASE("Euclidean algorithm - 32-bit")
    {
        uint32_t q;
        q = number<uint32_t>::ugcd(uint32_t(0x00000001), uint32_t(0x00000001));
        EXPECT(q == 0x00000001);
        q = number<uint32_t>::ugcd(uint32_t(0x00000004), uint32_t(0x00000008));
        EXPECT(q == 0x00000004);
        q = number<uint32_t>::ugcd(uint32_t(0x10000000), uint32_t(0x04000000));
        EXPECT(q == 0x04000000);
        q = number<uint32_t>::ugcd(uint32_t(0x80000000), uint32_t(0xc0000000));
        EXPECT(q == 0x40000000);
    },
    CASE("Euclidean algorithm - 64-bit")
    {
        uint64_t q;
        q = number<uint64_t>::ugcd(uint64_t(0x0000000000000001), uint64_t(0x0000000000000001));
        EXPECT(q == 0x0000000000000001);
        q = number<uint64_t>::ugcd(uint64_t(0x0000000000000004), uint64_t(0x0000000000000008));
        EXPECT(q == 0x0000000000000004);
        q = number<uint64_t>::ugcd(uint64_t(0x1000000000000000), uint64_t(0x0400000000000000));
        EXPECT(q == 0x0400000000000000);
        q = number<uint64_t>::ugcd(uint64_t(0x8000000000000000), uint64_t(0xc000000000000000));
        EXPECT(q == 0x4000000000000000);
    },
    CASE("Extended Euclidean algorithm - 8-bit")
    {
        uint8_t q, x, y;
        q = number<uint8_t>::uxgcd(uint8_t(0x01), uint8_t(0x01), &x, &y);
        EXPECT(q == 0x01);
        EXPECT(uint8_t(uint8_t(0x01) * x + uint8_t(0x01) * y) == q);
        q = number<uint8_t>::uxgcd(uint8_t(0x04), uint8_t(0x08), &x, &y);
        EXPECT(q == 0x04);
        EXPECT(uint8_t(uint8_t(0x04) * x + uint8_t(0x08) * y) == q);
        q = number<uint8_t>::uxgcd(uint8_t(0x10), uint8_t(0x04), &x, &y);
        EXPECT(q == 0x04);
        EXPECT(uint8_t(uint8_t(0x10) * x + uint8_t(0x04) * y) == q);
        q = number<uint8_t>::uxgcd(uint8_t(0x80), uint8_t(0xc0), &x, &y);
        EXPECT(q == 0x40);
        EXPECT(uint8_t(uint8_t(0x80) * x + uint8_t(0xc0) * y) == q);
    },
    CASE("Extended Euclidean algorithm - 16-bit")
    {
        uint16_t q, x, y;
        q = number<uint16_t>::uxgcd(uint16_t(0x0001), uint16_t(0x0001), &x, &y);
        EXPECT(q == 0x0001);
        EXPECT(uint16_t(uint16_t(0x0001) * x + uint16_t(0x0001) * y) == q);
        q = number<uint16_t>::uxgcd(uint16_t(0x0004), uint16_t(0x0008), &x, &y);
        EXPECT(q == 0x0004);
        EXPECT(uint16_t(uint16_t(0x0004) * x + uint16_t(0x0008) * y) == q);
        q = number<uint16_t>::uxgcd(uint16_t(0x1000), uint16_t(0x0400), &x, &y);
        EXPECT(q == 0x0400);
        EXPECT(uint16_t(uint16_t(0x1000) * x + uint16_t(0x0400) * y) == q);
        q = number<uint16_t>::uxgcd(uint16_t(0x8000), uint16_t(0xc000), &x, &y);
        EXPECT(q == 0x4000);
        EXPECT(uint16_t(uint16_t(0x8000) * x + uint16_t(0xc000) * y) == q);
    },
    CASE("Extended Euclidean algorithm - 32-bit")
    {
        uint32_t q, x, y;
        q = number<uint32_t>::uxgcd(uint32_t(0x00000001), uint32_t(0x00000001), &x, &y);
        EXPECT(q == 0x00000001);
        EXPECT(uint32_t(uint32_t(0x00000001) * x + uint32_t(0x00000001) * y) == q);
        q = number<uint32_t>::uxgcd(uint32_t(0x00000004), uint32_t(0x00000008), &x, &y);
        EXPECT(q == 0x00000004);
        EXPECT(uint32_t(uint32_t(0x00000004) * x + uint32_t(0x00000008) * y) == q);
        q = number<uint32_t>::uxgcd(uint32_t(0x10000000), uint32_t(0x04000000), &x, &y);
        EXPECT(q == 0x04000000);
        EXPECT(uint32_t(uint32_t(0x10000000) * x + uint32_t(0x04000000) * y) == q);
        q = number<uint32_t>::uxgcd(uint32_t(0x80000000), uint32_t(0xc0000000), &x, &y);
        EXPECT(q == 0x40000000);
        EXPECT(uint32_t(uint32_t(0x80000000) * x + uint32_t(0xc0000000) * y) == q);
    },
    CASE("Extended Euclidean algorithm - 64-bit")
    {
        uint64_t q, x, y;
        q = number<uint64_t>::uxgcd(uint64_t(0x0000000000000001), uint64_t(0x0000000000000001), &x, &y);
        EXPECT(q == 0x0000000000000001);
        EXPECT(uint64_t(uint64_t(0x0000000000000001) * x + uint64_t(0x0000000000000001) * y) == q);
        q = number<uint64_t>::uxgcd(uint64_t(0x0000000000000004), uint64_t(0x0000000000000008), &x, &y);
        EXPECT(q == 0x0000000000000004);
        EXPECT(uint64_t(uint64_t(0x0000000000000004) * x + uint64_t(0x0000000000000008) * y) == q);
        q = number<uint64_t>::uxgcd(uint64_t(0x1000000000000000), uint64_t(0x0400000000000000), &x, &y);
        EXPECT(q == 0x0400000000000000);
        EXPECT(uint64_t(uint64_t(0x1000000000000000) * x + uint64_t(0x0400000000000000) * y) == q);
        q = number<uint64_t>::uxgcd(uint64_t(0x8000000000000000), uint64_t(0xc000000000000000), &x, &y);
        EXPECT(q == 0x4000000000000000);
        EXPECT(uint64_t(uint64_t(0x8000000000000000) * x + uint64_t(0xc000000000000000) * y) == q);
    },
    CASE("Binary Extended GCD algorithm - 8-bit")
    {
        int errcode;
        uint8_t u, v;
        errcode = number<uint8_t>::ubinxgcd(uint8_t(0x01), uint8_t(0x01), &u, &v);
        EXPECT(errcode == -1);
        errcode = number<uint8_t>::ubinxgcd(uint8_t(0x04), uint8_t(0x08), &u, &v);
        EXPECT(errcode == -2);
        errcode = number<uint8_t>::ubinxgcd(uint8_t(0x10), uint8_t(0x05), &u, &v);
        EXPECT(errcode == 0);
        EXPECT(uint8_t(2 * uint8_t(0x10) * u - uint8_t(0x05) * v) == 1);
    },
    CASE("Binary Extended GCD algorithm - 16-bit")
    {
        int errcode;
        uint16_t u, v;
        errcode = number<uint16_t>::ubinxgcd(uint16_t(0x0001), uint16_t(0x0001), &u, &v);
        EXPECT(errcode == -1);
        errcode = number<uint16_t>::ubinxgcd(uint16_t(0x0004), uint16_t(0x0008), &u, &v);
        EXPECT(errcode == -2);
        errcode = number<uint16_t>::ubinxgcd(uint16_t(0x1000), uint16_t(0x0005), &u, &v);
        EXPECT(errcode == 0);
        EXPECT(uint16_t(2 * uint16_t(0x1000) * u - uint16_t(0x0005) * v) == 1);
    },
    CASE("Binary Extended GCD algorithm - 32-bit")
    {
        int errcode;
        uint32_t u, v;
        errcode = number<uint32_t>::ubinxgcd(uint32_t(0x00000001), uint32_t(0x00000001), &u, &v);
        EXPECT(errcode == -1);
        errcode = number<uint32_t>::ubinxgcd(uint32_t(0x00000004), uint32_t(0x00000008), &u, &v);
        EXPECT(errcode == -2);
        errcode = number<uint32_t>::ubinxgcd(uint32_t(0x10000000), uint32_t(0x00000005), &u, &v);
        EXPECT(errcode == 0);
        EXPECT(uint32_t(2 * uint32_t(0x10000000) * u - uint32_t(0x00000005) * v) == 1);
    },
    CASE("Binary Extended GCD algorithm - 64-bit")
    {
        int errcode;
        uint64_t u, v;
        errcode = number<uint64_t>::ubinxgcd(uint64_t(0x0000000000000001), uint64_t(0x0000000000000001), &u, &v);
        EXPECT(errcode == -1);
        errcode = number<uint64_t>::ubinxgcd(uint64_t(0x0000000000000004), uint64_t(0x0000000000000008), &u, &v);
        EXPECT(errcode == -2);
        errcode = number<uint64_t>::ubinxgcd(uint64_t(0x1000000000000000), uint64_t(0x0000000000000005), &u, &v);
        EXPECT(errcode == 0);
        EXPECT(uint64_t(2 * uint64_t(0x1000000000000000) * u - uint64_t(0x0000000000000005) * v) == 1);
    },
    CASE("Binary Extended GCD algorithm - 8-bit")
    {
        uint8_t inv;
        inv = number<uint8_t>::umod_mul_inverse(uint8_t(0x01), uint8_t(0x01));
        EXPECT(uint8_t(uint8_t(0x01) * uint8_t(0x01) / inv) == 1);
        inv = number<uint8_t>::umod_mul_inverse(uint8_t(0x81), uint8_t(0x81));
        EXPECT(uint8_t(uint8_t(0x81) * uint8_t(0x81) / inv) == 1);
        inv = number<uint8_t>::umod_mul_inverse(uint8_t(0xff), uint8_t(0xff));
        EXPECT(uint8_t(uint8_t(0xff) * uint8_t(0xff) / inv) == 1);
    },
    CASE("Binary Extended GCD algorithm - 16-bit")
    {
        uint16_t inv;
        inv = number<uint16_t>::umod_mul_inverse(uint16_t(0x0001), uint16_t(0x0001));
        EXPECT(uint16_t(uint16_t(0x0001) * uint16_t(0x0001) / inv) == 1);
        inv = number<uint16_t>::umod_mul_inverse(uint16_t(0x8001), uint16_t(0x8001));
        EXPECT(uint16_t(uint16_t(0x8001) * uint16_t(0x8001) / inv) == 1);
        inv = number<uint16_t>::umod_mul_inverse(uint16_t(0xffff), uint16_t(0xffff));
        EXPECT(uint16_t(uint32_t(0xffff) * uint32_t(0xffff) / inv) == 1);
    },
    CASE("Binary Extended GCD algorithm - 32-bit")
    {
        uint32_t inv;
        inv = number<uint32_t>::umod_mul_inverse(uint32_t(0x00000001), uint32_t(0x00000001));
        EXPECT(uint32_t(uint32_t(0x00000001) * uint32_t(0x00000001) / inv) == 1);
        inv = number<uint32_t>::umod_mul_inverse(uint32_t(0x80000001), uint32_t(0x80000001));
        EXPECT(uint32_t(uint32_t(0x80000001) * uint32_t(0x80000001) / inv) == 1);
        inv = number<uint32_t>::umod_mul_inverse(uint32_t(0xffffffff), uint32_t(0xffffffff));
        EXPECT(uint32_t(uint32_t(0xffffffff) * uint32_t(0xffffffff) / inv) == 1);
    },
    CASE("Binary Extended GCD algorithm - 64-bit")
    {
        uint64_t inv;
        inv = number<uint64_t>::umod_mul_inverse(uint64_t(0x0000000000000001), uint64_t(0x0000000000000001));
        EXPECT(uint64_t(uint64_t(0x0000000000000001) * uint64_t(0x0000000000000001) / inv) == 1);
        inv = number<uint64_t>::umod_mul_inverse(uint64_t(0x8000000000000001), uint64_t(0x8000000000000001));
        EXPECT(uint64_t(uint64_t(0x8000000000000001) * uint64_t(0x8000000000000001) / inv) == 1);
        inv = number<uint64_t>::umod_mul_inverse(uint64_t(0xffffffffffffffff), uint64_t(0xffffffffffffffff));
        EXPECT(uint64_t(uint64_t(0xffffffffffffffff) * uint64_t(0xffffffffffffffff) / inv) == 1);
    },
    CASE("invx = (B^2-1)/x-B - 8-bit")
    {
        uint8_t inv;
        inv = number<uint8_t>::uinverse(uint8_t(0x01));
        EXPECT(uint8_t((uint16_t(0xffff) / uint16_t(0x01)) - 256) == inv);
        inv = number<uint8_t>::uinverse(uint8_t(0xff));
        EXPECT(uint8_t((uint16_t(0xffff) / uint16_t(0xff)) - 256) == inv);
    },
    CASE("invx = (B^2-B*x-1)/x = (B^2-1)/x-B - 16-bit")
    {
        uint16_t inv;
        inv = number<uint16_t>::uinverse(uint16_t(0x0001));
        EXPECT(uint16_t((uint32_t(0xffffffff) / uint32_t(0x0001)) - 65535 - 1) == inv);
        inv = number<uint16_t>::uinverse(uint16_t(0xffff));
        EXPECT(uint16_t((uint32_t(0xffffffff) / uint32_t(0xffff)) - 65535 - 1) == inv);
    },
    CASE("invx = (B^2-B*x-1)/x = (B^2-1)/x-B - 32-bit")
    {
        uint32_t inv;
        inv = number<uint32_t>::uinverse(uint32_t(0x00000001));
        EXPECT(uint32_t((uint64_t(0xffffffffffffffff) / uint64_t(0x00000001)) - 0xffffffff - 1) == inv);
        inv = number<uint32_t>::uinverse(uint32_t(0xffffffff));
        EXPECT(uint32_t((uint64_t(0xffffffffffffffff) / uint64_t(0xffffffff)) - 0xffffffff - 1) == inv);
    },
#if defined(__SIZEOF_INT128__)
    CASE("invx = (B^2-B*x-1)/x = (B^2-1)/x-B - 64-bit")
    {
        using uint128_t = unsigned __int128;
        uint64_t inv;
        uint128_t max = 0xffffffffffffffffULL;
        max <<= 64ULL;
        max |= 0xffffffffffffffffULL;
        inv = number<uint64_t>::uinverse(uint64_t(0x0000000000000001));
        EXPECT(uint64_t((max / uint128_t(0x0000000000000001)) - 0xffffffffffffffffULL - 1) == inv);
        inv = number<uint64_t>::uinverse(uint64_t(0xffffffffffffffff));
        EXPECT(uint64_t((max / uint128_t(0xffffffffffffffff)) - 0xffffffffffffffffULL - 1) == inv);
    },
#endif
    CASE("negative inverse, -1/q mod 2^7 - 8-bit")
    {
        uint8_t inv;
        inv = number<uint8_t>::uninv_minus1(uint8_t(0x01));
        EXPECT(uint8_t((-inv * uint8_t(0x01)) & 127) == 1);
        inv = number<uint8_t>::uninv_minus1(uint8_t(0xff));
        EXPECT(uint8_t((-inv * uint8_t(0xff)) & 127) == 1);
    },
    CASE("negative inverse, -1/q mod 2^15 - 16-bit")
    {
        uint16_t inv;
        inv = number<uint16_t>::uninv_minus1(uint16_t(0x0001));
        EXPECT(uint16_t((-inv * uint16_t(0x0001)) & 0x7fff) == 1);
        inv = number<uint16_t>::uninv_minus1(uint16_t(0xffff));
        EXPECT(uint16_t((-inv * uint16_t(0xffff)) & 0x7fff) == 1);
    },
    CASE("negative inverse, -1/q mod 2^31 - 32-bit")
    {
        uint32_t inv;
        inv = number<uint32_t>::uninv_minus1(uint32_t(0x00000001));
        EXPECT(uint32_t((-inv * uint32_t(0x00000001)) & 0x7fffffff) == 1);
        inv = number<uint32_t>::uninv_minus1(uint32_t(0xffffffff));
        EXPECT(uint32_t((-inv * uint32_t(0xffffffff)) & 0x7fffffff) == 1);
    },
    CASE("negative inverse, -1/q mod 2^63 - 64-bit")
    {
        uint64_t inv;
        inv = number<uint64_t>::uninv_minus1(uint64_t(0x0000000000000001));
        EXPECT(uint64_t((-inv * uint64_t(0x0000000000000001)) & 0x7fffffffffffffff) == 1);
        inv = number<uint64_t>::uninv_minus1(uint64_t(0xffffffffffffffff));
        EXPECT(uint64_t((-inv * uint64_t(0xffffffffffffffff)) & 0x7fffffffffffffff) == 1);
    }
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

