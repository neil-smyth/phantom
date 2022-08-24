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
    CASE("divide - 8-bit")
    {
        uint8_t q;
        q = number<uint8_t>::udiv(uint8_t(0x00), uint8_t(0x01));
        EXPECT(q == 0x00);
        q = number<uint8_t>::udiv(uint8_t(0x01), uint8_t(0x01));
        EXPECT(q == 0x01);
        q = number<uint8_t>::udiv(uint8_t(0xff), uint8_t(0x02));
        EXPECT(q == 0x7f);
        q = number<uint8_t>::udiv(uint8_t(0x88), uint8_t(0x08));
        EXPECT(q == 0x11);
        q = number<uint8_t>::udiv(uint8_t(0xfe), uint8_t(0xff));
        EXPECT(q == 0x00);
    },
    CASE("divide - 16-bit")
    {
        uint16_t q;
        q = number<uint16_t>::udiv(uint16_t(0x0000), uint16_t(0x0001));
        EXPECT(q == 0x0000);
        q = number<uint16_t>::udiv(uint16_t(0x0001), uint16_t(0x0001));
        EXPECT(q == 0x0001);
        q = number<uint16_t>::udiv(uint16_t(0xffff), uint16_t(0x0002));
        EXPECT(q == 0x7fff);
        q = number<uint16_t>::udiv(uint16_t(0x8888), uint16_t(0x0008));
        EXPECT(q == 0x1111);
        q = number<uint16_t>::udiv(uint16_t(0xfffe), uint16_t(0xffff));
        EXPECT(q == 0x0000);
    },
    CASE("divide - 32-bit")
    {
        uint32_t q;
        q = number<uint32_t>::udiv(uint32_t(0x00000000), uint32_t(0x00000001));
        EXPECT(q == 0x00000000);
        q = number<uint32_t>::udiv(uint32_t(0x00000001), uint32_t(0x00000001));
        EXPECT(q == 0x00000001);
        q = number<uint32_t>::udiv(uint32_t(0xffffffff), uint32_t(0x00000002));
        EXPECT(q == 0x7fffffff);
        q = number<uint32_t>::udiv(uint32_t(0x88888888), uint32_t(0x00000008));
        EXPECT(q == 0x11111111);
        q = number<uint32_t>::udiv(uint32_t(0xfffffffe), uint32_t(0xffffffff));
        EXPECT(q == 0x00000000);
    },
    CASE("divide - 64-bit")
    {
        uint64_t q;
        q = number<uint64_t>::udiv(uint64_t(0x0000000000000000), uint64_t(0x0000000000000001));
        EXPECT(q == 0x0000000000000000);
        q = number<uint64_t>::udiv(uint64_t(0x0000000000000001), uint64_t(0x0000000000000001));
        EXPECT(q == 0x0000000000000001);
        q = number<uint64_t>::udiv(uint64_t(0xffffffffffffffff), uint64_t(0x0000000000000002));
        EXPECT(q == 0x7fffffffffffffff);
        q = number<uint64_t>::udiv(uint64_t(0x8888888888888888), uint64_t(0x0000000000000008));
        EXPECT(q == 0x1111111111111111);
        q = number<uint64_t>::udiv(uint64_t(0xfffffffffffffffe), uint64_t(0xffffffffffffffff));
        EXPECT(q == 0x0000000000000000);
    },
    CASE("divide with remainder - 8-bit")
    {
        uint8_t q, r;
        number<uint8_t>::udiv_qrnd(&q, &r, uint8_t(0x00), uint8_t(0x01));
        EXPECT(q == 0x00);
        EXPECT(r == 0x00);
        number<uint8_t>::udiv_qrnd(&q, &r, uint8_t(0x01), uint8_t(0x01));
        EXPECT(q == 0x01);
        EXPECT(r == 0x00);
        number<uint8_t>::udiv_qrnd(&q, &r, uint8_t(0xff), uint8_t(0x02));
        EXPECT(q == 0x7f);
        EXPECT(r == 0x01);
        number<uint8_t>::udiv_qrnd(&q, &r, uint8_t(0x88), uint8_t(0x08));
        EXPECT(q == 0x11);
        EXPECT(r == 0x00);
        number<uint8_t>::udiv_qrnd(&q, &r, uint8_t(0xfe), uint8_t(0xff));
        EXPECT(q == 0x00);
        EXPECT(r == 0xfe);
    },
    CASE("divide with remainder - 16-bit")
    {
        uint16_t q, r;
        number<uint16_t>::udiv_qrnd(&q, &r, uint16_t(0x0000), uint16_t(0x0001));
        EXPECT(q == 0x0000);
        EXPECT(r == 0x0000);
        number<uint16_t>::udiv_qrnd(&q, &r, uint16_t(0x0001), uint16_t(0x0001));
        EXPECT(q == 0x0001);
        EXPECT(r == 0x0000);
        number<uint16_t>::udiv_qrnd(&q, &r, uint16_t(0xffff), uint16_t(0x0002));
        EXPECT(q == 0x7fff);
        EXPECT(r == 0x0001);
        number<uint16_t>::udiv_qrnd(&q, &r, uint16_t(0x8888), uint16_t(0x0008));
        EXPECT(q == 0x1111);
        EXPECT(r == 0x0000);
        number<uint16_t>::udiv_qrnd(&q, &r, uint16_t(0xfffe), uint16_t(0xffff));
        EXPECT(q == 0x0000);
        EXPECT(r == 0xfffe);
    },
    CASE("divide with remainder - 32-bit")
    {
        uint32_t q, r;
        number<uint32_t>::udiv_qrnd(&q, &r, uint32_t(0x00000000), uint32_t(0x00000001));
        EXPECT(q == 0x00000000);
        EXPECT(r == 0x00000000);
        number<uint32_t>::udiv_qrnd(&q, &r, uint32_t(0x00000001), uint32_t(0x00000001));
        EXPECT(q == 0x00000001);
        EXPECT(r == 0x00000000);
        number<uint32_t>::udiv_qrnd(&q, &r, uint32_t(0xffffffff), uint32_t(0x00000002));
        EXPECT(q == 0x7fffffff);
        EXPECT(r == 0x00000001);
        number<uint32_t>::udiv_qrnd(&q, &r, uint32_t(0x88888888), uint32_t(0x00000008));
        EXPECT(q == 0x11111111);
        EXPECT(r == 0x00000000);
        number<uint32_t>::udiv_qrnd(&q, &r, uint32_t(0xfffffffe), uint32_t(0xffffffff));
        EXPECT(q == 0x00000000);
        EXPECT(r == 0xfffffffe);
    },
    CASE("divide with remainder - 64-bit")
    {
        uint64_t q, r;
        number<uint64_t>::udiv_qrnd(&q, &r, uint64_t(0x0000000000000000), uint64_t(0x0000000000000001));
        EXPECT(q == 0x0000000000000000);
        EXPECT(r == 0x0000000000000000);
        number<uint64_t>::udiv_qrnd(&q, &r, uint64_t(0x0000000000000001), uint64_t(0x0000000000000001));
        EXPECT(q == 0x0000000000000001);
        EXPECT(r == 0x0000000000000000);
        number<uint64_t>::udiv_qrnd(&q, &r, uint64_t(0xffffffffffffffff), uint64_t(0x0000000000000002));
        EXPECT(q == 0x7fffffffffffffff);
        EXPECT(r == 0x0000000000000001);
        number<uint64_t>::udiv_qrnd(&q, &r, uint64_t(0x8888888888888888), uint64_t(0x0000000000000008));
        EXPECT(q == 0x1111111111111111);
        EXPECT(r == 0x0000000000000000);
        number<uint64_t>::udiv_qrnd(&q, &r, uint64_t(0xfffffffffffffffe), uint64_t(0xffffffffffffffff));
        EXPECT(q == 0x0000000000000000);
        EXPECT(r == 0xfffffffffffffffe);
    },
    CASE("divide double word numerator with remainder - 8-bit")
    {
        uint8_t q, r;
        number<uint8_t>::udiv_qrnnd(&q, &r, uint8_t(0x00), uint8_t(0x00), uint8_t(0x01));
        EXPECT(q == 0x00);
        EXPECT(r == 0000);
        number<uint8_t>::udiv_qrnnd(&q, &r, uint8_t(0x00), uint8_t(0x01), uint8_t(0x01));
        EXPECT(q == 0x01);
        EXPECT(r == 0x00);
        number<uint8_t>::udiv_qrnnd(&q, &r, uint8_t(0x01), uint8_t(0xff), uint8_t(0x02));
        EXPECT(q == 0xff);
        EXPECT(r == 0x01);
        number<uint8_t>::udiv_qrnnd(&q, &r, uint8_t(0x08), uint8_t(0x89), uint8_t(0x80));
        EXPECT(q == 0x11);
        EXPECT(r == 0x09);
        number<uint8_t>::udiv_qrnnd(&q, &r, uint8_t(0x0f), uint8_t(0xfe), uint8_t(0xff));
        EXPECT(q == 0x10);
        EXPECT(r == 0x0e);
    },
    CASE("divide double word numerator with remainder - 16-bit")
    {
        uint16_t q, r;
        number<uint16_t>::udiv_qrnnd(&q, &r, uint16_t(0x0000), uint16_t(0x0000), uint16_t(0x0001));
        EXPECT(q == 0x0000);
        EXPECT(r == 0x0000);
        number<uint16_t>::udiv_qrnnd(&q, &r, uint16_t(0x0000), uint16_t(0x0001), uint16_t(0x0001));
        EXPECT(q == 0x0001);
        EXPECT(r == 0x0000);
        number<uint16_t>::udiv_qrnnd(&q, &r, uint16_t(0x0001), uint16_t(0xffff), uint16_t(0x0002));
        EXPECT(q == 0xffff);
        EXPECT(r == 0x0001);
        number<uint16_t>::udiv_qrnnd(&q, &r, uint16_t(0x0008), uint16_t(0x8889), uint16_t(0x0080));
        EXPECT(q == 0x1111);
        EXPECT(r == 0x0009);
        number<uint16_t>::udiv_qrnnd(&q, &r, uint16_t(0x000f), uint16_t(0xfffe), uint16_t(0xffff));
        EXPECT(q == 0x0010);
        EXPECT(r == 0x000e);
    },
    CASE("divide double word numerator with remainder - 32-bit")
    {
        uint32_t q, r;
        number<uint32_t>::udiv_qrnnd(&q, &r, uint32_t(0x00000000), uint32_t(0x00000000), uint32_t(0x00000001));
        EXPECT(q == 0x00000000);
        EXPECT(r == 0x00000000);
        number<uint32_t>::udiv_qrnnd(&q, &r, uint32_t(0x00000000), uint32_t(0x00000001), uint32_t(0x00000001));
        EXPECT(q == 0x00000001);
        EXPECT(r == 0x00000000);
        number<uint32_t>::udiv_qrnnd(&q, &r, uint32_t(0x00000001), uint32_t(0xffffffff), uint32_t(0x00000002));
        EXPECT(q == 0xffffffff);
        EXPECT(r == 0x00000001);
        number<uint32_t>::udiv_qrnnd(&q, &r, uint32_t(0x00000008), uint32_t(0x88888889), uint32_t(0x00000080));
        EXPECT(q == 0x11111111);
        EXPECT(r == 0x00000009);
        number<uint32_t>::udiv_qrnnd(&q, &r, uint32_t(0x0000000f), uint32_t(0xfffffffe), uint32_t(0xffffffff));
        EXPECT(q == 0x00000010);
        EXPECT(r == 0x0000000e);
    },
    CASE("divide double word numerator with remainder - 64-bit")
    {
        uint64_t q, r;
        number<uint64_t>::udiv_qrnnd(&q, &r, uint64_t(0x0000000000000000),
            uint64_t(0x0000000000000000), uint64_t(0x0000000000000001));
        EXPECT(q == 0x0000000000000000);
        EXPECT(r == 0x0000000000000000);
        number<uint64_t>::udiv_qrnnd(&q, &r, uint64_t(0x0000000000000000),
            uint64_t(0x0000000000000001), uint64_t(0x0000000000000001));
        EXPECT(q == 0x0000000000000001);
        EXPECT(r == 0x0000000000000000);
        number<uint64_t>::udiv_qrnnd(&q, &r, uint64_t(0x0000000000000001),
            uint64_t(0xffffffffffffffff), uint64_t(0x0000000000000002));
        EXPECT(q == 0xffffffffffffffff);
        EXPECT(r == 0x0000000000000001);
        number<uint64_t>::udiv_qrnnd(&q, &r, uint64_t(0x0000000000000008),
            uint64_t(0x8888888888888889), uint64_t(0x0000000000000080));
        EXPECT(q == 0x1111111111111111);
        EXPECT(r == 0x0000000000000009);
        number<uint64_t>::udiv_qrnnd(&q, &r, uint64_t(0x000000000000000f),
            uint64_t(0xfffffffffffffffe), uint64_t(0xffffffffffffffff));
        EXPECT(q == 0x0000000000000010);
        EXPECT(r == 0x000000000000000e);
    },
    CASE("divide double word numerator with remainder and pre-inversion - 8-bit")
    {
        uint8_t q, r, d_inv;
        d_inv = number<uint8_t>::uinverse(uint8_t(0x80));
        number<uint8_t>::udiv_qrnnd_preinv(&q, &r, uint8_t(0x00), uint8_t(0x00), uint8_t(0x80), d_inv);
        EXPECT(q == 0x00);
        EXPECT(r == 0x00);
        d_inv = number<uint8_t>::uinverse(uint8_t(0x80));
        number<uint8_t>::udiv_qrnnd_preinv(&q, &r, uint8_t(0x00), uint8_t(0x80), uint8_t(0x80), d_inv);
        EXPECT(q == 0x01);
        EXPECT(r == 0x00);
        d_inv = number<uint8_t>::uinverse(uint8_t(2 << 6));
        number<uint8_t>::udiv_qrnnd_preinv(&q, &r, uint8_t(0x7f), uint8_t(0xc0), uint8_t(2 << 6), d_inv);
        EXPECT(q == 0xff);
        EXPECT((r >> 6) == 0x01);
        d_inv = number<uint8_t>::uinverse(uint8_t(0x80));
        number<uint8_t>::udiv_qrnnd_preinv(&q, &r, uint8_t(0x08), uint8_t(0x89), uint8_t(0x80), d_inv);
        EXPECT(q == 0x11);
        EXPECT(r == 0x09);
        d_inv = number<uint8_t>::uinverse(uint8_t(0xff));
        number<uint8_t>::udiv_qrnnd_preinv(&q, &r, uint8_t(0x0f), uint8_t(0xfe), uint8_t(0xff), d_inv);
        EXPECT(q == 0x10);
        EXPECT(r == 0x0e);
    },
    CASE("divide double word numerator with remainder and pre-inversion - 16-bit")
    {
        uint16_t q, r, d_inv;
        d_inv = number<uint16_t>::uinverse(uint16_t(0x8000));
        number<uint16_t>::udiv_qrnnd_preinv(&q, &r, uint16_t(0x0000), uint16_t(0x0000), uint16_t(0x8000), d_inv);
        EXPECT(q == 0x0000);
        EXPECT(r == 0x0000);
        d_inv = number<uint16_t>::uinverse(uint16_t(0x8000));
        number<uint16_t>::udiv_qrnnd_preinv(&q, &r, uint16_t(0x0000), uint16_t(0x8000), uint16_t(0x8000), d_inv);
        EXPECT(q == 0x0001);
        EXPECT(r == 0x0000);
        d_inv = number<uint16_t>::uinverse(uint16_t(2 << 14));
        number<uint16_t>::udiv_qrnnd_preinv(&q, &r, uint16_t(0x7fff), uint16_t(0xc000), uint16_t(2 << 14), d_inv);
        EXPECT(q == 0xffff);
        EXPECT((r >> 14) == 0x0001);
        d_inv = number<uint16_t>::uinverse(uint16_t(0x80 << 8));
        number<uint16_t>::udiv_qrnnd_preinv(&q, &r, uint16_t(0x0888), uint16_t(0x8900), uint16_t(0x80 << 8), d_inv);
        EXPECT(q == 0x1111);
        EXPECT((r >> 8) == 0x0009);
        d_inv = number<uint16_t>::uinverse(uint16_t(0xffff));
        number<uint16_t>::udiv_qrnnd_preinv(&q, &r, uint16_t(0x000f), uint16_t(0xfffe), uint16_t(0xffff), d_inv);
        EXPECT(q == 0x0010);
        EXPECT(r == 0x000e);
    },
    CASE("divide double word numerator with remainder and pre-inversion - 32-bit")
    {
        uint32_t q, r, d_inv;
        d_inv = number<uint32_t>::uinverse(uint32_t(0x80000000));
        number<uint32_t>::udiv_qrnnd_preinv(&q, &r, uint32_t(0x00000000),
            uint32_t(0x00000000), uint32_t(0x80000000), d_inv);
        EXPECT(q == 0x00000000);
        EXPECT(r == 0x00000000);
        d_inv = number<uint32_t>::uinverse(uint32_t(0x80000000));
        number<uint32_t>::udiv_qrnnd_preinv(&q, &r, uint32_t(0x00000000),
            uint32_t(0x80000000), uint32_t(0x80000000), d_inv);
        EXPECT(q == 0x00000001);
        EXPECT(r == 0x00000000);
        d_inv = number<uint32_t>::uinverse(uint32_t(2 << 30));
        number<uint32_t>::udiv_qrnnd_preinv(&q, &r, uint32_t(0x7fffffff),
            uint32_t(0xc0000000), uint32_t(2 << 30), d_inv);
        EXPECT(q == 0xffffffff);
        EXPECT((r >> 30) == 0x00000001);
        d_inv = number<uint32_t>::uinverse(uint32_t(0x80 << 24));
        number<uint32_t>::udiv_qrnnd_preinv(&q, &r, uint32_t(0x08888888),
            uint32_t(0x89000000), uint32_t(0x80 << 24), d_inv);
        EXPECT(q == 0x11111111);
        EXPECT((r >> 24) == 0x00000009);
        d_inv = number<uint32_t>::uinverse(uint32_t(0xffffffff));
        number<uint32_t>::udiv_qrnnd_preinv(&q, &r, uint32_t(0x0000000f),
            uint32_t(0xfffffffe), uint32_t(0xffffffff), d_inv);
        EXPECT(q == 0x00000010);
        EXPECT(r == 0x0000000e);
    },
    CASE("divide double word numerator with remainder and pre-inversion - 64-bit")
    {
        uint64_t q, r, d_inv;
        d_inv = number<uint64_t>::uinverse(uint64_t(0x8000000000000000));
        number<uint64_t>::udiv_qrnnd_preinv(&q, &r, uint64_t(0x0000000000000000),
            uint64_t(0x0000000000000000), uint64_t(0x8000000000000000), d_inv);
        EXPECT(q == 0x0000000000000000);
        EXPECT(r == 0x0000000000000000);
        d_inv = number<uint64_t>::uinverse(uint64_t(0x8000000000000000));
        number<uint64_t>::udiv_qrnnd_preinv(&q, &r, uint64_t(0x0000000000000000),
            uint64_t(0x8000000000000000), uint64_t(0x8000000000000000), d_inv);
        EXPECT(q == 0x0000000000000001);
        EXPECT(r == 0x0000000000000000);
        d_inv = number<uint64_t>::uinverse(uint64_t(2ULL << 62));
        number<uint64_t>::udiv_qrnnd_preinv(&q, &r, uint64_t(0x7fffffffffffffff),
            uint64_t(0xc000000000000000), uint64_t(2ULL << 62), d_inv);
        EXPECT(q == 0xffffffffffffffff);
        EXPECT((r >> 62ULL) == 0x0000000000000001);
        d_inv = number<uint64_t>::uinverse(uint64_t(0x80ULL << 56));
        number<uint64_t>::udiv_qrnnd_preinv(&q, &r, uint64_t(0x0888888888888888),
            uint64_t(0x8900000000000000), uint64_t(0x80ULL << 56), d_inv);
        EXPECT(q == 0x1111111111111111);
        EXPECT((r >> 56ULL) == 0x0000000000000009);
        d_inv = number<uint64_t>::uinverse(uint64_t(0xffffffffffffffff));
        number<uint64_t>::udiv_qrnnd_preinv(&q, &r, uint64_t(0x000000000000000f),
            uint64_t(0xfffffffffffffffe), uint64_t(0xffffffffffffffff), d_inv);
        EXPECT(q == 0x0000000000000010);
        EXPECT(r == 0x000000000000000e);
    },
    CASE("remainder - 8-bit")
    {
        uint8_t r;
        r = number<uint8_t>::urem(uint8_t(0x00), uint8_t(0x01));
        EXPECT(r == 0x00);
        r = number<uint8_t>::urem(uint8_t(0x7f), uint8_t(0x80));
        EXPECT(r == 0x7f);
        r = number<uint8_t>::urem(uint8_t(0x1f), uint8_t(0x10));
        EXPECT(r == 0x0f);
        r = number<uint8_t>::urem(uint8_t(0x5f), uint8_t(0x20));
        EXPECT(r == 0x1f);
    },
    CASE("remainder - 16-bit")
    {
        uint16_t r;
        r = number<uint16_t>::urem(uint16_t(0x0000), uint16_t(0x0001));
        EXPECT(r == 0x0000);
        r = number<uint16_t>::urem(uint16_t(0x7fff), uint16_t(0x8000));
        EXPECT(r == 0x7fff);
        r = number<uint16_t>::urem(uint16_t(0x1fff), uint16_t(0x1000));
        EXPECT(r == 0x0fff);
        r = number<uint16_t>::urem(uint16_t(0x5fff), uint16_t(0x2000));
        EXPECT(r == 0x1fff);
    },
    CASE("remainder - 32-bit")
    {
        uint32_t r;
        r = number<uint32_t>::urem(uint32_t(0x00000000), uint32_t(0x00000001));
        EXPECT(r == 0x00000000);
        r = number<uint32_t>::urem(uint32_t(0x7fffffff), uint32_t(0x80000000));
        EXPECT(r == 0x7fffffff);
        r = number<uint32_t>::urem(uint32_t(0x1fffffff), uint32_t(0x10000000));
        EXPECT(r == 0x0fffffff);
        r = number<uint32_t>::urem(uint32_t(0x5fffffff), uint32_t(0x20000000));
        EXPECT(r == 0x1fffffff);
    },
    CASE("remainder - 64-bit")
    {
        uint64_t r;
        r = number<uint64_t>::urem(uint64_t(0x0000000000000000), uint64_t(0x0000000000000001));
        EXPECT(r == 0x0000000000000000);
        r = number<uint64_t>::urem(uint64_t(0x7fffffffffffffff), uint64_t(0x8000000000000000));
        EXPECT(r == 0x7fffffffffffffff);
        r = number<uint64_t>::urem(uint64_t(0x1fffffffffffffff), uint64_t(0x1000000000000000));
        EXPECT(r == 0x0fffffffffffffff);
        r = number<uint64_t>::urem(uint64_t(0x5fffffffffffffff), uint64_t(0x2000000000000000));
        EXPECT(r == 0x1fffffffffffffff);
    },
    CASE("remainder - 8-bit")
    {
        uint8_t r;
        r = number<uint8_t>::umod_nnd(uint8_t(0x00), uint8_t(0x00), uint8_t(0x01));
        EXPECT(r == 0x00);
        r = number<uint8_t>::umod_nnd(uint8_t(0x00), uint8_t(0x7f), uint8_t(0x80));
        EXPECT(r == 0x7f);
        r = number<uint8_t>::umod_nnd(uint8_t(0x00), uint8_t(0x1f), uint8_t(0x10));
        EXPECT(r == 0x0f);
        r = number<uint8_t>::umod_nnd(uint8_t(0x00), uint8_t(0x5f), uint8_t(0x20));
        EXPECT(r == 0x1f);
        r = number<uint8_t>::umod_nnd(uint8_t(0x01), uint8_t(0xff), uint8_t(0x20));
        EXPECT(r == 0x1f);
        r = number<uint8_t>::umod_nnd(uint8_t(0xff), uint8_t(0xff), uint8_t(0x10));
        EXPECT(r == 0x0f);
    },
    CASE("remainder - 16-bit")
    {
        uint16_t r;
        r = number<uint16_t>::umod_nnd(uint16_t(0x0000), uint16_t(0x0000), uint16_t(0x0001));
        EXPECT(r == 0x0000);
        r = number<uint16_t>::umod_nnd(uint16_t(0x0000), uint16_t(0x7fff), uint16_t(0x8000));
        EXPECT(r == 0x7fff);
        r = number<uint16_t>::umod_nnd(uint16_t(0x0000), uint16_t(0x1fff), uint16_t(0x1000));
        EXPECT(r == 0x0fff);
        r = number<uint16_t>::umod_nnd(uint16_t(0x0000), uint16_t(0x5fff), uint16_t(0x2000));
        EXPECT(r == 0x1fff);
        r = number<uint16_t>::umod_nnd(uint16_t(0x0001), uint16_t(0xffff), uint16_t(0x2000));
        EXPECT(r == 0x1fff);
        r = number<uint16_t>::umod_nnd(uint16_t(0xffff), uint16_t(0xffff), uint16_t(0x1000));
        EXPECT(r == 0x0fff);
    },
    CASE("remainder - 32-bit")
    {
        uint32_t r;
        r = number<uint32_t>::umod_nnd(uint32_t(0x00000000), uint32_t(0x00000000), uint32_t(0x00000001));
        EXPECT(r == 0x00000000);
        r = number<uint32_t>::umod_nnd(uint32_t(0x00000000), uint32_t(0x7fffffff), uint32_t(0x80000000));
        EXPECT(r == 0x7fffffff);
        r = number<uint32_t>::umod_nnd(uint32_t(0x00000000), uint32_t(0x1fffffff), uint32_t(0x10000000));
        EXPECT(r == 0x0fffffff);
        r = number<uint32_t>::umod_nnd(uint32_t(0x00000000), uint32_t(0x5fffffff), uint32_t(0x20000000));
        EXPECT(r == 0x1fffffff);
        r = number<uint32_t>::umod_nnd(uint32_t(0x00000001), uint32_t(0xffffffff), uint32_t(0x20000000));
        EXPECT(r == 0x1fffffff);
        r = number<uint32_t>::umod_nnd(uint32_t(0xffffffff), uint32_t(0xffffffff), uint32_t(0x10000000));
        EXPECT(r == 0x0fffffff);
    },
    CASE("remainder - 64-bit")
    {
        uint64_t r;
        r = number<uint64_t>::umod_nnd(uint64_t(0x0000000000000000),
            uint64_t(0x0000000000000000), uint64_t(0x0000000000000001));
        EXPECT(r == 0x0000000000000000);
        r = number<uint64_t>::umod_nnd(uint64_t(0x0000000000000000),
            uint64_t(0x7fffffffffffffff), uint64_t(0x8000000000000000));
        EXPECT(r == 0x7fffffffffffffff);
        r = number<uint64_t>::umod_nnd(uint64_t(0x0000000000000000),
            uint64_t(0x1fffffffffffffff), uint64_t(0x1000000000000000));
        EXPECT(r == 0x0fffffffffffffff);
        r = number<uint64_t>::umod_nnd(uint64_t(0x0000000000000000),
            uint64_t(0x5fffffffffffffff), uint64_t(0x2000000000000000));
        EXPECT(r == 0x1fffffffffffffff);
        r = number<uint64_t>::umod_nnd(uint64_t(0x0000000000000001),
            uint64_t(0xffffffffffffffff), uint64_t(0x2000000000000000));
        EXPECT(r == 0x1fffffffffffffff);
        r = number<uint64_t>::umod_nnd(uint64_t(0xffffffffffffffff),
            uint64_t(0xffffffffffffffff), uint64_t(0x1000000000000000));
        EXPECT(r == 0x0fffffffffffffff);
    },
    CASE("multiply - 8-bit")
    {
        uint8_t h, l;
        number<uint8_t>::umul(&h, &l, uint8_t(0x00), uint8_t(0x00));
        EXPECT(h == 0x00);
        EXPECT(l == 0x00);
        number<uint8_t>::umul(&h, &l, uint8_t(0x00), uint8_t(0x01));
        EXPECT(h == 0x00);
        EXPECT(l == 0x00);
        number<uint8_t>::umul(&h, &l, uint8_t(0x01), uint8_t(0x01));
        EXPECT(h == 0x00);
        EXPECT(l == 0x01);
        number<uint8_t>::umul(&h, &l, uint8_t(0xff), uint8_t(0xff));
        EXPECT(h == 0xfe);
        EXPECT(l == 0x01);
    },
    CASE("multiply - 16-bit")
    {
        uint16_t h, l;
        number<uint16_t>::umul(&h, &l, uint16_t(0x0000), uint16_t(0x0000));
        EXPECT(h == 0x0000);
        EXPECT(l == 0x0000);
        number<uint16_t>::umul(&h, &l, uint16_t(0x0000), uint16_t(0x0001));
        EXPECT(h == 0x0000);
        EXPECT(l == 0x0000);
        number<uint16_t>::umul(&h, &l, uint16_t(0x0001), uint16_t(0x0001));
        EXPECT(h == 0x0000);
        EXPECT(l == 0x0001);
        number<uint16_t>::umul(&h, &l, uint16_t(0xffff), uint16_t(0xffff));
        EXPECT(h == 0xfffe);
        EXPECT(l == 0x0001);
    },
    CASE("multiply - 32-bit")
    {
        uint32_t h, l;
        number<uint32_t>::umul(&h, &l, uint32_t(0x00000000), uint32_t(0x00000000));
        EXPECT(h == 0x00000000);
        EXPECT(l == 0x00000000);
        number<uint32_t>::umul(&h, &l, uint32_t(0x00000000), uint32_t(0x00000001));
        EXPECT(h == 0x00000000);
        EXPECT(l == 0x00000000);
        number<uint32_t>::umul(&h, &l, uint32_t(0x00000001), uint32_t(0x00000001));
        EXPECT(h == 0x00000000);
        EXPECT(l == 0x00000001);
        number<uint32_t>::umul(&h, &l, uint32_t(0xffffffff), uint32_t(0xffffffff));
        EXPECT(h == 0xfffffffe);
        EXPECT(l == 0x00000001);
    },
    CASE("multiply - 64-bit")
    {
        uint64_t h, l;
        number<uint64_t>::umul(&h, &l, uint64_t(0x0000000000000000), uint64_t(0x0000000000000000));
        EXPECT(h == 0x0000000000000000);
        EXPECT(l == 0x0000000000000000);
        number<uint64_t>::umul(&h, &l, uint64_t(0x0000000000000000), uint64_t(0x0000000000000001));
        EXPECT(h == 0x0000000000000000);
        EXPECT(l == 0x0000000000000000);
        number<uint64_t>::umul(&h, &l, uint64_t(0x0000000000000001), uint64_t(0x0000000000000001));
        EXPECT(h == 0x0000000000000000);
        EXPECT(l == 0x0000000000000001);
        number<uint64_t>::umul(&h, &l, uint64_t(0xffffffffffffffff), uint64_t(0xffffffffffffffff));
        EXPECT(h == 0xfffffffffffffffe);
        EXPECT(l == 0x0000000000000001);
    }
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

