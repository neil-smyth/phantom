/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include <iostream>
#include <memory>
#include "./lest.hpp"
#include "core/mp_gf2n.hpp"

namespace phantom {
using namespace core;  // NOLINT

const lest::test specification[] =
{
    CASE("Addition - 16-bit")
    {
        mp_gf2n<uint16_t> a("fffe", "ffff", 16);
        mp_gf2n<uint16_t> b("0001", "ffff", 16);
        mp_gf2n<uint16_t> s = a + b;
        EXPECT(s.sizeinbase(2) == 16U);
        EXPECT(s.get_str(16) == "ffff");
    },
    CASE("Addition multi-word - 16-bit")
    {
        mp_gf2n<uint16_t> a("aaaaaaaaaaaaaaaaaa", "ffffffffffffffffff", 16);
        mp_gf2n<uint16_t> b("555555555555555555", "ffffffffffffffffff", 16);
        mp_gf2n<uint16_t> s = a + b;
        EXPECT(s.sizeinbase(2) == 72U);
        EXPECT(s.get_str(16) == "ffffffffffffffffff");
    },
    CASE("Subtraction - 16-bit")
    {
        mp_gf2n<uint16_t> a("ffff", "ffff", 16);
        mp_gf2n<uint16_t> b("0001", "ffff", 16);
        mp_gf2n<uint16_t> s = a - b;
        EXPECT(s.sizeinbase(2) == 16U);
        EXPECT(s.get_str(16) == "fffe");
    },
    CASE("Subtraction multi-word - 16-bit")
    {
        mp_gf2n<uint16_t> a("aaaaaaaaaaaaaaaaaa", "ffffffffffffffffff", 16);
        mp_gf2n<uint16_t> b("555555555555555555", "ffffffffffffffffff", 16);
        mp_gf2n<uint16_t> s = a - b;
        EXPECT(s.sizeinbase(2) == 72U);
        EXPECT(s.get_str(16) == "ffffffffffffffffff");
    },
    CASE("Multiplication without overflow - 16-bit")
    {
        mp_gf2n<uint16_t> a("7ffe", "ffff", 16);
        mp_gf2n<uint16_t> b("0002", "ffff", 16);
        mp_gf2n<uint16_t> s = a * b;
        EXPECT(s.sizeinbase(2) == 2U);
        EXPECT(s.get_str(16) == "3");
    },
    CASE("Multiplication without overflow multi-word - 16-bit")
    {
        mp_gf2n<uint16_t> a("7ffffffffffffffffe", "ffffffffffffffffff", 16);
        mp_gf2n<uint16_t> b("0002", "ffffffffffffffffff", 16);
        mp_gf2n<uint16_t> s = a * b;
        EXPECT(s.sizeinbase(2) == 2U);
        EXPECT(s.get_str(16) == "3");
    },
    CASE("Left shift zero - 16-bit")
    {
        mp_gf2n<uint16_t> a("7ffe", "ffff", 16);
        mp_gf2n<uint16_t> s = a << 0;
        EXPECT(s.sizeinbase(2) == 15U);
        EXPECT(s.get_str(16) == "7ffe");
    },
    CASE("Left shift - 16-bit")
    {
        mp_gf2n<uint16_t> a("7ffe", "ffff", 16);
        mp_gf2n<uint16_t> s = a << 1;
        EXPECT(s.sizeinbase(2) == 16U);
        EXPECT(s.get_str(16) == "fffc");
    },
    CASE("Left shift multi-word - 16-bit")
    {
        mp_gf2n<uint16_t> a("7ffffffffe", "ffffffffff", 16);
        mp_gf2n<uint16_t> s = a << 17;
        EXPECT(s.sizeinbase(2) == 56U);
        EXPECT(s.get_str(16) == "fffffffffc0000");
    },
    CASE("Left shift multi-word assignment - 16-bit")
    {
        mp_gf2n<uint16_t> a("7ffffffffe", "ffffffffff", 16);
        a <<= 17;
        EXPECT(a.sizeinbase(2) == 56U);
        EXPECT(a.get_str(16) == "fffffffffc0000");
    },
    CASE("Right shift zero - 16-bit")
    {
        mp_gf2n<uint16_t> a("7ffe", "ffff", 16);
        mp_gf2n<uint16_t> s = a >> 0;
        EXPECT(s.sizeinbase(2) == 15U);
        EXPECT(s.get_str(16) == "7ffe");
    },
    CASE("Right shift - 16-bit")
    {
        mp_gf2n<uint16_t> a("7ffe", "ffff", 16);
        mp_gf2n<uint16_t> s = a >> 1;
        EXPECT(s.sizeinbase(2) == 14U);
        EXPECT(s.get_str(16) == "3fff");
    },
    CASE("Right shift multi-word - 16-bit")
    {
        mp_gf2n<uint16_t> a("7ffffffffe", "ffffffffff", 16);
        mp_gf2n<uint16_t> s = a >> 17;
        EXPECT(s.sizeinbase(2) == 22U);
        EXPECT(s.get_str(16) == "3fffff");
    },
    CASE("Right shift multi-word assignment - 16-bit")
    {
        mp_gf2n<uint16_t> a("7ffffffffe", "ffffffffff", 16);
        a >>= 17;
        EXPECT(a.sizeinbase(2) == 22U);
        EXPECT(a.get_str(16) == "3fffff");
    },
    CASE("Division simple - 16-bit")
    {
        mp_gf2n<uint16_t> a("4", "8041", 16);
        mp_gf2n<uint16_t> b("2", "8041", 16);
        mp_gf2n<uint16_t> s = a / b;
        mp_gf2n<uint16_t> t = s * b;
        EXPECT(t.get_str(16) == "4");
    },
    CASE("Division fractional - 16-bit")
    {
        mp_gf2n<uint16_t> a("3", "141", 16);
        mp_gf2n<uint16_t> b("65", "141", 16);
        mp_gf2n<uint16_t> s = a / b;
        mp_gf2n<uint16_t> t = s * b;
        EXPECT(t.get_str(16) == "3");
    },
    CASE("Addition - 32-bit")
    {
        mp_gf2n<uint32_t> a("fffe", "ffff", 16);
        mp_gf2n<uint32_t> b("0001", "ffff", 16);
        mp_gf2n<uint32_t> s = a + b;
        EXPECT(s.sizeinbase(2) == 16U);
        EXPECT(s.get_str(16) == "ffff");
    },
    CASE("Addition multi-word - 32-bit")
    {
        mp_gf2n<uint32_t> a("aaaaaaaaaaaaaaaaaa", "ffffffffffffffffff", 16);
        mp_gf2n<uint32_t> b("555555555555555555", "ffffffffffffffffff", 16);
        mp_gf2n<uint32_t> s = a + b;
        EXPECT(s.sizeinbase(2) == 72U);
        EXPECT(s.get_str(16) == "ffffffffffffffffff");
    },
    CASE("Subtraction - 32-bit")
    {
        mp_gf2n<uint32_t> a("ffff", "ffff", 16);
        mp_gf2n<uint32_t> b("0001", "ffff", 16);
        mp_gf2n<uint32_t> s = a - b;
        EXPECT(s.sizeinbase(2) == 16U);
        EXPECT(s.get_str(16) == "fffe");
    },
    CASE("Subtraction multi-word - 32-bit")
    {
        mp_gf2n<uint32_t> a("aaaaaaaaaaaaaaaaaa", "ffffffffffffffffff", 16);
        mp_gf2n<uint32_t> b("555555555555555555", "ffffffffffffffffff", 16);
        mp_gf2n<uint32_t> s = a - b;
        EXPECT(s.sizeinbase(2) == 72U);
        EXPECT(s.get_str(16) == "ffffffffffffffffff");
    },
    CASE("Multiplication without overflow - 32-bit")
    {
        mp_gf2n<uint32_t> a("7ffe", "ffff", 16);
        mp_gf2n<uint32_t> b("0002", "ffff", 16);
        mp_gf2n<uint32_t> s = a * b;
        EXPECT(s.sizeinbase(2) == 2U);
        EXPECT(s.get_str(16) == "3");
    },
    CASE("Multiplication without overflow multi-word - 32-bit")
    {
        mp_gf2n<uint32_t> a("7ffffffffffffffffe", "ffffffffffffffffff", 16);
        mp_gf2n<uint32_t> b("0002", "ffffffffffffffffff", 16);
        mp_gf2n<uint32_t> s = a * b;
        EXPECT(s.sizeinbase(2) == 2U);
        EXPECT(s.get_str(16) == "3");
    },
    CASE("Left shift zero - 32-bit")
    {
        mp_gf2n<uint32_t> a("7ffe", "ffff", 16);
        mp_gf2n<uint32_t> s = a << 0;
        EXPECT(s.sizeinbase(2) == 15U);
        EXPECT(s.get_str(16) == "7ffe");
    },
    CASE("Left shift - 32-bit")
    {
        mp_gf2n<uint32_t> a("7ffe", "ffff", 16);
        mp_gf2n<uint32_t> s = a << 1;
        EXPECT(s.sizeinbase(2) == 16U);
        EXPECT(s.get_str(16) == "fffc");
    },
    CASE("Left shift multi-word - 32-bit")
    {
        mp_gf2n<uint32_t> a("7ffffffffe", "ffffffffff", 16);
        mp_gf2n<uint32_t> s = a << 17;
        EXPECT(s.sizeinbase(2) == 56U);
        EXPECT(s.get_str(16) == "fffffffffc0000");
    },
    CASE("Left shift multi-word assignment - 32-bit")
    {
        mp_gf2n<uint32_t> a("7ffffffffe", "ffffffffff", 16);
        a <<= 17;
        EXPECT(a.sizeinbase(2) == 56U);
        EXPECT(a.get_str(16) == "fffffffffc0000");
    },
    CASE("Right shift zero - 32-bit")
    {
        mp_gf2n<uint32_t> a("7ffe", "ffff", 16);
        mp_gf2n<uint32_t> s = a >> 0;
        EXPECT(s.sizeinbase(2) == 15U);
        EXPECT(s.get_str(16) == "7ffe");
    },
    CASE("Right shift - 32-bit")
    {
        mp_gf2n<uint32_t> a("7ffe", "ffff", 16);
        mp_gf2n<uint32_t> s = a >> 1;
        EXPECT(s.sizeinbase(2) == 14U);
        EXPECT(s.get_str(16) == "3fff");
    },
    CASE("Right shift multi-word - 32-bit")
    {
        mp_gf2n<uint32_t> a("7ffffffffe", "ffffffffff", 16);
        mp_gf2n<uint32_t> s = a >> 17;
        EXPECT(s.sizeinbase(2) == 22U);
        EXPECT(s.get_str(16) == "3fffff");
    },
    CASE("Right shift multi-word assignment - 32-bit")
    {
        mp_gf2n<uint32_t> a("7ffffffffe", "ffffffffff", 16);
        a >>= 17;
        EXPECT(a.sizeinbase(2) == 22U);
        EXPECT(a.get_str(16) == "3fffff");
    },
    CASE("Division simple - 32-bit")
    {
        mp_gf2n<uint32_t> a("4", "8041", 16);
        mp_gf2n<uint32_t> b("2", "8041", 16);
        mp_gf2n<uint32_t> s = a / b;
        mp_gf2n<uint32_t> t = s * b;
        EXPECT(t.get_str(16) == "4");
    },
    CASE("Division fractional - 32-bit")
    {
        mp_gf2n<uint32_t> a("3", "141", 16);
        mp_gf2n<uint32_t> b("65", "141", 16);
        mp_gf2n<uint32_t> s = a / b;
        mp_gf2n<uint32_t> t = s * b;
        EXPECT(t.get_str(16) == "3");
    }
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

