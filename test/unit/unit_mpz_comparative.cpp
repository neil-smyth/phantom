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
#include "core/mpz.hpp"

namespace phantom {
using namespace core;  // NOLINT

const lest::test specification[] =
{
    CASE("Equal - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        mpz<uint16_t> b(uint16_t(0xFFFF));
        bool compare = a == b;
        EXPECT(compare);
    },
    CASE("Equal free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x0000));
        mpz<uint16_t> b(uint16_t(0x0000));
        EXPECT(a == b);
    },
    CASE("Not Equal - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        mpz<uint16_t> b(uint16_t(0x0000));
        bool compare = a != b;
        EXPECT(compare);
    },
    CASE("Not Equal free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x0000));
        mpz<uint16_t> b(uint16_t(0xFFFF));
        EXPECT(a != b);
    },
    CASE("Less Than Or Equal - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x8000));
        mpz<uint16_t> b(uint16_t(0x8000));
        bool compare = a <= b;
        EXPECT(compare);
        a = uint16_t(0x7FFF);
        compare = a <= b;
        EXPECT(compare);
    },
    CASE("Less Than Or Equal free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x0000));
        mpz<uint16_t> b(uint16_t(0xFFFF));
        EXPECT(a <= b);
        b = uint16_t(0x0000);
        EXPECT(a <= b);
    },
    CASE("Less Than - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x7FFF));
        mpz<uint16_t> b(uint16_t(0x8000));
        bool compare = a < b;
        EXPECT(compare);
    },
    CASE("Less Than free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFE));
        mpz<uint16_t> b(uint16_t(0xFFFF));
        EXPECT(a < b);
    },
    CASE("Greater Than Or Equal - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x8000));
        mpz<uint16_t> b(uint16_t(0x8000));
        bool compare = a >= b;
        EXPECT(compare);
        b = uint16_t(0x7FFF);
        compare = a >= b;
        EXPECT(compare);
    },
    CASE("Greater Than Or Equal free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        mpz<uint16_t> b(uint16_t(0xFFFF));
        EXPECT(a >= b);
        b = uint16_t(0x0000);
        EXPECT(a >= b);
    },
    CASE("Greater Than - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x8000));
        mpz<uint16_t> b(uint16_t(0x7FFF));
        bool compare = a > b;
        EXPECT(compare);
    },
    CASE("Greater Than single-precision negative integers - 16-bit")
    {
        mpz<uint16_t> a(int16_t(-3));
        mpz<uint16_t> b(int16_t(-4));
        bool compare = a > b;
        EXPECT(compare);
    },
    CASE("Greater Than free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        mpz<uint16_t> b(uint16_t(0xFFFE));
        EXPECT(a > b);
    },

    CASE("Equal unsigned integer - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        uint16_t b(0xFFFF);
        bool equal = a == b;
        EXPECT(equal);
    },
    CASE("Equal unsigned integer free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x0000));
        uint16_t b(0x0000);
        EXPECT(a == b);
    },
    CASE("Not Equal unsigned integer - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        uint16_t b(0x0000);
        bool not_equal = a != b;
        EXPECT(not_equal);
    },
    CASE("Not Equal unsigned integer free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x0000));
        uint16_t b(0xFFFF);
        EXPECT(a != b);
    },
    CASE("Less Than Or Equal - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x8000));
        uint16_t b(0x8000);
        bool compare = a <= b;
        EXPECT(compare);
        a = uint16_t(0x7FFF);
        compare = a <= b;
        EXPECT(compare);
    },
    CASE("Less Than Or Equal free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x0000));
        uint16_t b(0xFFFF);
        EXPECT(a <= b);
        b = uint16_t(0x0000);
        EXPECT(a <= b);
    },
    CASE("Less Than - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x7FFF));
        uint16_t b(0x8000);
        bool compare = a < b;
        EXPECT(compare);
    },
    CASE("Less Than free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFE));
        uint16_t b(0xFFFF);
        EXPECT(a < b);
    },
    CASE("Greater Than Or Equal - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x8000));
        uint16_t b(0x8000);
        bool compare = a >= b;
        EXPECT(compare);
        b = uint16_t(0x7FFF);
        compare = a >= b;
        EXPECT(compare);
    },
    CASE("Greater Than Or Equal free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        uint16_t b(0xFFFF);
        EXPECT(a >= b);
        b = uint16_t(0x0000);
        EXPECT(a >= b);
    },
    CASE("Greater Than - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x8000));
        uint16_t b(0x7FFF);
        bool compare = a > b;
        EXPECT(compare);
    },
    CASE("Greater Than free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        uint16_t b(0xFFFE);
        EXPECT(a > b);
    },

    CASE("Equal signed integer - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x7FFF));
        int16_t b(0x7FFF);
        bool equal = a == b;
        EXPECT(equal);
    },
    CASE("Equal signed integer free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x0000));
        int16_t b(0x0000);
        EXPECT(a == b);
    },
    CASE("Not Equal signed integer - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        int16_t b(0x0000);
        bool not_equal = a != b;
        EXPECT(not_equal);
    },
    CASE("Not Equal signed integer free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x0000));
        int16_t b(0x7FFF);
        EXPECT(a != b);
    },
    CASE("Less Than Or Equal signed integer - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x4000));
        int16_t b(0x4000);
        bool compare = a <= b;
        EXPECT(compare);
        a = uint16_t(0x3FFF);
        compare = a <= b;
        EXPECT(compare);
    },
    CASE("Less Than Or Equal signed integer free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x0000));
        int16_t b(0x7FFF);
        EXPECT(a <= b);
        b = uint16_t(0x0000);
        EXPECT(a <= b);
    },
    CASE("Less Than signed integer - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x3FFF));
        int16_t b(0x4000);
        bool compare = a < b;
        EXPECT(compare);
    },
    CASE("Less Than signed integer free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x7FFE));
        int16_t b(0x7FFF);
        EXPECT(a < b);
    },
    CASE("Greater Than Or Equal signed integer - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x4000));
        int16_t b(0x4000);
        bool compare = a >= b;
        EXPECT(compare);
        b = uint16_t(0x3FFF);
        compare = a >= b;
        EXPECT(compare);
    },
    CASE("Greater Than Or Equal signed integer free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x7FFF));
        int16_t b(0x7FFF);
        EXPECT(a >= b);
        b = uint16_t(0x0000);
        EXPECT(a >= b);
    },
    CASE("Greater Than signed integer - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x4000));
        int16_t b(0x3FFF);
        bool compare = a > b;
        EXPECT(compare);
    },
    CASE("Greater Than signed integer free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x7FFF));
        int16_t b(0x7FFE);
        EXPECT(a > b);
    },

    CASE("Equal double - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x7FFF));
        double b(32767.0);
        EXPECT(static_cast<double>(a) == 32767.0);
        bool equal = a == b;
        EXPECT(equal);
    },
    CASE("Equal double free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x0000));
        double b(0.0);
        EXPECT(a == b);
    },
    CASE("Not Equal double - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        double b(0.0);
        bool not_equal = a != b;
        EXPECT(not_equal);
    },
    CASE("Not Equal double free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x0000));
        double b(32767.0);
        EXPECT(a != b);
    },
    CASE("Less Than Or Equal double - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x4000));
        double b(16384.0);
        bool compare = a <= b;
        EXPECT(compare);
        a = uint16_t(0x3FFF);
        compare = a <= b;
        EXPECT(compare);
    },
    CASE("Less Than Or Equal double free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x0000));
        double b(32767.0);
        EXPECT(a <= b);
        b = uint16_t(0x0000);
        EXPECT(a <= b);
    },
    CASE("Less Than double - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x3FFF));
        double b(16384.0);
        bool compare = a < b;
        EXPECT(compare);
    },
    CASE("Less Than double free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x7FFE));
        double b(32767.0);
        EXPECT(a < b);
    },
    CASE("Greater Than Or Equal double - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x4000));
        double b(16384.0);
        bool compare = a >= b;
        EXPECT(compare);
        b = uint16_t(0x3FFF);
        compare = a >= b;
        EXPECT(compare);
    },
    CASE("Greater Than Or Equal double free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x7FFF));
        double b(32767.0);
        EXPECT(a >= b);
        b = uint16_t(0x0000);
        EXPECT(a >= b);
    },
    CASE("Greater Than double - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x4000));
        double b(16383.0);
        bool compare = a > b;
        EXPECT(compare);
    },
    CASE("Greater Than double free function - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x7FFF));
        double b(32766.0);
        EXPECT(a > b);
    },
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

