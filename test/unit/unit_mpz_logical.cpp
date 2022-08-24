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
    CASE("Instantiation from lower case hex prefix string - 16-bit")
    {
        mpz<uint16_t> a("0x0123456789abcdef", 16);
        EXPECT(a.sizeinbase(2) == 57);
        EXPECT(a[3] == uint16_t(0x0123));
        EXPECT(a[2] == uint16_t(0x4567));
        EXPECT(a[1] == uint16_t(0x89ab));
        EXPECT(a[0] == uint16_t(0xcdef));
        EXPECT(a.get_str(16) == "123456789abcdef");
    },
    CASE("Instantiation from upper case hex prefix string - 16-bit")
    {
        mpz<uint16_t> a("0x0123456789ABCDEF", 16);
        EXPECT(a.sizeinbase(2) == 57);
        EXPECT(a[3] == uint16_t(0x0123));
        EXPECT(a[2] == uint16_t(0x4567));
        EXPECT(a[1] == uint16_t(0x89ab));
        EXPECT(a[0] == uint16_t(0xcdef));
        EXPECT(a.get_str(16, true) == "123456789ABCDEF");
    },
    CASE("Instantiation from lower case hex upper prefix string - 16-bit")
    {
        mpz<uint16_t> a("0X0123456789abcdef", 16);
        EXPECT(a.sizeinbase(2) == 57);
        EXPECT(a[3] == uint16_t(0x0123));
        EXPECT(a[2] == uint16_t(0x4567));
        EXPECT(a[1] == uint16_t(0x89ab));
        EXPECT(a[0] == uint16_t(0xcdef));
        EXPECT(a.get_str(16) == "123456789abcdef");
    },
    CASE("Instantiation from lower case hex non-prefix string - 16-bit")
    {
        mpz<uint16_t> a("0123456789abcdef", 16);
        EXPECT(a.sizeinbase(2) == 57);
        EXPECT(a[3] == uint16_t(0x0123));
        EXPECT(a[2] == uint16_t(0x4567));
        EXPECT(a[1] == uint16_t(0x89ab));
        EXPECT(a[0] == uint16_t(0xcdef));
        EXPECT(a.get_str(16) == "123456789abcdef");
    },
    CASE("Instantiation from lower case binary non-prefix string - 16-bit")
    {
        mpz<uint16_t> a("1011001", 2);
        EXPECT(a.sizeinbase(2) == 7);
        EXPECT(a == uint16_t(0x59));
    },
    CASE("Instantiation from lower case binary negative string - 16-bit")
    {
        mpz<uint16_t> a("-111111111111111", 2);
        EXPECT(a.sizeinbase(2) == 15);
        EXPECT(a == int16_t(-0x7fff));
    },
    CASE("Instantiation from decimal negative string - 16-bit")
    {
        mpz<uint16_t> a("-32767", 10);
        EXPECT(a.sizeinbase(2) == 15);
        EXPECT(a == int16_t(-0x7fff));
    },
    CASE("Instantiation from decimal negative string - 16-bit")
    {
        mpz<uint16_t> a("100001", 10);
        EXPECT(a.sizeinbase(2) == 17);
        EXPECT(a[1] == uint16_t(0x0001));
        EXPECT(a[0] == uint16_t(0x86a1));
    },
    CASE("Instantiation from decimal negative string with leading zeros - 16-bit")
    {
        mpz<uint16_t> a("000000000000100001", 10);
        EXPECT(a.sizeinbase(2) == 17);
        EXPECT(a[1] == uint16_t(0x0001));
        EXPECT(a[0] == uint16_t(0x86a1));
        EXPECT(a.get_str(10) == "100001");
    },
    CASE("Instantiation from base32 - 16-bit")
    {
        mpz<uint16_t> a("AA======", 32);
        EXPECT(a.sizeinbase(2) == 1);
        EXPECT(a == uint16_t(0));
        EXPECT(a.get_str(32) == "AA======");
    },
    CASE("Instantiation from base32 - 16-bit")
    {
        mpz<uint16_t> a("AE======", 32);
        EXPECT(a.sizeinbase(2) == 1);
        EXPECT(a == uint16_t(1));
        EXPECT(a.get_str(32) == "AE======");
    },
    CASE("Instantiation from base32 - 16-bit")
    {
        mpz<uint16_t> a("AH77777774======", 32);
        EXPECT(a.sizeinbase(2) == 41);
        EXPECT(a[2] == uint16_t(0x1ff));
        EXPECT(a[1] == uint16_t(0xffff));
        EXPECT(a[0] == uint16_t(0xffff));
        EXPECT(a.get_str(32) == "AH77777774======");
    },
    CASE("Instantiation from base32 - 16-bit")
    {
        mpz<uint16_t> a("AH7777777777777777777777777Q====", 32);
        EXPECT(a.sizeinbase(2) == 129);
        EXPECT(a[8] == uint16_t(0x1));
        EXPECT(a[7] == uint16_t(0xffff));
        EXPECT(a[6] == uint16_t(0xffff));
        EXPECT(a[5] == uint16_t(0xffff));
        EXPECT(a[4] == uint16_t(0xffff));
        EXPECT(a[3] == uint16_t(0xffff));
        EXPECT(a[2] == uint16_t(0xffff));
        EXPECT(a[1] == uint16_t(0xffff));
        EXPECT(a[0] == uint16_t(0xffff));
        EXPECT(a.get_str(32) == "AH7777777777777777777777777Q====");
    },
    CASE("Instantiation from base64 - 16-bit")
    {
        mpz<uint16_t> a("AA==", 64);
        EXPECT(a.sizeinbase(2) == 1);
        EXPECT(a == uint16_t(0));
        EXPECT(a.get_str(64) == "AA==");
    },
    CASE("Instantiation from base64 - 16-bit")
    {
        mpz<uint16_t> a("AQ==", 64);
        EXPECT(a.sizeinbase(2) == 1);
        EXPECT(a == uint16_t(1));
        EXPECT(a.get_str(64) == "AQ==");
    },
    CASE("Instantiation from base64 - 16-bit")
    {
        mpz<uint16_t> a("Af//////", 64);
        EXPECT(a.sizeinbase(2) == 41);
        EXPECT(a[2] == uint16_t(0x1ff));
        EXPECT(a[1] == uint16_t(0xffff));
        EXPECT(a[0] == uint16_t(0xffff));
    },
    CASE("String output binary - 16-bit")
    {
        mpz<uint16_t> a("0x186a1", 16);
        EXPECT(a.sizeinbase(2) == 17);
        EXPECT(a.get_str(2) == "11000011010100001");
    },
    CASE("String output octal - 16-bit")
    {
        mpz<uint16_t> a("0x186a1", 16);
        EXPECT(a.sizeinbase(8) == 6);
        EXPECT(a.get_str(8) == "303241");
    },
    CASE("String output hexadecimal - 16-bit")
    {
        mpz<uint16_t> a("0x186a1", 16);
        EXPECT(a.sizeinbase(16) == 5);
        EXPECT(a.get_str(16) == "186a1");
    },
    CASE("String output decimal - 16-bit")
    {
        mpz<uint16_t> a("0", 10);
        EXPECT(a.sizeinbase(10) == 1);
        EXPECT(a.get_str(10) == "0");
    },
    CASE("String output decimal - 16-bit")
    {
        mpz<uint16_t> a("-1", 10);
        EXPECT(a.sizeinbase(10) == 1);
        EXPECT(a.get_str(10) == "-1");
    },
    CASE("String output decimal - 16-bit")
    {
        mpz<uint16_t> a("0x186a1", 16);
        EXPECT(a.sizeinbase(10) == 6);
        EXPECT(a.get_str(10) == "100001");
    },
    CASE("String output decimal - 16-bit")
    {
        mpz<uint16_t> a("123456789", 10);
        EXPECT(a.sizeinbase(10) == 9);
        EXPECT(a.get_str(10) == "123456789");
    },
    CASE("String output decimal - 16-bit")
    {
        mpz<uint16_t> a("0x1ffffffffffffffffffffffffffffffff", 16);
        EXPECT(a.sizeinbase(10) == 39);
        EXPECT(a.get_str(10) == "680564733841876926926749214863536422911");
    },
    CASE("String output base 32 - 16-bit")
    {
        mpz<uint16_t> a("0x186a1", 16);
        EXPECT(a.sizeinbase(32) == 8);
        EXPECT(a.get_str(32) == "AGDKC===");
    },
    CASE("String output base 32 - 16-bit")
    {
        mpz<uint16_t> a("0xFFFFFF", 16);
        EXPECT(a.sizeinbase(32) == 8);
        EXPECT(a.get_str(32) == "77776===");
    },
    CASE("String output base 32 - 16-bit")
    {
        mpz<uint16_t> a("0x1FFFFFFFFFF", 16);
        EXPECT(a.sizeinbase(32) == 16);
        EXPECT(a.get_str(32) == "AH77777774======");
    },
    CASE("String output base 32 - 16-bit")
    {
        mpz<uint16_t> a("0x1ffffffffffffffffffffffffffffffff", 16);
        EXPECT(a.sizeinbase(32) == 32);
        EXPECT(a.get_str(32) == "AH7777777777777777777777777Q====");
    },
    CASE("String output base 32 - 16-bit")
    {
        mpz<uint16_t> a("0x0", 16);
        EXPECT(a.sizeinbase(32) == 8);
        EXPECT(a.get_str(32) == "AA======");
    },
    CASE("String output base 32 - 16-bit")
    {
        mpz<uint16_t> a("0x1", 16);
        EXPECT(a.sizeinbase(32) == 8);
        EXPECT(a.get_str(32) == "AE======");
    },
    CASE("String output base 32 - 16-bit")
    {
        mpz<uint16_t> a("-1", 10);
        EXPECT(a.sizeinbase(32) == 8);
        EXPECT(a.get_str(32) == "-AE======");
    },
    CASE("String output base 64 - 16-bit")
    {
        mpz<uint16_t> a("0x0", 16);
        EXPECT(a.sizeinbase(64) == 4);
        EXPECT(a.get_str(64) == "AA==");
    },
    CASE("String output base 64 - 16-bit")
    {
        mpz<uint16_t> a("0x1", 16);
        EXPECT(a.sizeinbase(64) == 4);
        EXPECT(a.get_str(64) == "AQ==");
    },
    CASE("String output base 32 - 16-bit")
    {
        mpz<uint16_t> a("0x186a1", 16);
        EXPECT(a.sizeinbase(64) == 4);
        EXPECT(a.get_str(64) == "AYah");
    },
    CASE("String output base 32 - 16-bit")
    {
        mpz<uint16_t> a("0xFFFFFF", 16);
        EXPECT(a.sizeinbase(64) == 4);
        EXPECT(a.get_str(64) == "////");
    },
    CASE("String output base 32 - 16-bit")
    {
        mpz<uint16_t> a("0x1FFFFFFFFFF", 16);
        EXPECT(a.sizeinbase(64) == 8);
        EXPECT(a.get_str(64) == "Af//////");
    },
    CASE("String output base 32 - 16-bit")
    {
        mpz<uint16_t> a("0x1ffffffffffffffffffffffffffffffff", 16);
        EXPECT(a.sizeinbase(64) == 24);
        EXPECT(a.get_str(64) == "Af////////////////////8=");
    },
    CASE("AND zero - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0));
        mpz<uint16_t> b(uint16_t(0xFFFF));
        mpz<uint16_t> c = a & b;
        EXPECT(c == uint16_t(0));
        a = uint16_t(1);
        b = uint16_t(0);
        c = a & b;
        EXPECT(c == uint16_t(0));
    },
    CASE("AND single-precision - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        mpz<uint16_t> b(uint16_t(0x8001));
        mpz<uint16_t> c = a & b;
        EXPECT(c == uint16_t(0x8001));
    },
    CASE("AND multiple-precision - 16-bit")
    {
        uint8_t vala[9] = {0xFF, 0x55, 0xAA, 0xFF, 0x81, 0, 0xC3, 0, 1};
        uint8_t valb[7] = {0xAA, 0xFF, 0x55, 0xFF, 0xC3, 0, 0x81};
        mpz<uint16_t> a(vala, 9);
        mpz<uint16_t> b(valb, 7);
        mpz<uint16_t> c = a & b;
        EXPECT(c.sizeinbase(2) == 56);
        EXPECT(c[3] == 0x0081);
        EXPECT(c[2] == 0x0081);
        EXPECT(c[1] == 0xFF00);
        EXPECT(c[0] == 0x55AA);
        EXPECT(c.is_negative() == false);
    },
    CASE("AND EQUAL zero - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0));
        mpz<uint16_t> b(uint16_t(0xFFFF));
        a &= b;
        EXPECT(a == uint16_t(0));
    },
    CASE("AND EQUAL single-precision - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        mpz<uint16_t> b(uint16_t(0x8001));
        a &= b;
        EXPECT(a == uint16_t(0x8001));
    },
    CASE("AND EQUAL multiple-precision - 16-bit")
    {
        uint8_t vala[9] = {0xFF, 0x55, 0xAA, 0xFF, 0x81, 0, 0xC3, 0, 1};
        uint8_t valb[7] = {0xAA, 0xFF, 0x55, 0xFF, 0xC3, 0, 0x81};
        mpz<uint16_t> a(vala, 9);
        mpz<uint16_t> b(valb, 7);
        a &= b;
        EXPECT(a.sizeinbase(2) == 56);
        EXPECT(a[3] == 0x0081);
        EXPECT(a[2] == 0x0081);
        EXPECT(a[1] == 0xFF00);
        EXPECT(a[0] == 0x55AA);
        EXPECT(a.is_negative() == false);
    },
    CASE("OR zero - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0));
        mpz<uint16_t> b(uint16_t(0xFFFF));
        mpz<uint16_t> c = a | b;
        EXPECT(c == uint16_t(0xFFFF));
        a = uint16_t(0x8000);
        b = uint16_t(0);
        c = a | b;
        EXPECT(c == uint16_t(0x8000));
    },
    CASE("OR single-precision - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xF0FE));
        mpz<uint16_t> b(uint16_t(0x8001));
        mpz<uint16_t> c = a | b;
        EXPECT(c == uint16_t(0xF0FF));
    },
    CASE("OR multiple-precision - 16-bit")
    {
        uint8_t vala[9] = {0xFF, 0x55, 0xAA, 0xFF, 0x81, 0, 0xC3, 0, 1};
        uint8_t valb[7] = {0xAA, 0xFF, 0x55, 0xFF, 0xC3, 0, 0x81};
        mpz<uint16_t> a(vala, 9);
        mpz<uint16_t> b(valb, 7);
        mpz<uint16_t> c = a | b;
        EXPECT(c.sizeinbase(2) == 65);
        EXPECT(c[4] == 0x0001);
        EXPECT(c[3] == 0x00C3);
        EXPECT(c[2] == 0x00C3);
        EXPECT(c[1] == 0xFFFF);
        EXPECT(c[0] == 0xFFFF);
        EXPECT(c.is_negative() == false);
    },
    CASE("OR EQUAL zero - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0));
        mpz<uint16_t> b(uint16_t(0xFFFF));
        a |= b;
        EXPECT(a == uint16_t(0xFFFF));
    },
    CASE("OR EQUAL single-precision - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFF00));
        mpz<uint16_t> b(uint16_t(0x8001));
        a |= b;
        EXPECT(a == uint16_t(0xFF01));
    },
    CASE("OR EQUAL multiple-precision - 16-bit")
    {
        uint8_t vala[9] = {0xFF, 0x55, 0xAA, 0xFF, 0x81, 0, 0xC3, 0, 1};
        uint8_t valb[7] = {0xAA, 0xFF, 0x55, 0xFF, 0xC3, 0, 0x81};
        mpz<uint16_t> a(vala, 9);
        mpz<uint16_t> b(valb, 7);
        a |= b;
        EXPECT(a.sizeinbase(2) == 65);
        EXPECT(a[4] == 0x0001);
        EXPECT(a[3] == 0x00C3);
        EXPECT(a[2] == 0x00C3);
        EXPECT(a[1] == 0xFFFF);
        EXPECT(a[0] == 0xFFFF);
        EXPECT(a.is_negative() == false);
    },
    CASE("XOR zero - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0));
        mpz<uint16_t> b(uint16_t(0xFFFF));
        mpz<uint16_t> c = a ^ b;
        EXPECT(c == uint16_t(0xFFFF));
        a = uint16_t(0x8000);
        b = uint16_t(0);
        c = a ^ b;
        EXPECT(c == uint16_t(0x8000));
    },
    CASE("XOR single-precision - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xF0FE));
        mpz<uint16_t> b(uint16_t(0x8001));
        mpz<uint16_t> c = a ^ b;
        EXPECT(c == uint16_t(0x70FF));
    },
    CASE("XOR multiple-precision - 16-bit")
    {
        uint8_t vala[9] = {0xFF, 0x55, 0xAA, 0xFF, 0x81, 0, 0xC3, 0, 1};
        uint8_t valb[7] = {0xAA, 0xFF, 0x55, 0xFF, 0xC3, 0, 0x81};
        mpz<uint16_t> a(vala, 9);
        mpz<uint16_t> b(valb, 7);
        mpz<uint16_t> c = a ^ b;
        EXPECT(c.sizeinbase(2) == 65);
        EXPECT(c[4] == 0x0001);
        EXPECT(c[3] == 0x0042);
        EXPECT(c[2] == 0x0042);
        EXPECT(c[1] == 0x00FF);
        EXPECT(c[0] == 0xAA55);
        EXPECT(c.is_negative() == false);
    },
    CASE("XOR EQUAL zero - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0));
        mpz<uint16_t> b(uint16_t(0xFFFF));
        a ^= b;
        EXPECT(a == uint16_t(0xFFFF));
    },
    CASE("XOR EQUAL single-precision - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFF00));
        mpz<uint16_t> b(uint16_t(0x8001));
        a ^= b;
        EXPECT(a == uint16_t(0x7F01));
    },
    CASE("XOR EQUAL multiple-precision - 16-bit")
    {
        uint8_t vala[9] = {0xFF, 0x55, 0xAA, 0xFF, 0x81, 0, 0xC3, 0, 1};
        uint8_t valb[7] = {0xAA, 0xFF, 0x55, 0xFF, 0xC3, 0, 0x81};
        mpz<uint16_t> a(vala, 9);
        mpz<uint16_t> b(valb, 7);
        a ^= b;
        EXPECT(a.sizeinbase(2) == 65);
        EXPECT(a[4] == 0x0001);
        EXPECT(a[3] == 0x0042);
        EXPECT(a[2] == 0x0042);
        EXPECT(a[1] == 0x00FF);
        EXPECT(a[0] == 0xAA55);
        EXPECT(a.is_negative() == false);
    },
    CASE("RSHIFT zero - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        a = a >> 0;
        EXPECT(a == uint16_t(0xFFFF));
    },
    CASE("RSHIFT multi zero - 16-bit")
    {
        mpz<uint16_t> a("ffffffffff", 16);
        a = a >> 0;
        EXPECT(a.get_str(16) == "ffffffffff");
    },
    CASE("RSHIFT one - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        a = a >> 1;
        EXPECT(a == uint16_t(0x7FFF));
    },
    CASE("RSHIFT multi one - 16-bit")
    {
        mpz<uint16_t> a("ffffffffff", 16);
        a = a >> 1;
        EXPECT(a.get_str(16) == "7fffffffff");
    },
    CASE("RSHIFT 17 - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        a = a >> 17;
        EXPECT(a == uint16_t(0));
    },
    CASE("RSHIFT multi 17 - 16-bit")
    {
        mpz<uint16_t> a("ffffffffff", 16);
        a = a >> 17;
        EXPECT(a.get_str(16) == "7fffff");
    },
    CASE("RSHIFT EQUAL zero - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        a >>= 0;
        EXPECT(a == uint16_t(0xFFFF));
    },
    CASE("RSHIFT EQUAL multi zero - 16-bit")
    {
        mpz<uint16_t> a("ffffffffff", 16);
        a >>= 0;
        EXPECT(a.get_str(16) == "ffffffffff");
    },
    CASE("RSHIFT EQUAL one - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        a >>= 1;
        EXPECT(a == uint16_t(0x7FFF));
    },
    CASE("RSHIFT EQUAL multi one - 16-bit")
    {
        mpz<uint16_t> a("ffffffffff", 16);
        a >>= 1;
        EXPECT(a.get_str(16) == "7fffffffff");
    },
    CASE("RSHIFT EQUAL 17 - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        a >>= 17;
        EXPECT(a == uint16_t(0));
    },
    CASE("RSHIFT EQUAL multi 17 - 16-bit")
    {
        mpz<uint16_t> a("ffffffffff", 16);
        a >>= 17;
        EXPECT(a.get_str(16) == "7fffff");
    },
    CASE("LSHIFT zero - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        a = a << 0;
        EXPECT(a == uint16_t(0xFFFF));
    },
    CASE("LSHIFT multi zero - 16-bit")
    {
        mpz<uint16_t> a("ffffffffff", 16);
        a = a << 0;
        EXPECT(a.get_str(16) == "ffffffffff");
    },
    CASE("LSHIFT one - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        a = a << 1;
        EXPECT(a.get_str(16) == "1fffe");
    },
    CASE("LSHIFT multi one - 16-bit")
    {
        mpz<uint16_t> a("ffffffffff", 16);
        a = a << 1;
        EXPECT(a.get_str(16) == "1fffffffffe");
    },
    CASE("LSHIFT 17 - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        a = a << 17;
        EXPECT(a.get_str(16) == "1fffe0000");
    },
    CASE("LSHIFT multi 17 - 16-bit")
    {
        mpz<uint16_t> a("ffffffffff", 16);
        a = a << 17;
        EXPECT(a.get_str(16) == "1fffffffffe0000");
    },
    CASE("LSHIFT EQUAL zero - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        a <<= 0;
        EXPECT(a == uint16_t(0xFFFF));
    },
    CASE("LSHIFT EQUAL multi zero - 16-bit")
    {
        mpz<uint16_t> a("ffffffffff", 16);
        a <<= 0;
        EXPECT(a.get_str(16) == "ffffffffff");
    },
    CASE("LSHIFT EQUAL one - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        a <<= 1;
        EXPECT(a.get_str(16) == "1fffe");
    },
    CASE("LSHIFT EQUAL multi one - 16-bit")
    {
        mpz<uint16_t> a("ffffffffff", 16);
        a <<= 1;
        EXPECT(a.get_str(16) == "1fffffffffe");
    },
    CASE("LSHIFT EQUAL 17 - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        a <<= 17;
        EXPECT(a.get_str(16) == "1fffe0000");
    },
    CASE("LSHIFT EQUAL multi 17 - 16-bit")
    {
        mpz<uint16_t> a("ffffffffff", 16);
        a <<= 17;
        EXPECT(a.get_str(16) == "1fffffffffe0000");
    },
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

