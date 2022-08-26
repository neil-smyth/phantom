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
    CASE("addition with size increment - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        mpz<uint16_t> b(uint16_t(0x0001));
        mpz<uint16_t> s = a + b;
        EXPECT(s.sizeinbase(2) == 17U);
        EXPECT(s[1] == 0x0001);
        EXPECT(s[0] == 0x0000);
        EXPECT(s.is_negative() == false);
    },
    CASE("subtraction of smaller value - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        mpz<uint16_t> b(uint16_t(0x0001));
        mpz<uint16_t> s = a - b;
        EXPECT(s.sizeinbase(2) == 16U);
        EXPECT(s[0] == 0xFFFE);
        EXPECT(s.is_negative() == false);
    },
    CASE("subtraction of larger value - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x0001));
        mpz<uint16_t> b(uint16_t(0x0002));
        mpz<uint16_t> s = a - b;
        EXPECT(s.sizeinbase(2) == 1U);
        EXPECT(s[0] == 0x0001);
        EXPECT(s.is_negative() == true);
        EXPECT(static_cast<int16_t>(s) == int16_t(-1));
    },
    CASE("subtraction with size decrement - 16-bit")
    {
        uint8_t val[5] = {0, 0, 0, 0, 1};
        mpz<uint16_t> a(val, 5);
        mpz<uint16_t> b(uint16_t(0x0001));
        mpz<uint16_t> s = a - b;
        EXPECT(s[1] == 0xFFFF);
        EXPECT(s[0] == 0xFFFF);
        EXPECT(s.is_negative() == false);
    },
    CASE("addition of negative numbers - 16-bit")
    {
        mpz<uint16_t> a(int16_t(-1));
        mpz<uint16_t> b(int16_t(-3));
        mpz<uint16_t> s = a + b;
        EXPECT(s.sizeinbase(2) == 3U);
        EXPECT(s[0] == 0x0004);
        EXPECT(s.is_negative() == true);
        EXPECT(static_cast<int16_t>(s) == int16_t(-4));
    },
    CASE("addition of a signed integer - 16-bit")
    {
        mpz<uint16_t> a(int16_t(-1));
        int16_t b = -3;
        mpz<uint16_t> s = a + b;
        EXPECT(s.sizeinbase(2) == 3U);
        EXPECT(s[0] == 0x0004);
        EXPECT(s.is_negative() == true);
        EXPECT(static_cast<int16_t>(s) == int16_t(-4));
    },
    CASE("subtraction of a positive integer - 16-bit")
    {
        mpz<uint16_t> a(int16_t(-1));
        int16_t b = 3;
        mpz<uint16_t> s = a - b;
        EXPECT(s.sizeinbase(2) == 3U);
        EXPECT(s[0] == 0x0004);
        EXPECT(s.is_negative() == true);
        EXPECT(static_cast<int16_t>(s) == int16_t(-4));
    },
    CASE("subtraction of a negative integer - 16-bit")
    {
        mpz<uint16_t> a(int16_t(-1));
        int16_t b = -3;
        mpz<uint16_t> s = a - b;
        EXPECT(s.sizeinbase(2) == 2U);
        EXPECT(s[0] == 0x0002);
        EXPECT(s.is_negative() == false);
        EXPECT(static_cast<int16_t>(s) == int16_t(2));
    },
    CASE("Post-increment funtionality- 16-bit")
    {
        mpz<uint16_t> a(int16_t(-2));
        EXPECT(a++ == int16_t(-2));
        EXPECT(a == int16_t(-1));
    },
    CASE("Post-increment size growth- 16-bit")
    {
        uint8_t val[4] = {0xFF, 0xFF, 0xFF, 0xFF};
        uint8_t val2[5] = {0x00, 0x00, 0x00, 0x00, 0x01};
        mpz<uint16_t> a(val, 4);
        mpz<uint16_t> b(val, 4);
        mpz<uint16_t> r(val2, 5);
        EXPECT(a++ == b);
        EXPECT(a != b);
        EXPECT(a == r);
        EXPECT(a.sizeinbase(2) == 33U);
        EXPECT(b.sizeinbase(2) == 32U);
    },
    CASE("Post-increment values- 16-bit")
    {
        mpz<uint16_t> a(int16_t(-2));
        a++;
        EXPECT(a.sizeinbase(2) == 1U);
        EXPECT(a == int16_t(-1));
        EXPECT(a.is_negative() == true);
        a++;
        EXPECT(a.sizeinbase(2) == 1U);
        EXPECT(a == int16_t(0));
        EXPECT(a.is_negative() == false);
        a++;
        EXPECT(a.sizeinbase(2) == 1U);
        EXPECT(a == int16_t(1));
        EXPECT(a.is_negative() == false);
        a++;
        EXPECT(a.sizeinbase(2) == 2U);
        EXPECT(a == int16_t(2));
        EXPECT(a.is_negative() == false);
    },
    CASE("Pre-increment funtionality- 16-bit")
    {
        mpz<uint16_t> a(int16_t(-2));
        EXPECT(++a == int16_t(-1));
        EXPECT(a == int16_t(-1));
    },
    CASE("Pre-increment - 16-bit")
    {
        mpz<uint16_t> a(int16_t(-2));
        ++a;
        EXPECT(a.sizeinbase(2) == 1U);
        EXPECT(a == int16_t(-1));
        EXPECT(a.is_negative() == true);
        ++a;
        EXPECT(a.sizeinbase(2) == 1U);
        EXPECT(a == int16_t(0));
        EXPECT(a.is_negative() == false);
        ++a;
        EXPECT(a.sizeinbase(2) == 1U);
        EXPECT(a == int16_t(1));
        EXPECT(a.is_negative() == false);
        ++a;
        EXPECT(a.sizeinbase(2) == 2U);
        EXPECT(a == int16_t(2));
        EXPECT(a.is_negative() == false);
    },
    CASE("Pre-increment size growth - 16-bit")
    {
        uint8_t val[4] = {0xFF, 0xFF, 0xFF, 0xFF};
        uint8_t val2[5] = {0x00, 0x00, 0x00, 0x00, 0x01};
        mpz<uint16_t> a(val, 4);
        mpz<uint16_t> b(val, 4);
        mpz<uint16_t> r(val2, 5);
        EXPECT(++a != b);
        EXPECT(a == r);
        EXPECT(a.sizeinbase(2) == 33U);
        EXPECT(b.sizeinbase(2) == 32U);
    },
    CASE("Post-decrement funtionality - 16-bit")
    {
        mpz<uint16_t> a(int16_t(1));
        EXPECT(a-- == int16_t(1));
        EXPECT(a == int16_t(0));
        EXPECT(a-- == int16_t(0));
        EXPECT(a == int16_t(-1));
    },
    CASE("Pre-decrement size shrink - 16-bit")
    {
        uint8_t val[5] = {0x00, 0x00, 0x00, 0x00, 0x01};
        uint8_t val2[4] = {0xFF, 0xFF, 0xFF, 0xFF};
        mpz<uint16_t> a(val, 5);
        mpz<uint16_t> b(val, 5);
        mpz<uint16_t> r(val2, 4);
        EXPECT(--a == r);
        EXPECT(a != b);
        EXPECT(a.sizeinbase(2) == 32U);
        EXPECT(b.sizeinbase(2) == 33U);
    },
    CASE("Post-decrement values - 16-bit")
    {
        mpz<uint16_t> a(int16_t(2));
        a--;
        EXPECT(a.sizeinbase(2) == 1U);
        EXPECT(a == int16_t(1));
        EXPECT(a.is_negative() == false);
        a--;
        EXPECT(a.sizeinbase(2) == 1U);
        EXPECT(a == int16_t(0));
        EXPECT(a.is_negative() == false);
        a--;
        EXPECT(a.sizeinbase(2) == 1U);
        EXPECT(a == int16_t(-1));
        EXPECT(a.is_negative() == true);
        a--;
        EXPECT(a.sizeinbase(2) == 2U);
        EXPECT(a == int16_t(-2));
        EXPECT(a.is_negative() == true);
    },
    CASE("Pre-decrement funtionality - 16-bit")
    {
        mpz<uint16_t> a(int16_t(2));
        EXPECT(--a == int16_t(1));
        EXPECT(a == int16_t(1));
    },
    CASE("Pre-decrement - 16-bit")
    {
        mpz<uint16_t> a(int16_t(2));
        --a;
        EXPECT(a.sizeinbase(2) == 1U);
        EXPECT(a == int16_t(1));
        EXPECT(a.is_negative() == false);
        --a;
        EXPECT(a.sizeinbase(2) == 1U);
        EXPECT(a == int16_t(0));
        EXPECT(a.is_negative() == false);
        --a;
        EXPECT(a.sizeinbase(2) == 1U);
        EXPECT(a == int16_t(-1));
        EXPECT(a.is_negative() == true);
        --a;
        EXPECT(a.sizeinbase(2) == 2U);
        EXPECT(a == int16_t(-2));
        EXPECT(a.is_negative() == true);
    },
    CASE("Pre-decrement size shrink - 16-bit")
    {
        uint8_t val[5] = {0x00, 0x00, 0x00, 0x00, 0x01};
        uint8_t val2[4] = {0xFF, 0xFF, 0xFF, 0xFF};
        mpz<uint16_t> a(val, 5);
        mpz<uint16_t> b(val, 5);
        mpz<uint16_t> r(val2, 4);
        EXPECT(--a == r);
        EXPECT(a != b);
        EXPECT(a.sizeinbase(2) == 32U);
        EXPECT(b.sizeinbase(2) == 33U);
    },
    CASE("Negate - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(255));
        EXPECT(a == int16_t(255));
        a.negate();
        EXPECT(a == int16_t(-255));
    },
    CASE("Addition with modular Montgomery reduction - 16-bit")
    {
        mpz<uint16_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint16_t> a(uint16_t(0xFFFF));
        mpz<uint16_t> b(uint16_t(0x0001));

        mpz<uint16_t> temp, temp2, mu, R, R2, s, t;
        R2.setbit(16 * 12 * 2);
        R.setbit(16 * 12);
        mpz<uint16_t>::tdiv_qr(mu, temp, R2, m);
        R2 = temp;
        temp2 = m;

        mpz<uint16_t>::gcdext(temp, s, t, R, temp2);
        EXPECT(temp.get_limbsize() == 1U);
        EXPECT(temp == uint16_t(1));

        uint16_t mont_inv = 0;
        if (t.get_limbsize() > 0) {
            mont_inv = t.is_negative()? t[0] : -t[0];
        }

        mod_config<uint16_t> mod = { m, mu, m.sizeinbase(2), 12, 16, reduction_e::REDUCTION_MONTGOMERY, R2, mont_inv };

        mpz<uint16_t> one(uint16_t(1));
        a = a.mul_mont(R2, mod);
        b = b.mul_mont(R2, mod);
        a = a.add_mod(b, mod);
        a = a.mul_mont(one, mod);
        EXPECT(a.sizeinbase(2) == 17U);
        EXPECT(a[1] == 0x0001);
        EXPECT(a[0] == 0x0000);
        EXPECT(a.is_negative() == false);
    },
    CASE("Subtraction with modular Montgomery reduction - 16-bit")
    {
        mpz<uint16_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint16_t> a("0", 16);
        mpz<uint16_t> b(uint16_t(0x0001));

        mpz<uint16_t> temp, temp2, mu, R, R2, s, t;
        R2.setbit(16 * 12 * 2);
        R.setbit(16 * 12);
        mpz<uint16_t>::tdiv_qr(mu, temp, R2, m);
        R2 = temp;
        temp2 = m;

        mpz<uint16_t>::gcdext(temp, s, t, R, temp2);
        EXPECT(temp.get_limbsize() == 1U);
        EXPECT(temp == uint16_t(1));

        uint16_t mont_inv = 0;
        if (t.get_limbsize() > 0) {
            mont_inv = t.is_negative()? t[0] : -t[0];
        }

        mod_config<uint16_t> mod = { m, mu, m.sizeinbase(2), 12, 16, reduction_e::REDUCTION_MONTGOMERY, R2, mont_inv };

        mpz<uint16_t> one(uint16_t(1));
        a = a.mul_mont(R2, mod);
        b = b.mul_mont(R2, mod);
        a = a.sub_mod(b, mod);
        a = a.mul_mont(one, mod);
        EXPECT(a.sizeinbase(2) == 192U);
        EXPECT(a.get_str(16, true) == "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFE");
        EXPECT(a.is_negative() == false);
    },
    CASE("Addition with modular Montgomery reduction - 16-bit")
    {
        mpz<uint16_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint16_t> a("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFE", 16);
        mpz<uint16_t> b("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFE", 16);

        mpz<uint16_t> temp, temp2, mu, R, R2, s, t;
        R2.setbit(16 * 12 * 2);
        R.setbit(16 * 12);
        mpz<uint16_t>::tdiv_qr(mu, temp, R2, m);
        R2 = temp;
        temp2 = m;

        mpz<uint16_t>::gcdext(temp, s, t, R, temp2);
        EXPECT(temp.get_limbsize() == 1U);
        EXPECT(temp == uint16_t(1));

        uint16_t mont_inv = 0;
        if (t.get_limbsize() > 0) {
            mont_inv = t.is_negative()? t[0] : -t[0];
        }

        mod_config<uint16_t> mod = { m, mu, m.sizeinbase(2), 12, 16, reduction_e::REDUCTION_MONTGOMERY, R2, mont_inv };

        mpz<uint16_t> one(uint16_t(1));
        a = a.mul_mont(R2, mod);
        b = b.mul_mont(R2, mod);
        a = a.add_mod(b, mod);
        a = a.mul_mont(one, mod);
        EXPECT(a.sizeinbase(2) == 192U);
        EXPECT(a.get_str(16, true) == "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFD");
        EXPECT(a.is_negative() == false);
    },
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

