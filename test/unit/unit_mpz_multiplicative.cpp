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
#include "ecc/secp_mpz.hpp"

namespace phantom {
using namespace core;      // NOLINT
using namespace elliptic;  // NOLINT

const lest::test specification[] =
{
    CASE("multiplication without size increment - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        mpz<uint16_t> b(uint16_t(1));
        mpz<uint16_t> s = a * b;
        EXPECT(s.sizeinbase(2) == 16U);
        EXPECT(s[0] == 0xFFFF);
        EXPECT(s.is_negative() == false);
    },
    CASE("multiplication with size increment - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        mpz<uint16_t> b(uint16_t(2));
        mpz<uint16_t> s = a * b;
        EXPECT(s.sizeinbase(2) == 17U);
        EXPECT(s[1] == 0x0001);
        EXPECT(s[0] == 0xFFFE);
        EXPECT(s.is_negative() == false);
    },
    CASE("multiplication by squaring - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        mpz<uint16_t> b(uint16_t(0xFFFF));
        mpz<uint16_t> s = a * b;
        EXPECT(s.sizeinbase(2) == 32U);
        EXPECT(s[1] == 0xFFFE);
        EXPECT(s[0] == 0x0001);
        EXPECT(s.is_negative() == false);
    },
    CASE("multiplication by zero - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        mpz<uint16_t> b(uint16_t(0));
        mpz<uint16_t> s = a * b;
        EXPECT(s.sizeinbase(2) == 1U);
        EXPECT(s == uint16_t(0));
        EXPECT(s.is_negative() == false);
    },
    CASE("multiplication by unsigned integer - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        uint16_t b = 3;
        mpz<uint16_t> s = a * b;
        EXPECT(s.sizeinbase(2) == 18U);
        EXPECT(s[1] == 0x0002);
        EXPECT(s[0] == 0xFFFD);
        EXPECT(s.is_negative() == false);
    },
    CASE("multiplication by negative signed integer - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        int16_t b = -3;
        mpz<uint16_t> s = a * b;
        EXPECT(s.sizeinbase(2) == 18U);
        EXPECT(s[1] == 0x0002);
        EXPECT(s[0] == 0xFFFD);
        EXPECT(s.is_negative() == true);
    },
    CASE("multiplication by positive signed integer - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        int16_t b = 3;
        mpz<uint16_t> s = a * b;
        EXPECT(s.sizeinbase(2) == 18U);
        EXPECT(s[1] == 0x0002);
        EXPECT(s[0] == 0xFFFD);
        EXPECT(s.is_negative() == false);
    },
    CASE("multiplication by double - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0xFFFF));
        double b = 3.5;
        mpz<uint16_t> s = a * b;
        EXPECT(s.sizeinbase(2) == 18U);
        EXPECT(s[1] == 0x0002);
        EXPECT(s[0] == 0xFFFD);
        EXPECT(s.is_negative() == false);
    },
    CASE("exp() with 0.2^1 - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0));
        mpz<uint16_t> s;
        s = a.mul_2exp(1);
        EXPECT(s.sizeinbase(2) == 1U);
        bool equal = s == uint16_t(0);
        EXPECT(equal);
        EXPECT(s == uint16_t(0));
        EXPECT(s.is_negative() == false);
    },
    CASE("exp() with 2.2^0 - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x0002));
        mpz<uint16_t> s;
        s = a.mul_2exp(0);
        EXPECT(s.sizeinbase(2) == 2U);
        EXPECT(s[0] == 2);
        EXPECT(s.is_negative() == false);
    },
    CASE("exp() with 2.2^3 - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x0002));
        mpz<uint16_t> s;
        s = a.mul_2exp(3);
        EXPECT(s.sizeinbase(2) == 5U);
        EXPECT(s[0] == 16);
        EXPECT(s.is_negative() == false);
    },
    CASE("exp() with -2.2^3 - 16-bit")
    {
        mpz<uint16_t> a(int16_t(-2));
        mpz<uint16_t> s;
        s = a.mul_2exp(3);
        EXPECT(s.sizeinbase(2) == 5U);
        EXPECT(s[0] == 16);
        EXPECT(s.is_negative() == true);
    },
    CASE("Square root of 0 - 16-bit")
    {
        mpz<uint16_t> a;
        mpz<uint16_t> r = a.sqrt();
        EXPECT(r.sizeinbase(2) == 1U);
        bool equal = r == uint16_t(0);
        EXPECT(equal);
        EXPECT(r == uint16_t(0));
        EXPECT(r.is_negative() == false);
    },
    CASE("Square root of -1 - 16-bit")
    {
        mpz<uint16_t> a(int16_t(-1));
        mpz<uint16_t> r = a.sqrt();
        EXPECT(r.sizeinbase(2) == 1U);
        bool equal = r == uint16_t(0);
        EXPECT(equal);
        EXPECT(r == uint16_t(0));
        EXPECT(r.is_negative() == false);
    },
    CASE("Square root of 16384 - 16-bit")
    {
        mpz<uint16_t> a(int16_t(16384));
        mpz<uint16_t> r = a.sqrt();
        EXPECT(r.sizeinbase(2) == 8U);
        EXPECT(r[0] == 128);
        EXPECT(r.is_negative() == false);
    },
    CASE("Square root of 0x100000000 - 16-bit")
    {
        uint8_t val[9] = {0, 0, 0, 0, 0, 0, 0, 0, 1};
        mpz<uint16_t> a(val, 9);
        mpz<uint16_t> r = a.sqrt();
        EXPECT(r.sizeinbase(2) == 33U);
        EXPECT(r[2] == 1);
        EXPECT(r[1] == 0);
        EXPECT(r[0] == 0);
        EXPECT(r.is_negative() == false);
    },
    CASE("Square root of -0x100000000 - 16-bit")
    {
        uint8_t val[9] = {0, 0, 0, 0, 0, 0, 0, 0, 1};
        mpz<uint16_t> a(val, 9);
        a.negate();
        mpz<uint16_t> r = a.sqrt();
        EXPECT(r.sizeinbase(2) == 1U);
        bool equal = r == uint16_t(0);
        EXPECT(equal);
        EXPECT(r == uint16_t(0));
        EXPECT(r.is_negative() == false);
    },
    CASE("Modular Square root of 16 - 16-bit")
    {
        mpz<uint16_t> a("10", 16);
        mpz<uint16_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint16_t> temp, mu;
        temp.setbit(16 *  12 * 2);
        mpz<uint16_t>::tdiv_q(mu, temp, m);

        mod_config<uint16_t> mod = { m, mu, m.sizeinbase(2), 12, 16, reduction_e::REDUCTION_BARRETT, mpz<uint16_t>(uint16_t(0)), 0, nullptr };

        mpz<uint16_t> r = a.sqrt_mod(mod);
        EXPECT(r.get_str(16) == "4");
        EXPECT(r.is_negative() == false);
    },
    CASE("Modular Square root of 2^128 - 16-bit")
    {
        mpz<uint16_t> a("FFFFFFFFFFFFFFF500000000006789000000000000001234", 16);
        mpz<uint16_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint16_t> temp, mu, b;
        temp.setbit(16 *  12 * 2);
        mpz<uint16_t>::tdiv_q(mu, temp, m);

        mod_config<uint16_t> mod = { m, mu, m.sizeinbase(2), 12, 16, reduction_e::REDUCTION_BARRETT, mpz<uint16_t>(uint16_t(0)), 0, nullptr };

        b = a.square_mod(mod);
        mpz<uint16_t> r = a.sqrt_mod(mod);
        mpz<uint16_t> r2 = r.square_mod(mod);
        EXPECT(r.get_str(16) == b.get_str(16));
        EXPECT(r.is_negative() == false);
    },
    CASE("2^12 - 16-bit")
    {
        mpz<uint16_t> a(int16_t(2));
        mpz<uint16_t> r = a.pow(12);
        EXPECT(r.sizeinbase(2) == 13U);
        bool equal = r == uint16_t(4096);
        EXPECT(equal);
        EXPECT(r == uint16_t(4096));
        EXPECT(r.is_negative() == false);
    },
    CASE("2^32 - 16-bit")
    {
        mpz<uint16_t> a(int16_t(2));
        mpz<uint16_t> r = a.pow(32);
        EXPECT(r.sizeinbase(2) == 33U);
        EXPECT(r[2] == uint16_t(1));
        EXPECT(r[1] == uint16_t(0));
        EXPECT(r[0] == uint16_t(0));
        EXPECT(r.is_negative() == false);
    },
    CASE("2^192 multiple-precision - 16-bit")
    {
        mpz<uint16_t> a(int16_t(2));
        mpz<uint16_t> b("192", 10);
        mpz<uint16_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint16_t> temp, mu;
        temp.setbit(16 *  12 * 2);
        mpz<uint16_t>::tdiv_q(mu, temp, m);

        mod_config<uint16_t> mod = { m, mu, m.sizeinbase(2), 12, 16, reduction_e::REDUCTION_BARRETT, mpz<uint16_t>(uint16_t(0)), 0, nullptr };

        mpz<uint16_t> r = a.pow_mod(b, mod);
        EXPECT(r.sizeinbase(2) == 65U);
        EXPECT(r.get_str(16) == "10000000000000001");
        EXPECT(r.is_negative() == false);
    },
    CASE("Exponentiation bug (a^b mod m == m-1) - 32-bit")
    {
        mpz<uint32_t> a("12945691313522123041986096672773446001405320837818255327"
                        "67565776783098523490134484961030662423105172728753008119"
                        "51068692189889731211177164307804606528856274613159947644"
                        "81786589382974203722414310292011195619500696129156773636"
                        "70492754494073655869082134359382463630469798196976104445"
                        "30781953044196108094240471122", 10);
        mpz<uint32_t> b("75296123376883313372540145968109024467662600265514720742"
                        "78396146714854872377436224354171048204231655273683603484"
                        "19676866210009275443167008784568978199247011253337255471"
                        "91960317838387317974177299106690233961945661398807694262"
                        "85571469282299739452858948897914658245325179439576887341"
                        "8417854053555201377271475459", 10);
        mpz<uint32_t> m("15059224675376662674508029193621804893532520053102944148"
                        "55679229342970974475487244870834209640846331054736720696"
                        "83935373242001855088633401756913795639849402250667451094"
                        "38392063567677463594835459821338046792389132279761538852"
                        "57114293856459947890571789779582931649065035887915377468"
                        "36835708107110402754542950919", 10);
        mpz<uint32_t> temp, mu;
        temp.setbit(32 * 32 * 2);
        mpz<uint32_t>::tdiv_q(mu, temp, m);

        mod_config<uint32_t> mod = { m, mu, m.sizeinbase(2), 32, 32, reduction_e::REDUCTION_BARRETT, mpz<uint32_t>(uint32_t(0)), 0, nullptr };

        mpz<uint32_t> r = a.pow_mod(b, mod);
        EXPECT(r.sizeinbase(2) == 1024U);
        EXPECT(r.get_str(10) == "15059224675376662674508029193621804893532520053102944148"
                                "55679229342970974475487244870834209640846331054736720696"
                                "83935373242001855088633401756913795639849402250667451094"
                                "38392063567677463594835459821338046792389132279761538852"
                                "57114293856459947890571789779582931649065035887915377468"
                                "36835708107110402754542950918");
        EXPECT(r.is_negative() == false);
    },
    CASE("Division quotient by unsigned integer - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x0100));
        uint16_t b = 2;
        mpz<uint16_t> s = a / b;
        EXPECT(s.sizeinbase(2) == 8U);
        EXPECT(s[0] == 0x0080);
        EXPECT(s.is_negative() == false);
    },
    CASE("Division quotient by unsigned integer - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x0100));
        mpz<uint16_t> b(uint16_t(0x0101));
        mpz<uint16_t> s = a / b;
        EXPECT(s.sizeinbase(2) == 1U);
        EXPECT(s == uint16_t(0));
        EXPECT(s.is_negative() == false);
    },
    CASE("Division quotient of positive number - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x0100));
        mpz<uint16_t> b(uint16_t(0x0101));
        mpz<uint16_t> s = a / b;
        EXPECT(s.sizeinbase(2) == 1U);
        bool equal = s == uint16_t(0);
        EXPECT(equal);
        EXPECT(s == uint16_t(0));
        EXPECT(s.is_negative() == false);
    },
    CASE("Division quotient of negative number with 0 result - 16-bit")
    {
        mpz<uint16_t> a(int16_t(-0x0100));
        mpz<uint16_t> b(uint16_t(0x0101));
        mpz<uint16_t> s = a / b;
        EXPECT(s.sizeinbase(2) == 1U);
        bool equal = s == uint16_t(0);
        EXPECT(equal);
        EXPECT(s == uint16_t(0));
        EXPECT(s.is_negative() == true);
    },
    CASE("Division quotient of negative number with negative result - 16-bit")
    {
        mpz<uint16_t> a(int16_t(-0x0200));
        mpz<uint16_t> b(uint16_t(0x0101));
        mpz<uint16_t> s = a / b;
        EXPECT(s.sizeinbase(2) == 1U);
        EXPECT(s[0] == 1);
        bool equal = s == int16_t(-1);
        EXPECT(equal);
        EXPECT(s == int16_t(-1));
        EXPECT(s.is_negative() == true);
    },
    CASE("Division remainder by unsigned integer - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x0100));
        uint16_t b = 3;
        mpz<uint16_t> s = a % b;
        EXPECT(s.sizeinbase(2) == 1U);
        bool equal = s == int16_t(1);
        EXPECT(equal);
        EXPECT(s == int16_t(1));
        EXPECT(s.is_negative() == false);
    },
    CASE("Division remainder of positive number - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x0100));
        mpz<uint16_t> b(uint16_t(0x0101));
        mpz<uint16_t> s = a % b;
        EXPECT(s.sizeinbase(2) == 9U);
        bool equal = s == uint16_t(0x0100);
        EXPECT(equal);
        EXPECT(s == uint16_t(0x0100));
        EXPECT(s.is_negative() == false);
    },
    CASE("GCD zero LHS - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0));
        mpz<uint16_t> b(uint16_t(1));
        mpz<uint16_t> s = a.gcd(b);
        EXPECT(s.sizeinbase(2) == 1U);
        EXPECT(s == uint16_t(1));
        EXPECT(s.is_negative() == false);
    },
    CASE("GCD zero RHS - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(3));
        mpz<uint16_t> b(uint16_t(0));
        mpz<uint16_t> s = a.gcd(b);
        EXPECT(s.sizeinbase(2) == 2U);
        EXPECT(s == uint16_t(3));
        EXPECT(s.is_negative() == false);
    },
    CASE("GCD single-precision - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(0x6666));
        mpz<uint16_t> b(uint16_t(0x2222));
        mpz<uint16_t> s = a.gcd(b);
        EXPECT(s.sizeinbase(2) == 14U);
        EXPECT(s == uint16_t(0x2222));
        EXPECT(s.is_negative() == false);
    },
    CASE("GCD multiple-precision - 16-bit")
    {
        uint8_t vala[8] = {0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66};
        mpz<uint16_t> a(vala, 8);
        uint8_t valb[4] = {0x22, 0x22, 0x22, 0x22};
        mpz<uint16_t> b(valb, 4);
        mpz<uint16_t> s = a.gcd(b);
        EXPECT(s.sizeinbase(2) == 30U);
        EXPECT(s[1] == uint16_t(0x2222));
        EXPECT(s[0] == uint16_t(0x2222));
        EXPECT(s.is_negative() == false);
    },
    CASE("GCD small - 16-bit")
    {
        uint8_t vala[8] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80};
        mpz<uint16_t> a(vala, 8);
        uint8_t valb[4] = {0x01, 0x00, 0x00, 0x80};
        mpz<uint16_t> b(valb, 4);
        mpz<uint16_t> s = a.gcd(b);
        EXPECT(s.sizeinbase(2) == 2U);
        EXPECT(s[0] == uint16_t(3));
        EXPECT(s.is_negative() == false);
    },
    CASE("GCD doesn't exist - 16-bit")
    {
        uint8_t vala[8] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80};
        mpz<uint16_t> a(vala, 8);
        uint8_t valb[4] = {0x01, 0x00, 0x00, 0x81};
        mpz<uint16_t> b(valb, 4);
        mpz<uint16_t> s = a.gcd(b);
        EXPECT(s.sizeinbase(2) == 1U);
        EXPECT(s[0] == uint16_t(1));
        EXPECT(s.is_negative() == false);
    },
    CASE("Extended Euclidean GCD single - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(55));
        mpz<uint16_t> b(uint16_t(25));
        mpz<uint16_t> g, s, t;
        mpz<uint16_t>::gcdext(g, s, t, a, b);
        EXPECT(g == uint16_t(5));
        EXPECT(s[0] == int16_t(1));
        EXPECT(t[0] == int16_t(2));
    },
    CASE("Extended Euclidean GCD single swapped - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(25));
        mpz<uint16_t> b(uint16_t(55));
        mpz<uint16_t> g, s, t;
        mpz<uint16_t>::gcdext(g, s, t, a, b);
        EXPECT(g == uint16_t(5));
        EXPECT(s == int16_t(-2));
        EXPECT(t == uint16_t(1));
    },
    CASE("Extended Euclidean GCD multiple - 16-bit")
    {
        uint8_t vala[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 25};
        mpz<uint16_t> a(vala, 6);
        uint8_t valb[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 55};
        mpz<uint16_t> b(valb, 6);
        mpz<uint16_t> g, s, t;
        mpz<uint16_t>::gcdext(g, s, t, a, b);
        EXPECT(g.sizeinbase(2) == 43U);
        EXPECT(s.sizeinbase(2) == 2U);
        EXPECT(t.sizeinbase(2) == 1U);
        EXPECT(g[2] == uint16_t(0x0500));
        EXPECT(g[1] == uint16_t(0x0000));
        EXPECT(g[0] == uint16_t(0x0000));
        EXPECT(s == int16_t(-2));
        EXPECT(t == uint16_t(1));
    },
    CASE("Extended Euclidean GCD multple signed - 16-bit")
    {
        uint8_t vala[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 25};
        mpz<uint16_t> a(vala, 6);
        uint8_t valb[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 55};
        mpz<uint16_t> b(valb, 6);
        b.set_sign(true);
        mpz<uint16_t> g, s, t;
        mpz<uint16_t>::gcdext(g, s, t, a, b);
        EXPECT(g.sizeinbase(2) == 43U);
        EXPECT(s.sizeinbase(2) == 2U);
        EXPECT(t.sizeinbase(2) == 1U);
        EXPECT(g[2] == uint16_t(0x0500));
        EXPECT(g[1] == uint16_t(0x0000));
        EXPECT(g[0] == uint16_t(0x0000));
        EXPECT(s == int16_t(-2));
        EXPECT(t == int16_t(-1));
    },
    CASE("Modular multiplicative inverse single failure - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(55));
        mpz<uint16_t> b(uint16_t(25));
        mpz<uint16_t> inv;
        bool success = mpz<uint16_t>::invert(inv, a, b);
        EXPECT(success == false);
    },
    CASE("Modular multiplicative inverse single - 16-bit")
    {
        mpz<uint16_t> a(uint16_t(55));
        mpz<uint16_t> b(uint16_t(7));
        mpz<uint16_t> inv;
        bool success = mpz<uint16_t>::invert(inv, a, b);
        EXPECT(success == true);
        EXPECT(inv.sizeinbase(2) == 3U);
        EXPECT(inv == uint16_t(6));
    },
    CASE("Modular multiplicative inverse multiple - 16-bit")
    {
        uint8_t vala[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 55};
        mpz<uint16_t> a(vala, 6);
        mpz<uint16_t> b(uint16_t(7));
        mpz<uint16_t> inv;
        bool success = mpz<uint16_t>::invert(inv, a, b);
        EXPECT(success == true);
        EXPECT(inv.sizeinbase(2) == 2U);
        EXPECT(inv == uint16_t(3));
    },
    CASE("Modular multiplicative inverse full - 16-bit")
    {
        uint8_t vala[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 55};
        mpz<uint16_t> a(vala, 6);
        uint8_t valb[6] = {0x01, 0x00, 0x00, 0x00, 0x00, 1};
        mpz<uint16_t> m(valb, 6);
        mpz<uint16_t> inv;
        bool success = mpz<uint16_t>::invert(inv, a, m);
        EXPECT(success == true);
        EXPECT(inv.sizeinbase(2) == 40U);
        EXPECT(inv[2] == uint16_t(0x0082));
        EXPECT(inv[1] == uint16_t(0x53C8));
        EXPECT(inv[0] == uint16_t(0x253D));

        mpz<uint16_t> temp, mu;
        mpz<uint16_t>::tdiv_q(mu, temp, m);
        mod_config<uint16_t> mod = { m, mu, m.sizeinbase(2), 12, 16, reduction_e::REDUCTION_NAIVE, mpz<uint16_t>(uint16_t(0)), 0, nullptr };

        mpz<uint16_t> c = (a * inv).mod(mod);
        mpz<uint16_t> scale = (a * inv).mod(mod);
        for (size_t i=(scale.sizeinbase(2)+15) >> 4; --i > 0; ) {
            std::cout << std::hex << " " << scale[i] << std::endl;
        }
        EXPECT(c == uint16_t(1));
    },
    CASE("Modular multiplicative inverse full - 16-bit")
    {
        mpz<uint16_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint16_t> x2("DAFEBF5828783F2AD35534631588A3F629A70FB16982A888", 16);
        mpz<uint16_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint16_t> inv;
        bool success = mpz<uint16_t>::invert(inv, x2 - x1, m);
        EXPECT(success == true);

        mpz<uint16_t> temp, mu;
        mpz<uint16_t>::tdiv_q(mu, temp, m);
        mod_config<uint16_t> mod = { m, mu, m.sizeinbase(2), 12, 16, reduction_e::REDUCTION_NAIVE, mpz<uint16_t>(uint16_t(0)), 0, nullptr };

        mpz<uint16_t> c = ((x2 - x1) * inv).mod(mod);
        EXPECT(c == uint16_t(1));
    },
    CASE("Mod 2^k - 16-bit")
    {
        mpz<uint16_t> a("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000", 16);
        mpz<uint16_t> b = a.mod_2exp(192);
        EXPECT(b.sizeinbase(2) == 192U);
        EXPECT(b == a);
    },
    CASE("Mod 2^k - 16-bit")
    {
        mpz<uint16_t> a("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000", 16);
        mpz<uint16_t> b = a.mod_2exp(65);
        EXPECT(b.sizeinbase(2) == 65U);
        EXPECT(b.get_str(16) == "10000000000000000");
    },
    CASE("Mod 2^k - 16-bit")
    {
        mpz<uint16_t> a("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000", 16);
        mpz<uint16_t> b = a.mod_2exp(6);
        EXPECT(b.sizeinbase(2) == 1U);
        EXPECT(b == uint16_t(0));
    },
    CASE("Barrett reduction - 16-bit")
    {
        mpz<uint16_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint16_t> a("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000", 16);
        mpz<uint16_t> temp, mu;
        temp.setbit(16 * 12 * 2);
        mpz<uint16_t>::tdiv_q(mu, temp, m);

        mod_config<uint16_t> mod = { m, mu, m.sizeinbase(2), 12, 16, reduction_e::REDUCTION_BARRETT, mpz<uint16_t>(uint16_t(0)), 0, nullptr };
        mpz<uint16_t> b = a.barrett(mod);
        EXPECT(b.sizeinbase(2) == 1U);
        EXPECT(b == uint16_t(1));
    },
    CASE("Barrett reduction - 16-bit")
    {
        mpz<uint16_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint16_t> a("10000000000000000000000000000000000000000000000000", 16);
        mpz<uint16_t> temp, mu;
        temp.setbit(16 *  12 * 2);
        mpz<uint16_t>::tdiv_q(mu, temp, m);

        a = a * m - uint16_t(1);
        mod_config<uint16_t> mod = { m, mu, m.sizeinbase(2), 12, 16, reduction_e::REDUCTION_BARRETT, mpz<uint16_t>(uint16_t(0)), 0, nullptr };
        mpz<uint16_t> b = a.barrett(mod);
        EXPECT(b.sizeinbase(2) == 192U);
        EXPECT(b.get_str(16, true) == "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFE");
    },
    CASE("Barrett reduction - 16-bit")
    {
        mpz<uint16_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint16_t> a("-5", 10);
        mpz<uint16_t> temp, mu;
        temp.setbit(16 *  12 * 2);
        mpz<uint16_t>::tdiv_q(mu, temp, m);

        mod_config<uint16_t> mod = { m, mu, m.sizeinbase(2), 12, 16, reduction_e::REDUCTION_BARRETT, mpz<uint16_t>(uint16_t(0)), 0, nullptr };
        mpz<uint16_t> b = a.barrett(mod);
        EXPECT(b.sizeinbase(2) == 192U);
        EXPECT(b.get_str(16, true) == "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFA");
    },
#if defined(IS_64BIT)
    CASE("Barrett reduction - 64-bit")
    {
        mpz<uint64_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint64_t> a("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000", 16);
        mpz<uint64_t> temp, mu;
        temp.setbit(64 * 3 * 2);
        mpz<uint64_t>::tdiv_q(mu, temp, m);

        mod_config<uint64_t> mod = { m, mu, m.sizeinbase(2), 3, 64, reduction_e::REDUCTION_BARRETT, mpz<uint64_t>(uint64_t(0)), 0, nullptr };
        mpz<uint64_t> b = a.barrett(mod);
        EXPECT(b.sizeinbase(2) == 1U);
        EXPECT(b == uint64_t(1));
    },
    CASE("Barrett reduction - 64-bit")
    {
        mpz<uint64_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint64_t> a("10000000000000000000000000000000000000000000000000", 16);
        mpz<uint64_t> temp, mu;
        temp.setbit(64 * 3 * 2);
        mpz<uint64_t>::tdiv_q(mu, temp, m);

        a = a * m - uint64_t(1);
        mod_config<uint64_t> mod = { m, mu, m.sizeinbase(2), 3, 64, reduction_e::REDUCTION_BARRETT, mpz<uint64_t>(uint64_t(0)), 0, nullptr };
        mpz<uint64_t> b = a.barrett(mod);
        EXPECT(b.sizeinbase(2) == 192U);
        EXPECT(b.get_str(16, true) == "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFE");
    },
    CASE("Barrett reduction - 64-bit")
    {
        mpz<uint64_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint64_t> a("-5", 10);
        mpz<uint64_t> temp, mu;
        temp.setbit(64 * 3 * 2);
        mpz<uint64_t>::tdiv_q(mu, temp, m);

        mod_config<uint64_t> mod = { m, mu, m.sizeinbase(2), 3, 64, reduction_e::REDUCTION_BARRETT, mpz<uint64_t>(uint64_t(0)), 0, nullptr };
        mpz<uint64_t> b = a.barrett(mod);
        EXPECT(b.sizeinbase(2) == 192U);
        EXPECT(b.get_str(16, true) == "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFA");
    },
    CASE("Barrett reduction - 64-bit")
    {
        mpz<uint64_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", 16);
        mpz<uint64_t> a("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000002", 16);
        mpz<uint64_t> temp, mu;
        temp.setbit(64 * 4 * 2);
        mpz<uint64_t>::tdiv_q(mu, temp, m);

        mod_config<uint64_t> mod = { m, mu, m.sizeinbase(2), 4, 64, reduction_e::REDUCTION_BARRETT, mpz<uint64_t>(uint64_t(0)), 0, nullptr };
        mpz<uint64_t> b = a.barrett(mod);
        EXPECT(b.sizeinbase(2) == 1U);
        EXPECT(b == uint64_t(1));
    },
    CASE("Barrett reduction - 32-bit")
    {
        mpz<uint32_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", 16);
        mpz<uint32_t> a("100000000000000000000000000000000000000000000000000000000", 16);
        mpz<uint32_t> temp, mu;
        temp.setbit(32 * 7 * 2);
        mpz<uint32_t>::tdiv_q(mu, temp, m);

        a = a * m - uint32_t(1);
        mod_config<uint32_t> mod = { m, mu, m.sizeinbase(2), 7, 32, reduction_e::REDUCTION_BARRETT, mpz<uint32_t>(uint32_t(0)), 0, nullptr };
        mpz<uint32_t> b = a.barrett(mod);
        EXPECT(b.sizeinbase(2) == 224U);
        EXPECT(b.get_str(16, true) == "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000");
    },
    CASE("Barrett reduction - 64-bit")
    {
        mpz<uint64_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", 16);
        mpz<uint64_t> a("100000000000000000000000000000000000000000000000000000000", 16);
        mpz<uint64_t> temp, mu;
        temp.setbit(64 * 4 * 2);
        mpz<uint64_t>::tdiv_q(mu, temp, m);

        a = a * m - uint64_t(1);
        mod_config<uint64_t> mod = { m, mu, m.sizeinbase(2), 4, 64, reduction_e::REDUCTION_BARRETT, mpz<uint64_t>(uint64_t(0)), 0, nullptr };
        mpz<uint64_t> b = a.barrett(mod);
        EXPECT(b.sizeinbase(2) == 224U);
        EXPECT(b.get_str(16, true) == "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000");
    },
    CASE("Barrett reduction - 64-bit")
    {
        mpz<uint64_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", 16);
        mpz<uint64_t> a("-5", 10);
        mpz<uint64_t> temp, mu;
        temp.setbit(64 * 4 * 2);
        mpz<uint64_t>::tdiv_q(mu, temp, m);

        mod_config<uint64_t> mod = { m, mu, m.sizeinbase(2), 4, 64, reduction_e::REDUCTION_BARRETT, mpz<uint64_t>(uint64_t(0)), 0, nullptr };
        mpz<uint64_t> b = a.barrett(mod);
        EXPECT(b.sizeinbase(2) == 224U);
        EXPECT(b.get_str(16, true) == "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFC");
    },
#endif
    CASE("Montgomery multiplication - 16-bit")
    {
        mpz<uint16_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint16_t> a("1", 16);
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

        mod_config<uint16_t> mod = { m, mu, m.sizeinbase(2), 12, 16, reduction_e::REDUCTION_MONTGOMERY, R2, mont_inv, nullptr };

        mpz<uint16_t> one(uint16_t(1));
        a = a.mul_mont(R2, mod);
        a = a.mul_mont(one, mod);
        EXPECT(a.get_str(16, true) == "1");
    },
    CASE("Montgomery multiplication - 16-bit")
    {
        mpz<uint16_t> m("FF7FFFFFFFFFFFFF00123000FFFFFFFEFFFFFFFFFFFFFFEF", 16);
        mpz<uint16_t> a("FF7FFFFFFFFFFFFF00123000FFFFFFFEFFFFFFFFFFFFFFEE", 16);
        mpz<uint16_t> temp, temp2, mu, R, R2, s, t;
        R2.setbit(16 * 12 * 2);
        R.setbit(16 * 12);
        std::cout << "R2 = " << R2.get_str(16) << std::endl;
        mpz<uint16_t>::tdiv_qr(mu, temp, R2, m);
        R2 = temp;
        temp2 = m;
        std::cout << "mu = " << mu.get_str(16) << std::endl;
        std::cout << "R2 = " << R2.get_str(16) << std::endl;

        mpz<uint16_t>::gcdext(temp, s, t, R, temp2);
        EXPECT(temp.get_limbsize() == 1U);
        EXPECT(temp == uint16_t(1));

        uint16_t mont_inv = 0;
        if (t.get_limbsize() > 0) {
            mont_inv = t.is_negative()? t[0] : -t[0];
        }

        mod_config<uint16_t> mod = { m, mu, m.sizeinbase(2), 12, 16, reduction_e::REDUCTION_MONTGOMERY, R2, mont_inv, nullptr };

        a = a.mul_mont(R2, mod);
        a = a.mul_mont(uint16_t(1), mod);
        EXPECT(a.get_str(16, true) == "FF7FFFFFFFFFFFFF00123000FFFFFFFEFFFFFFFFFFFFFFEE");
    },
    CASE("Montgomery multiplication - 32-bit")
    {
        mpz<uint32_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint32_t> a("1", 16);
        mpz<uint32_t> temp, temp2, mu, R, R2, s, t;
        R2.setbit(32 * 6 * 2);
        R.setbit(32 * 6);
        mpz<uint32_t>::tdiv_qr(mu, temp, R2, m);
        R2 = temp;
        temp2 = m;

        mpz<uint32_t>::gcdext(temp, s, t, R, temp2);
        EXPECT(temp.get_limbsize() == 1U);
        EXPECT(temp == uint32_t(1));

        uint32_t mont_inv = 0;
        if (t.get_limbsize() > 0) {
            mont_inv = t.is_negative()? t[0] : -t[0];
        }

        mod_config<uint32_t> mod = { m, mu, m.sizeinbase(2), 6, 32, reduction_e::REDUCTION_MONTGOMERY, R2, mont_inv, nullptr };

        mpz<uint32_t> one(uint32_t(1));
        a = a.mul_mont(R2, mod);
        a = a.mul_mont(one, mod);
        EXPECT(a.get_str(16, true) == "1");
    },
    CASE("Montgomery multiplication - 32-bit")
    {
        mpz<uint32_t> m("FF7FFFFFFFFFFFFF00123000FFFFFFFEFFFFFFFFFFFFFFEF", 16);
        mpz<uint32_t> a("FF7FFFFFFFFFFFFF00123000FFFFFFFEFFFFFFFFFFFFFFEE", 16);
        mpz<uint32_t> temp, temp2, mu, R, R2, s, t;
        R2.setbit(32 * 6 * 2);
        R.setbit(32 * 6);
        std::cout << "R2 = " << R2.get_str(16) << std::endl;
        mpz<uint32_t>::tdiv_qr(mu, temp, R2, m);
        std::cout << "mu = " << mu.get_str(16) << std::endl;
        std::cout << "R2 = " << R2.get_str(16) << std::endl;
        R2 = temp;
        temp2 = m;

        mpz<uint32_t>::gcdext(temp, s, t, R, temp2);
        EXPECT(temp.get_limbsize() == 1U);
        EXPECT(temp == uint32_t(1));

        std::cout << "s  = " << s.get_str(16) << std::endl;
        std::cout << "t  = " << t.get_str(16) << std::endl;
        std::cout << "R2 = " << R2.get_str(16) << std::endl;

        uint32_t mont_inv = 0;
        if (t.get_limbsize() > 0) {
            mont_inv = t.is_negative()? t[0] : -t[0];
        }
        std::cout << "inv = " << mont_inv << std::endl;

        mod_config<uint32_t> mod = { m, mu, m.sizeinbase(2), 6, 32, reduction_e::REDUCTION_MONTGOMERY, R2, mont_inv, nullptr };

        a = a.mul_mont(R2, mod);
        std::cout << "a = " << a.get_str(16) << std::endl;
        a = a.mul_mont(uint32_t(1), mod);
        EXPECT(a.get_str(16, true) == "FF7FFFFFFFFFFFFF00123000FFFFFFFEFFFFFFFFFFFFFFEE");
    },
#if defined(IS_64BIT)
    CASE("Montgomery multiplication - 64-bit")
    {
        mpz<uint64_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint64_t> a("1", 16);
        mpz<uint64_t> temp, temp2, mu, R, R2, s, t;
        R2.setbit(64 * 3 * 2);
        R.setbit(64 * 3);
        mpz<uint64_t>::tdiv_qr(mu, temp, R2, m);
        R2 = temp;
        temp2 = m;

        mpz<uint64_t>::gcdext(temp, s, t, R, temp2);
        EXPECT(temp.get_limbsize() == 1U);
        EXPECT(temp == uint64_t(1));

        uint64_t mont_inv = 0;
        if (t.get_limbsize() > 0) {
            mont_inv = t.is_negative()? t[0] : -t[0];
        }

        mod_config<uint64_t> mod = { m, mu, m.sizeinbase(2), 3, 64, reduction_e::REDUCTION_MONTGOMERY, R2, mont_inv, nullptr };

        mpz<uint64_t> one(uint64_t(1));
        a = a.mul_mont(R2, mod);
        a = a.mul_mont(one, mod);
        EXPECT(a.get_str(16, true) == "1");
    },
    CASE("Montgomery multiplication - 64-bit")
    {
        mpz<uint64_t> m("FF7FFFFFFFFFFFFF00123000FFFFFFFEFFFFFFFFFFFFFFEF", 16);
        mpz<uint64_t> a("FF7FFFFFFFFFFFFF00123000FFFFFFFEFFFFFFFFFFFFFFEE", 16);
        mpz<uint64_t> temp, temp2, mu, R, R2, s, t;
        R2.setbit(64 * 3 * 2);
        R.setbit(64 * 3);
        std::cout << "R2 = " << R2.get_str(16) << std::endl;
        mpz<uint64_t>::tdiv_qr(mu, temp, R2, m);
        std::cout << "mu = " << mu.get_str(16) << std::endl;
        std::cout << "R2 = " << temp.get_str(16) << std::endl;
        mpz<uint64_t>::tdiv_r(temp, R2, m);
        std::cout << "R2 = " << temp.get_str(16) << std::endl;
        mpz<uint64_t>::tdiv_q(mu, R2, m);
        std::cout << "mu = " << mu.get_str(16) << std::endl;
        R2 = temp;
        temp2 = m;

        mpz<uint64_t>::gcdext(temp, s, t, R, temp2);
        EXPECT(temp.get_limbsize() == 1U);
        EXPECT(temp == uint64_t(1));

        std::cout << "s  = " << s.get_str(16) << std::endl;
        std::cout << "t  = " << t.get_str(16) << std::endl;
        std::cout << "R2 = " << R2.get_str(16) << std::endl;

        uint64_t mont_inv = 0;
        if (t.get_limbsize() > 0) {
            mont_inv = t.is_negative()? t[0] : -t[0];
        }
        std::cout << "inv = " << mont_inv << std::endl;

        mod_config<uint64_t> mod = { m, mu, m.sizeinbase(2), 3, 64, reduction_e::REDUCTION_MONTGOMERY, R2, mont_inv, nullptr };

        a = a.mul_mont(R2, mod);
        std::cout << "a = " << a.get_str(16) << std::endl;
        a = a.mul_mont(uint64_t(1), mod);
        EXPECT(a.get_str(16, true) == "FF7FFFFFFFFFFFFF00123000FFFFFFFEFFFFFFFFFFFFFFEE");
    },
    CASE("Montgomery multiplication - 64-bit")
    {
        mpz<uint64_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint64_t> a("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF"
                        "000000000000000000000000000000000000000000000001", 16);
        mpz<uint64_t> b;

        mod_config<uint64_t> cfg;
        cfg.mod = m;

        using secp64 = secp_mpz<uint64_t>;
        b = secp64::mod_solinas<secp64::curve_e::secp192r1>(&a, cfg);
        EXPECT(b.get_str(16, true) == "1");
    },
#endif
    CASE("Montgomery squaring - 16-bit")
    {
        mpz<uint16_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint16_t> a("FFFF", 16);
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

        mod_config<uint16_t> mod = { m, mu, m.sizeinbase(2), 12, 16, reduction_e::REDUCTION_MONTGOMERY, R2, mont_inv, nullptr };

        mpz<uint16_t> one(uint16_t(1));
        a = a.mul_mont(R2, mod);
        a = a.square_mont(mod);
        a = a.mul_mont(one, mod);
        EXPECT(a.get_str(16) == "fffe0001");
    },
    CASE("Montgomery squaring - 16-bit")
    {
        mpz<uint16_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint16_t> a("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16);
        mpz<uint16_t> b("7192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16);
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

        mod_config<uint16_t> mod = { m, mu, m.sizeinbase(2), 12, 16, reduction_e::REDUCTION_MONTGOMERY, R2, mont_inv, nullptr };

        mpz<uint16_t> one(uint16_t(1));
        a = a.mul_mont(R2, mod);
        b = b.mul_mont(R2, mod);
        b = b.square_mont(mod);
        a = a.mul_mont(b, mod);
        a = a.mul_mont(one, mod);
        EXPECT(a.get_str(16) == "cb2bf6fcb4c43fb844850ff4d9fd0a57a7053423c85519bf");
    },
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

