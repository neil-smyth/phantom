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
#include "ecc/weierstrass_prime_projective.hpp"

namespace phantom {
using namespace core;      // NOLINT
using namespace elliptic;  // NOLINT

size_t num192_bits = 192;
size_t num192_bytes = 24;
const char* p192 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF";
const char* p192_inv = "1000000000000000000000000000000010000000000000001";
const char* order_m192 = "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831";
const char* a192 = "-3";
const char* b192 = "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1";
const char* g_x192 = "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012";
const char* g_y192 = "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811";

const lest::test specification[] =
{
    CASE("Projective point - 32-bit")
    {
        mpz<uint32_t> x(int32_t(1));
        mpz<uint32_t> y(int32_t(-1));

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(p192, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(p192_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m192, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(a192, 16));
        cfg.b = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(b192, 16));
        cfg.mod.k = 6;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 192;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        weierstrass_prime_projective<uint32_t> p(cfg, x, y);
        EXPECT(p.x() == x);
        EXPECT(p.x() == int32_t(1));
        EXPECT(p.y().get_str(16, true) == "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFE");
        EXPECT(p.z() == int32_t(1));
    },
    CASE("Projective point - 32-bit")
    {
        mpz<uint32_t> x(int32_t(1));
        mpz<uint32_t> y(int32_t(-1));

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(p192, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(p192_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m192, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(a192, 16));
        cfg.b = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(b192, 16));
        cfg.mod.k = 6;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 192;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        weierstrass_prime_projective<uint32_t> p(cfg, x, y);
        mpz<uint32_t> xr, yr;
        p.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x.get_str(16));
        EXPECT(yr.get_str(16) == y.mod(cfg.mod).get_str(16));
    },
    CASE("Projective point addition and subtraction zero x - 32-bit")
    {
        mpz<uint32_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y1("7192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        mpz<uint32_t> x2("DAFEBF5828783F2AD35534631588A3F629A70FB16982A888", 16);
        mpz<uint32_t> y2("DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB", 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(p192, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(p192_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m192, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(a192, 16));
        cfg.b = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(b192, 16));
        cfg.mod.k = 6;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 192;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        weierstrass_prime_projective<uint32_t> p1(cfg, x1, y1);
        weierstrass_prime_projective<uint32_t> p2(cfg, x1, y1);
        EXPECT(p1.x() == x1);
        EXPECT(p1.y() == y1);
        EXPECT(p1.z() == uint32_t(1));

        p1.doubling(cfg, 1);
        mpz<uint32_t> xr, yr;
        p1.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        EXPECT(yr.get_str(16) == y2.get_str(16));
        p2.y() = p2.y().negate();
        p1.addition(cfg, p2);
        p1.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x1.get_str(16));
        EXPECT(yr.get_str(16) == y1.get_str(16));
    },
    CASE("Projective point addition non-zero x - 32-bit")
    {
        mpz<uint32_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y1("7192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        mpz<uint32_t> x2("DAFEBF5828783F2AD35534631588A3F629A70FB16982A888", 16);
        mpz<uint32_t> y2("DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB", 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(p192, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(p192_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m192, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(a192, 16));
        cfg.b = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(b192, 16));
        cfg.mod.k = 6;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 192;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        mpz<uint32_t> xr, yr;

        weierstrass_prime_projective<uint32_t> p1(cfg, x1, y1);
        weierstrass_prime_projective<uint32_t> p2(cfg, x2, y2);
        weierstrass_prime_projective<uint32_t> pref = p1;
        EXPECT(p1.x() == x1);
        EXPECT(p2.x() == x2);

        p1.addition(cfg, p2);
        p2.y() = p2.y().negate();
        p1.addition(cfg, p2);
        p1.convert_from(cfg, &xr, &yr);
        EXPECT(xr == x1);
    },
    CASE("Projective point (Montgomery) - 32-bit")
    {
        mpz<uint32_t> x(int32_t(1));
        mpz<uint32_t> y(int32_t(-1));

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(p192, 16);
        cfg.order_m = mpz<uint32_t>(order_m192, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(a192, 16));
        cfg.b = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(b192, 16));
        cfg.mod.k = 6;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 192;
        cfg.mod.reduction = reduction_e::REDUCTION_MONTGOMERY;

        mpz<uint32_t> temp;
        temp.setbit(cfg.mod.blog2 * cfg.mod.k * 2);
        mpz<uint32_t>::tdiv_qr(cfg.mod.mod_inv, cfg.mod.mont_R2, temp, cfg.mod.mod);

        mpz<uint32_t> R, temp_m, s, t;
        R.setbit(cfg.mod.blog2 * cfg.mod.k);
        temp_m = cfg.mod.mod;
        mpz<uint32_t>::gcdext(temp, s, t, R, temp_m);
        cfg.mod.mont_inv = 0;
        if (t.get_limbsize() > 0) {
            // (R[0] - t[0]) mod B, R[0] is always 0
            cfg.mod.mont_inv = t.is_negative()? t[0] : -t[0];
        }

        s = uint32_t(1);
        s = s.mul_mont(cfg.mod.mont_R2, cfg.mod);
        s = s.mul_mont(uint32_t(1), cfg.mod);
        EXPECT(s.get_str(16, true) == "1");

        weierstrass_prime_projective<uint32_t> p(cfg, x, y);
        mpz<uint32_t> xr, yr;
        p.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x.get_str(16));
        EXPECT(yr.get_str(16, true) == "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFE");
    },
#if defined(IS_64BIT)
    CASE("Projective point (Montgomery) - 64-bit")
    {
        mpz<uint64_t> x(int64_t(1));
        mpz<uint64_t> y(int64_t(-1));

        ecc_config<uint64_t> cfg;
        cfg.mod.mod = mpz<uint64_t>(p192, 16);
        cfg.order_m = mpz<uint64_t>(order_m192, 16);
        cfg.a = std::shared_ptr<mpz<uint64_t>>(new mpz<uint64_t>(a192, 16));
        cfg.b = std::shared_ptr<mpz<uint64_t>>(new mpz<uint64_t>(b192, 16));
        cfg.mod.k = 3;
        cfg.mod.blog2 = 64;
        cfg.mod.mod_bits = 192;
        cfg.mod.reduction = reduction_e::REDUCTION_MONTGOMERY;

        mpz<uint64_t> temp;
        temp.setbit(cfg.mod.blog2 * cfg.mod.k * 2);
        mpz<uint64_t>::tdiv_qr(cfg.mod.mod_inv, cfg.mod.mont_R2, temp, cfg.mod.mod);

        mpz<uint64_t> R, temp_m, s, t;
        R.setbit(cfg.mod.blog2 * cfg.mod.k);
        temp_m = cfg.mod.mod;
        mpz<uint64_t>::gcdext(temp, s, t, R, temp_m);
        cfg.mod.mont_inv = 0;
        if (t.get_limbsize() > 0) {
            // (R[0] - t[0]) mod B, R[0] is always 0
            cfg.mod.mont_inv = t.is_negative()? t[0] : -t[0];
        }

        s = uint64_t(1);
        s = s.mul_mont(cfg.mod.mont_R2, cfg.mod);
        s = s.mul_mont(uint64_t(1), cfg.mod);
        EXPECT(s.get_str(16, true) == "1");

        weierstrass_prime_projective<uint64_t> p(cfg, x, y);
        mpz<uint64_t> xr, yr;
        p.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x.get_str(16));
        EXPECT(yr.get_str(16, true) == "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFE");
    },
#endif
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

