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
#include "ecc/weierstrass_prime_affine.hpp"

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
const char* g_y192 = "7192B95FFC8DA78631011ED6B24CDD573F977A11E794811";

size_t num224_bits = 224;
size_t num224_bytes = 28;
const char* p224 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001";
const char* p224_inv = "100000000000000000000000000000000ffffffffffffffffffffffff";
const char* order_m224 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D";
const char* a224 = "-3";
const char* b224 = "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4";
const char* g_x224 = "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21";
const char* g_y224 = "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34";

const lest::test specification[] =
{
    CASE("Affine point - 32-bit")
    {
        mpz<uint32_t> x(uint32_t(1));
        mpz<uint32_t> y(int32_t(-1));

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(p192, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(p192_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m192, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(a192, 16));
        cfg.b = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(b192, 16));
        cfg.mod.k = 6;
        cfg.mod.mod_bits = 192;
        cfg.mod.blog2 = 32;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        weierstrass_prime_affine<uint32_t> p(cfg, x, y);
        EXPECT(p.x() == x);
        EXPECT(p.x() == uint32_t(1));
        EXPECT(p.y().get_str(16, true) == "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFE");
    },
    CASE("Affine point addition and subtraction zero x - 32-bit")
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
        cfg.mod.mod_bits = 192;
        cfg.mod.blog2 = 32;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        weierstrass_prime_affine<uint32_t> p1(cfg, x1, y1);
        weierstrass_prime_affine<uint32_t> p2(cfg, x1, y1);
        EXPECT(p1.x() == x1);
        EXPECT(p1.y() == y1);

        p1.doubling(cfg, 1);
        EXPECT(p1.x().get_str(16) == x2.get_str(16));
        EXPECT(p1.y().get_str(16) == y2.get_str(16));
        p2.y() = p2.y().negate();
        p1.addition(cfg, p2);
        EXPECT(p1.x().get_str(16) == x1.get_str(16));
        EXPECT(p1.y().get_str(16) == y1.get_str(16));
    },
    CASE("Affine point addition non-zero x - 32-bit")
    {
        mpz<uint32_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y1("7192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        mpz<uint32_t> x2("10BB8E9840049B183E078D9C300E1605590118EBDD7FF590", 16);
        mpz<uint32_t> y2("31361008476F917BADC9F836E62762BE312B72543CCEAEA1", 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(p192, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(p192_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m192, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(a192, 16));
        cfg.b = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(b192, 16));
        cfg.mod.k = 6;
        cfg.mod.mod_bits = 192;
        cfg.mod.blog2 = 32;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        weierstrass_prime_affine<uint32_t> p1(cfg, x1, y1);
        weierstrass_prime_affine<uint32_t> p2(cfg, x2, y2);
        weierstrass_prime_affine<uint32_t> pref = p1;
        EXPECT(p1.x() == x1);
        EXPECT(p2.x() == x2);

        p1.addition(cfg, p2);
        p2.y() = p2.y().negate();
        p1.addition(cfg, p2);
        EXPECT(p1.x().get_str(16) == pref.x().get_str(16));
        EXPECT(p1.y().get_str(16) == pref.y().get_str(16));
    },
    CASE("Affine point doubling and subtraction - 32-bit")
    {
        mpz<uint32_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y1("7192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(p192, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(p192_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m192, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(a192, 16));
        cfg.b = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(b192, 16));
        cfg.mod.k = 6;
        cfg.mod.mod_bits = 192;
        cfg.mod.blog2 = 32;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        weierstrass_prime_affine<uint32_t> p1(cfg, x1, y1);
        weierstrass_prime_affine<uint32_t> p2(cfg, x1, y1);
        weierstrass_prime_affine<uint32_t> pref(cfg, x1, y1);

        retcode_e rc;
        rc = p1.doubling(cfg, 1);
        EXPECT(rc == POINT_OK);
        p2.y() = p2.y().negate();
        rc = p1.addition(cfg, p2);
        EXPECT(rc == POINT_OK);
        EXPECT(p1.x().get_str(16) == pref.x().get_str(16));
        EXPECT(p1.y().get_str(16) == pref.y().get_str(16));
    },
    CASE("Affine scalar multiplication P192 k = 5 - 32-bit")
    {
        mpz<uint32_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y1("7192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        mpz<uint32_t> x2("10BB8E9840049B183E078D9C300E1605590118EBDD7FF590", 16);
        mpz<uint32_t> y2("31361008476F917BADC9F836E62762BE312B72543CCEAEA1", 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(p192, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(p192_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m192, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(a192, 16));
        cfg.b = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(b192, 16));
        cfg.mod.k = 6;
        cfg.mod.mod_bits = 192;
        cfg.mod.blog2 = 32;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        weierstrass_prime_affine<uint32_t> p1(cfg, x1, y1);
        weierstrass_prime_affine<uint32_t> pbaseneg = p1;
        pbaseneg.y() = pbaseneg.y().negate();
        weierstrass_prime_affine<uint32_t> pbase = p1;
        EXPECT(p1.x() == x1);
        EXPECT(p1.y() == y1);
        EXPECT(pbaseneg.x() == x1);
        EXPECT(pbaseneg.y() == -y1);
        EXPECT(pbase.x() == x1);
        EXPECT(pbase.y() == y1);

        retcode_e rc;

        // Q = 2*2*P + P = 5*P
        rc = p1.doubling(cfg, 1);
        EXPECT(rc == POINT_OK);
        rc = p1.doubling(cfg, 1);
        EXPECT(rc == POINT_OK);
        rc = p1.addition(cfg, pbase);
        EXPECT(rc == POINT_OK);

        // R = Q - P - P - P - P = P
        rc = p1.addition(cfg, pbaseneg);
        EXPECT(rc == POINT_OK);
        rc = p1.addition(cfg, pbaseneg);
        EXPECT(rc == POINT_OK);
        rc = p1.addition(cfg, pbaseneg);
        EXPECT(rc == POINT_OK);
        rc = p1.addition(cfg, pbaseneg);
        EXPECT(rc == POINT_OK);

        EXPECT(p1.x().get_str(16) == x1.get_str(16));
        EXPECT(p1.y().get_str(16) == y1.get_str(16));
    },
#if defined(IS_64BIT)
    CASE("Affine point - 64-bit")
    {
        mpz<uint64_t> x(uint64_t(1));
        mpz<uint64_t> y(int64_t(-1));

        ecc_config<uint64_t> cfg;
        cfg.mod.mod = mpz<uint64_t>(p224, 16);
        cfg.order_m = mpz<uint64_t>(order_m224, 16);
        cfg.a = std::shared_ptr<mpz<uint64_t>>(new mpz<uint64_t>(a224, 16));
        cfg.b = std::shared_ptr<mpz<uint64_t>>(new mpz<uint64_t>(b224, 16));
        cfg.mod.k = 4;
        cfg.mod.mod_bits = 224;
        cfg.mod.blog2 = 64;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;
        mpz<uint64_t> temp;
        temp.setbit(64 * 4 * 2);
        mpz<uint64_t>::tdiv_q(cfg.mod.mod_inv, temp, cfg.mod.mod);

        weierstrass_prime_affine<uint64_t> p(cfg, x, y);
        EXPECT(p.x() == x);
        EXPECT(p.x() == uint64_t(1));
        EXPECT(p.y().get_str(16, true) == "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000");
    },
    CASE("Affine point addition and subtraction zero x - 64-bit")
    {
        mpz<uint64_t> x1("B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21", 16);
        mpz<uint64_t> y1("BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34", 16);
        mpz<uint64_t> x2("706A46DC76DCB76798E60E6D89474788D16DC18032D268FD1A704FA6", 16);
        mpz<uint64_t> y2("1C2B76A7BC25E7702A704FA986892849FCA629487ACF3709D2E4E8BB", 16);

        ecc_config<uint64_t> cfg;
        cfg.mod.mod = mpz<uint64_t>(p224, 16);
        cfg.order_m = mpz<uint64_t>(order_m224, 16);
        cfg.a = std::shared_ptr<mpz<uint64_t>>(new mpz<uint64_t>(a224, 16));
        cfg.b = std::shared_ptr<mpz<uint64_t>>(new mpz<uint64_t>(b224, 16));
        cfg.mod.k = 4;
        cfg.mod.mod_bits = 224;
        cfg.mod.blog2 = 64;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;
        mpz<uint64_t> temp;
        temp.setbit(64 * 4 * 2);
        mpz<uint64_t>::tdiv_q(cfg.mod.mod_inv, temp, cfg.mod.mod);

        weierstrass_prime_affine<uint64_t> p1(cfg, x1, y1);
        weierstrass_prime_affine<uint64_t> p2(cfg, x1, y1);
        EXPECT(p1.x() == x1);
        EXPECT(p1.y() == y1);

        p1.doubling(cfg, 1);
        EXPECT(p1.x().get_str(16) == x2.get_str(16));
        EXPECT(p1.y().get_str(16) == y2.get_str(16));
        p2.y() = p2.y().negate();
        p1.addition(cfg, p2);
        EXPECT(p1.x().get_str(16) == x1.get_str(16));
        EXPECT(p1.y().get_str(16) == y1.get_str(16));
    },
#endif
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

