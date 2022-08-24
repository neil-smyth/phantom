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
#include "ecc/edwards_prime_projective.hpp"

namespace phantom {
using namespace core;      // NOLINT
using namespace elliptic;  // NOLINT

const char* edwards25519     = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";
const char* edwards25519_inv = "2000000000000000000000000000000000000000000000000000000000000004c";
const char* order_m25519     = "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";
const char* d25519           = "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3";
const char* g_x25519         = "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a";
const char* g_y25519         = "6666666666666666666666666666666666666666666666666666666666666658";

const char* edwards448       = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
                               "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const char* edwards448_inv   = "100000000000000000000000000000000000000000000000000000001"
                               "00000000000000000000000000000000000000000000000000000002";
const char* order_m448       = "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";
const char* d448             = "-98a9";
const char* g_x448           = "4F1970C66BED0DED221D15A622BF36DA9E146570470F1767EA6DE324"
                               "A3D3A46412AE1AF72AB66511433B80E18B00938E2626A82BC70CC05E";
const char* g_y448           = "693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E"
                               "05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14";

const lest::test specification[] =
{
    CASE("Projective Edwards448 point - 32-bit")
    {
        mpz<uint32_t> x(g_x448, 16);
        mpz<uint32_t> y(g_y448, 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(edwards448, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(edwards448_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m448, 16);
        cfg.a_is_minus_1 = false;
        cfg.d = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(d448, 16));
        cfg.mod.k = 14;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 448;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        edwards_prime_projective<uint32_t> p(cfg, x, y);
        EXPECT(p.x() == x);
        EXPECT(p.x().get_str(16, true) == g_x448);
        EXPECT(p.y().get_str(16, true) == g_y448);
        EXPECT(p.z() == int32_t(1));
    },
    CASE("Projective Edwards448 point addition and subtraction zero x - 32-bit")
    {
        mpz<uint32_t> x1(g_x448, 16);
        mpz<uint32_t> y1(g_y448, 16);
        mpz<uint32_t> x2("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9"
                         "55555555555555555555555555555555555555555555555555555555",
                         16);
        mpz<uint32_t> y2("ae05e9634ad7048db359d6205086c2b0036ed7a035884dd7b7e36d72"
                         "8ad8c4b80d6565833a2a3098bbbcb2bed1cda06bdaeafbcdea9386ed",
                         16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(edwards448, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(edwards448_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m448, 16);
        cfg.a_is_minus_1 = false;
        cfg.d = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(d448, 16));
        cfg.mod.k = 14;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 448;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        edwards_prime_projective<uint32_t> p1(cfg, x1, y1);
        edwards_prime_projective<uint32_t> p2(cfg, x1, y1);
        EXPECT(p1.x() == x1);
        EXPECT(p1.y() == y1);
        EXPECT(p1.z() == uint32_t(1));

        p1.doubling(cfg, 1);
        mpz<uint32_t> xr, yr;
        p1.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        EXPECT(yr.get_str(16) == y2.get_str(16));

        p2.x() = p2.x().negate();
        p1.addition(cfg, p2);
        p1.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x1.get_str(16));
        EXPECT(yr.get_str(16) == y1.get_str(16));
    },
    CASE("Projective Edwards448 ECSM by 10 - 32-bit")
    {
        mpz<uint32_t> x1(g_x448, 16);
        mpz<uint32_t> y1(g_y448, 16);
        mpz<uint32_t> x2("77486f9d19f6411cdd35d30d1c3235f71936452c787e5c034134d3e8"
                         "172278aca61622bc805761ce3dab65118a0122d73b403165d0ed303d",
                         16);
        mpz<uint32_t> y2("4d2fea0b026be11024f1f0fe7e94e618e8ac17381ada1d1bf7ee293a"
                         "68ff5d0bf93c1997dc1aabdc0c7e6381428d85b6b1954a89e4cddf67",
                         16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(edwards448, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(edwards448_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m448, 16);
        cfg.a_is_minus_1 = false;
        cfg.d = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(d448, 16));
        cfg.mod.k = 14;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 448;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        edwards_prime_projective<uint32_t> p1(cfg, x1, y1);
        edwards_prime_projective<uint32_t> p2(cfg, x1, y1);
        EXPECT(p1.x() == x1);
        EXPECT(p1.y() == y1);
        EXPECT(p1.z() == uint32_t(1));

        p1.doubling(cfg, 1);
        p1.doubling(cfg, 1);
        p1.addition(cfg, p2);
        p1.doubling(cfg, 1);

        mpz<uint32_t> xr, yr;
        p1.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Projective Edwards25519 ECSM by 10 - 32-bit")
    {
        mpz<uint32_t> x1(g_x25519, 16);
        mpz<uint32_t> y1(g_y25519, 16);
        mpz<uint32_t> x2("602c797e30ca6d754470b60ed2bc8677207e8e4ed836f81444951f224877f94f", 16);
        mpz<uint32_t> y2("637ffcaa7a1b2477c8e44d54c898bfcf2576a6853de0e843ba8874b06ae87b2c", 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(edwards25519, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(edwards25519_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m25519, 16);
        cfg.a_is_minus_1 = true;
        auto d = new mpz<uint32_t>(d25519, 16);
        cfg.d = std::shared_ptr<mpz<uint32_t>>(d);
        cfg.mod.k = 8;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 255;
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

        d->mul_mont(cfg.mod.mont_R2, cfg.mod);

        edwards_prime_projective<uint32_t> p1(cfg, x1, y1);
        edwards_prime_projective<uint32_t> p2(cfg, x1, y1);

        p1.doubling(cfg, 1);
        p1.doubling(cfg, 1);
        p1.addition(cfg, p2);
        p1.doubling(cfg, 1);

        mpz<uint32_t> xr, yr;
        p1.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Projective Edwards25519 ECSM by 63 - 32-bit")
    {
        mpz<uint32_t> x1(g_x25519, 16);
        mpz<uint32_t> y1(g_y25519, 16);
        mpz<uint32_t> x2("649a996e6d4d3b60ccb526939ed8929134107e03e2fd4648eaa2fa9830822c1a", 16);
        mpz<uint32_t> y2("1648311b942fe95d492a1ace5e5235c1aea860d036d2475cc8964cd1acedee9c", 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(edwards25519, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(edwards25519_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m25519, 16);
        cfg.a_is_minus_1 = true;
        auto d = new mpz<uint32_t>(d25519, 16);
        cfg.d = std::shared_ptr<mpz<uint32_t>>(d);
        cfg.mod.k = 8;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 255;
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

        d->mul_mont(cfg.mod.mont_R2, cfg.mod);

        edwards_prime_projective<uint32_t> p1(cfg, x1, y1);
        edwards_prime_projective<uint32_t> p2(cfg, x1, y1);

        p1.doubling(cfg, 1);
        p1.addition(cfg, p2);
        p1.doubling(cfg, 1);
        p1.addition(cfg, p2);
        p1.doubling(cfg, 1);
        p1.addition(cfg, p2);
        p1.doubling(cfg, 1);
        p1.addition(cfg, p2);
        p1.doubling(cfg, 1);
        p1.addition(cfg, p2);

        mpz<uint32_t> xr, yr;
        p1.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Projective Edwards25519 ECSM by 63 - 32-bit")
    {
        mpz<uint32_t> x1(g_x25519, 16);
        mpz<uint32_t> y1(g_y25519, 16);
        mpz<uint32_t> x2("649a996e6d4d3b60ccb526939ed8929134107e03e2fd4648eaa2fa9830822c1a", 16);
        mpz<uint32_t> y2("1648311b942fe95d492a1ace5e5235c1aea860d036d2475cc8964cd1acedee9c", 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(edwards25519, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(edwards25519_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m25519, 16);
        cfg.a_is_minus_1 = true;
        auto d = new mpz<uint32_t>(d25519, 16);
        cfg.d = std::shared_ptr<mpz<uint32_t>>(d);
        cfg.mod.k = 8;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 255;
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

        d->mul_mont(cfg.mod.mont_R2, cfg.mod);

        edwards_prime_projective<uint32_t> p1(cfg, x1, y1);
        edwards_prime_projective<uint32_t> p2(cfg, x1, y1);

        p1.doubling(cfg, 1);
        p1.addition(cfg, p2);
        p1.doubling(cfg, 1);
        p1.addition(cfg, p2);
        p1.doubling(cfg, 1);
        p1.addition(cfg, p2);
        p1.doubling(cfg, 1);
        p1.addition(cfg, p2);
        p1.doubling(cfg, 1);
        p1.addition(cfg, p2);

        mpz<uint32_t> xr, yr;
        p1.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Projective Edwards448 ECSM by 10 (Montgomery) - 32-bit")
    {
        mpz<uint32_t> x1(g_x448, 16);
        mpz<uint32_t> y1(g_y448, 16);
        mpz<uint32_t> x2("77486f9d19f6411cdd35d30d1c3235f71936452c787e5c034134d3e8"
                         "172278aca61622bc805761ce3dab65118a0122d73b403165d0ed303d",
                         16);
        mpz<uint32_t> y2("4d2fea0b026be11024f1f0fe7e94e618e8ac17381ada1d1bf7ee293a"
                         "68ff5d0bf93c1997dc1aabdc0c7e6381428d85b6b1954a89e4cddf67",
                         16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(edwards448, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(edwards448_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m448, 16);
        cfg.a_is_minus_1 = false;
        auto d = new mpz<uint32_t>(d448, 16);
        cfg.d = std::shared_ptr<mpz<uint32_t>>(d);
        cfg.mod.k = 14;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 448;
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

        d->mul_mont(cfg.mod.mont_R2, cfg.mod);

        edwards_prime_projective<uint32_t> p1(cfg, x1, y1);
        edwards_prime_projective<uint32_t> p2(cfg, x1, y1);

        p1.doubling(cfg, 1);
        p1.doubling(cfg, 1);
        p1.addition(cfg, p2);
        p1.doubling(cfg, 1);

        mpz<uint32_t> xr, yr;
        p1.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        EXPECT(yr.get_str(16) == y2.get_str(16));
    }
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

