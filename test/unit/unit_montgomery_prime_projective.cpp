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
#include "ecc/montgomery_prime_projective.hpp"

namespace phantom {
using namespace core;      // NOLINT
using namespace elliptic;  // NOLINT

const char* curve25519     = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";
const char* curve25519_inv = "2000000000000000000000000000000000000000000000000000000000000004c";
const char* order_m25519   = "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";
const char* a25519         = "76D06";
const char* b25519         = "1";
const char* g_x25519       = "216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A";
const char* g_y25519       = "6666666666666666666666666666666666666666666666666666666666666658";

const char* curve448       = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
                             "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const char* curve448_inv   = "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                             "7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3";
const char* order_m448     = "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";
const char* a448           = "262a6";
const char* b448           = "1";

const lest::test specification[] =
{
    CASE("Projective Curve25519 point - 32-bit")
    {
        mpz<uint32_t> x(g_x25519, 16);
        mpz<uint32_t> y(g_y25519, 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(curve25519, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(curve25519_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m25519, 16);
        auto a = new mpz<uint32_t>(a25519, 16);
        auto b = new mpz<uint32_t>(b25519, 16);
        auto a24 = new mpz<uint32_t>(a25519, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(a);
        cfg.b = std::shared_ptr<mpz<uint32_t>>(b);
        cfg.d = std::shared_ptr<mpz<uint32_t>>(a24);
        a24->add(uint32_t(2));
        *a24 = *a24 >> 2;
        cfg.mod.k = 8;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 256;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        montgomery_prime_projective<uint32_t> p(cfg, x, y);
        EXPECT(p.x() == x);
        EXPECT(p.x().get_str(16, true) == "216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A");
        EXPECT(p.y().get_str(16, true) == "6666666666666666666666666666666666666666666666666666666666666658");
        EXPECT(p.z() == int32_t(1));
    },
    CASE("Projective Curve25519 point addition and subtraction zero x - 32-bit")
    {
        mpz<uint32_t> x1("9", 16);
        mpz<uint32_t> y1("20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9", 16);
        mpz<uint32_t> x2("20D342D51873F1B7D9750C687D1571148F3F5CED1E350B5C5CAE469CDD684EFB", 16);
        mpz<uint32_t> y2("6C4A81FEE8FF1751FAF5FF6BA2D45D0C889A614D7272C6E14328FB9A38D20A8A", 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(curve25519, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(curve25519_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m25519, 16);
        auto a = new mpz<uint32_t>(a25519, 16);
        auto b = new mpz<uint32_t>(b25519, 16);
        auto a24 = new mpz<uint32_t>(a25519, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(a);
        cfg.b = std::shared_ptr<mpz<uint32_t>>(b);
        cfg.d = std::shared_ptr<mpz<uint32_t>>(a24);
        a24->add(uint32_t(2));
        *a24 = *a24 >> 2;
        cfg.mod.k = 8;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 256;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        montgomery_prime_projective<uint32_t> p1(cfg, x1, y1);
        montgomery_prime_projective<uint32_t> p2(cfg, x1, y1);
        EXPECT(p1.x() == x1);
        EXPECT(p1.y() == y1);
        EXPECT(p1.z() == uint32_t(1));

        p1.doubling(cfg, 1);
        p1.y_recovery(cfg, p2, p2);
        mpz<uint32_t> xr, yr;
        p1.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x2.get_str(16));

        yr.square_mod(cfg.mod);
        y2.square_mod(cfg.mod);
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Projective Curve25519 point addition x=10 - 32-bit")
    {
        mpz<uint32_t> x1("a", 16);
        mpz<uint32_t> y1("7FA11E2C10248F175E1C49E162A38AF68B311C6719C9B2F6A042B8742E891F65", 16);
        mpz<uint32_t> x2("24A527D340A8614CDE0FF034C01D63A2B27C112C1853B4FFA0BE3E7AA02555F9", 16);
        mpz<uint32_t> y2("787B20645ADF84606107BBAF8B3E3AAD593FD53C41253AFE7405FA0B98B63FEE", 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(curve25519, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(curve25519_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m25519, 16);
        auto a = new mpz<uint32_t>(a25519, 16);
        auto b = new mpz<uint32_t>(b25519, 16);
        auto a24 = new mpz<uint32_t>(a25519, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(a);
        cfg.b = std::shared_ptr<mpz<uint32_t>>(b);
        cfg.d = std::shared_ptr<mpz<uint32_t>>(a24);
        a24->add(uint32_t(2));
        *a24 = *a24 >> 2;
        cfg.mod.k = 8;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 256;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        montgomery_prime_projective<uint32_t> p1(cfg, x1, y1);
        montgomery_prime_projective<uint32_t> p2(cfg, x1, y1);
        EXPECT(p1.x() == x1);
        EXPECT(p1.y() == y1);
        EXPECT(p1.z() == uint32_t(1));

        p1.doubling(cfg, 1);
        p1.y_recovery(cfg, p2, p2);
        mpz<uint32_t> xr, yr;
        p1.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        yr.square_mod(cfg.mod);
        y2.square_mod(cfg.mod);
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Projective Curve25519 point addition and subtraction zero x - 32-bit")
    {
        mpz<uint32_t> x1("9", 16);
        mpz<uint32_t> y1("20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9", 16);
        mpz<uint32_t> x2("1c12bc1a6d57abe645534d91c21bba64f8824e67621c0859c00a03affb713c12", 16);
        mpz<uint32_t> y2("56797aa341c7815153115bb9acd3cc73ac950a8f08e108308a399afe63beddc2", 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(curve25519, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(curve25519_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m25519, 16);
        auto a = new mpz<uint32_t>(a25519, 16);
        auto b = new mpz<uint32_t>(b25519, 16);
        auto a24 = new mpz<uint32_t>(a25519, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(a);
        cfg.b = std::shared_ptr<mpz<uint32_t>>(b);
        cfg.d = std::shared_ptr<mpz<uint32_t>>(a24);
        a24->add(uint32_t(2));
        *a24 = *a24 >> 2;
        cfg.mod.k = 8;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 256;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        montgomery_prime_projective<uint32_t> p1(cfg, x1, y1);
        montgomery_prime_projective<uint32_t> p2(cfg, x1, y1);
        montgomery_prime_projective<uint32_t> G(cfg, x1, y1);
        EXPECT(p1.x() == x1);
        EXPECT(p1.y() == y1);
        EXPECT(p1.z() == uint32_t(1));

        p2.doubling(cfg, 1);

        p1.ladder_step(cfg, &p2, G);

        p1.y_recovery(cfg, G, p2);
        mpz<uint32_t> xr, yr;
        p1.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        yr.square_mod(cfg.mod);
        y2.square_mod(cfg.mod);
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Projective Curve25519 ECSM by 15 - 32-bit")
    {
        mpz<uint32_t> x1("9", 16);
        mpz<uint32_t> y1("20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9", 16);
        mpz<uint32_t> x2("451d44beaaaf59cf740de459a82ac101302f8fca7e0433471e0ff10454a4fa5e", 16);
        mpz<uint32_t> y2("786a6d77c15dd48013386d0a3e619e6b3545470f28ef0c3897734c0bc0f3cc0e", 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(curve25519, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(curve25519_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m25519, 16);
        auto a = new mpz<uint32_t>(a25519, 16);
        auto b = new mpz<uint32_t>(b25519, 16);
        auto a24 = new mpz<uint32_t>(a25519, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(a);
        cfg.b = std::shared_ptr<mpz<uint32_t>>(b);
        cfg.d = std::shared_ptr<mpz<uint32_t>>(a24);
        a24->add(uint32_t(2));
        *a24 = *a24 >> 2;
        cfg.mod.k = 8;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 256;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        montgomery_prime_projective<uint32_t> ps(cfg, x1, y1);
        montgomery_prime_projective<uint32_t> pr(cfg, x1, y1);
        montgomery_prime_projective<uint32_t> G(cfg, x1, y1);
        EXPECT(pr.x() == x1);
        EXPECT(pr.y() == y1);
        EXPECT(pr.z() == uint32_t(1));

        pr.doubling(cfg, 1);

        ps.ladder_step(cfg, &pr, G);  // 3P, 4P
        ps.ladder_step(cfg, &pr, G);  // 7P, 8P
        ps.ladder_step(cfg, &pr, G);  // 15P, 16P

        ps.y_recovery(cfg, G, pr);
        mpz<uint32_t> xr, yr;
        ps.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        yr.square_mod(cfg.mod);
        y2.square_mod(cfg.mod);
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Projective Curve25519 ECSM by 197 - 32-bit")
    {
        mpz<uint32_t> x1("9", 16);
        mpz<uint32_t> y1("20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9", 16);
        mpz<uint32_t> x2("5852a8f349e63fc7def5cafcc257764dfde61b0809acc338bf5b9b977440a5ff", 16);
        mpz<uint32_t> y2("3bc78c8a592c4cac702ac1c16b1f5fcc048a330e1240d3fa99a859ba4c864dc8", 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(curve25519, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(curve25519_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m25519, 16);
        auto a = new mpz<uint32_t>(a25519, 16);
        auto b = new mpz<uint32_t>(b25519, 16);
        auto a24 = new mpz<uint32_t>(a25519, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(a);
        cfg.b = std::shared_ptr<mpz<uint32_t>>(b);
        cfg.d = std::shared_ptr<mpz<uint32_t>>(a24);
        a24->add(uint32_t(2));
        *a24 = *a24 >> 2;
        cfg.mod.k = 8;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 256;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        montgomery_prime_projective<uint32_t> ps(cfg, x1, y1);
        montgomery_prime_projective<uint32_t> pr(cfg, x1, y1);
        montgomery_prime_projective<uint32_t> G(cfg, x1, y1);
        EXPECT(pr.x() == x1);
        EXPECT(pr.y() == y1);
        EXPECT(pr.z() == uint32_t(1));

        pr.doubling(cfg, 1);

        ps.ladder_step(cfg, &pr, G);  // 3P, 4P
        pr.ladder_step(cfg, &ps, G);  // 7P, 6P
        pr.ladder_step(cfg, &ps, G);  // 13P, 12P
        pr.ladder_step(cfg, &ps, G);  // 25P, 24P
        ps.ladder_step(cfg, &pr, G);  // 49P, 50P
        pr.ladder_step(cfg, &ps, G);  // 99P, 98P
        ps.ladder_step(cfg, &pr, G);  // 197P, 198P

        ps.y_recovery(cfg, G, pr);
        mpz<uint32_t> xr, yr;
        ps.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        yr.square_mod(cfg.mod);
        y2.square_mod(cfg.mod);
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Projective Curve25519 ECSM by 198 - 32-bit")
    {
        mpz<uint32_t> x1("9", 16);
        mpz<uint32_t> y1("20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9", 16);
        mpz<uint32_t> x2("27980965574a01b9b83fc1d935a707f6bbda97e69d7a63a79495a0525a643f10", 16);
        mpz<uint32_t> y2("3a06433bbb86e8bad43f8f3443e6de7b130af4c06c8aa3ca48c935136339bace", 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(curve25519, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(curve25519_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m25519, 16);
        auto a = new mpz<uint32_t>(a25519, 16);
        auto b = new mpz<uint32_t>(b25519, 16);
        auto a24 = new mpz<uint32_t>(a25519, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(a);
        cfg.b = std::shared_ptr<mpz<uint32_t>>(b);
        cfg.d = std::shared_ptr<mpz<uint32_t>>(a24);
        a24->add(uint32_t(2));
        *a24 = *a24 >> 2;
        cfg.mod.k = 8;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 256;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        montgomery_prime_projective<uint32_t> ps(cfg, x1, y1);
        montgomery_prime_projective<uint32_t> pr(cfg, x1, y1);
        montgomery_prime_projective<uint32_t> G(cfg, x1, y1);
        EXPECT(pr.x() == x1);
        EXPECT(pr.y() == y1);
        EXPECT(pr.z() == uint32_t(1));

        pr.doubling(cfg, 1);

        ps.ladder_step(cfg, &pr, G);  // 3P, 4P
        pr.ladder_step(cfg, &ps, G);  // 7P, 6P
        pr.ladder_step(cfg, &ps, G);  // 13P, 12P
        pr.ladder_step(cfg, &ps, G);  // 25P, 24P
        ps.ladder_step(cfg, &pr, G);  // 49P, 50P
        ps.ladder_step(cfg, &pr, G);  // 99P, 100P
        pr.ladder_step(cfg, &ps, G);  // 199P, 198P

        ps.y_recovery(cfg, G, pr);
        mpz<uint32_t> xr, yr;
        ps.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        yr.square_mod(cfg.mod);
        y2.square_mod(cfg.mod);
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Projective Curve25519 ECSM Mont domain check  - 32-bit")
    {
        mpz<uint32_t> x1("9", 16);
        mpz<uint32_t> y1("20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9", 16);
        mpz<uint32_t> x2("9", 16);
        mpz<uint32_t> y2("20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9", 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(curve25519, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(curve25519_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m25519, 16);
        auto a = new mpz<uint32_t>(a25519, 16);
        auto b = new mpz<uint32_t>(b25519, 16);
        auto a24 = new mpz<uint32_t>(a25519, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(a);
        cfg.b = std::shared_ptr<mpz<uint32_t>>(b);
        cfg.d = std::shared_ptr<mpz<uint32_t>>(a24);
        a24->add(uint32_t(2));
        *a24 = *a24 >> 2;
        cfg.mod.k = 8;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 256;
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

        montgomery_prime_projective<uint32_t> ps(cfg, x1, y1);

        mpz<uint32_t> xr, yr;
        ps.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        yr.square_mod(cfg.mod);
        y2.square_mod(cfg.mod);
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Projective Curve25519 ECSM Mont domain check double  - 32-bit")
    {
        mpz<uint32_t> x1("9", 16);
        mpz<uint32_t> y1("20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9", 16);
        mpz<uint32_t> x2("20d342d51873f1b7d9750c687d1571148f3f5ced1e350b5c5cae469cdd684efb", 16);
        mpz<uint32_t> y2("6c4a81fee8ff1751faf5ff6ba2d45d0c889a614d7272c6e14328fb9a38d20a8a", 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(curve25519, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(curve25519_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m25519, 16);
        auto a = new mpz<uint32_t>(a25519, 16);
        auto b = new mpz<uint32_t>(b25519, 16);
        auto a24 = new mpz<uint32_t>(a25519, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(a);
        cfg.b = std::shared_ptr<mpz<uint32_t>>(b);
        cfg.d = std::shared_ptr<mpz<uint32_t>>(a24);
        a24->add(uint32_t(2));
        *a24 = *a24 >> 2;
        cfg.mod.k = 8;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 256;
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

        a->mul_mod(cfg.mod.mont_R2, cfg.mod);
        b->mul_mod(cfg.mod.mont_R2, cfg.mod);
        a24->mul_mod(cfg.mod.mont_R2, cfg.mod);

        montgomery_prime_projective<uint32_t> ps(cfg, x1, y1);
        montgomery_prime_projective<uint32_t> pr(cfg, x1, y1);
        montgomery_prime_projective<uint32_t> G(cfg, x1, y1);

        ps.doubling(cfg, 1);
        ps.y_recovery(cfg, G, pr);

        mpz<uint32_t> xr, yr;
        ps.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        yr.square_mod(cfg.mod);
        y2.square_mod(cfg.mod);
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Projective Curve25519 ECSM by 2 - 32-bit")
    {
        mpz<uint32_t> x1("9", 16);
        mpz<uint32_t> y1("20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9", 16);
        mpz<uint32_t> x2("20d342d51873f1b7d9750c687d1571148f3f5ced1e350b5c5cae469cdd684efb", 16);
        mpz<uint32_t> y2("6c4a81fee8ff1751faf5ff6ba2d45d0c889a614d7272c6e14328fb9a38d20a8a", 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(curve25519, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(curve25519_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m25519, 16);
        auto a = new mpz<uint32_t>(a25519, 16);
        auto b = new mpz<uint32_t>(b25519, 16);
        auto a24 = new mpz<uint32_t>(a25519, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(a);
        cfg.b = std::shared_ptr<mpz<uint32_t>>(b);
        cfg.d = std::shared_ptr<mpz<uint32_t>>(a24);
        a24->add(uint32_t(2));
        *a24 = *a24 >> 2;
        cfg.mod.k = 8;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 256;
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

        a->mul_mod(cfg.mod.mont_R2, cfg.mod);
        b->mul_mod(cfg.mod.mont_R2, cfg.mod);
        a24->mul_mod(cfg.mod.mont_R2, cfg.mod);

        montgomery_prime_projective<uint32_t> ps(cfg, x1, y1);
        montgomery_prime_projective<uint32_t> pr(cfg, x1, y1);
        montgomery_prime_projective<uint32_t> G(cfg, x1, y1);

        pr.doubling(cfg, 1);
        pr.ladder_step(cfg, &ps, G);  // 3P, 2P

        ps.y_recovery(cfg, G, pr);
        mpz<uint32_t> xr, yr;
        ps.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        yr.square_mod(cfg.mod);
        y2.square_mod(cfg.mod);
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Projective Curve25519 ECSM by 198 - 32-bit")
    {
        mpz<uint32_t> x1("9", 16);
        mpz<uint32_t> y1("20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9", 16);
        mpz<uint32_t> x2("27980965574a01b9b83fc1d935a707f6bbda97e69d7a63a79495a0525a643f10", 16);
        mpz<uint32_t> y2("3a06433bbb86e8bad43f8f3443e6de7b130af4c06c8aa3ca48c935136339bace", 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(curve25519, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(curve25519_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m25519, 16);
        auto a = new mpz<uint32_t>(a25519, 16);
        auto b = new mpz<uint32_t>(b25519, 16);
        auto a24 = new mpz<uint32_t>(a25519, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(a);
        cfg.b = std::shared_ptr<mpz<uint32_t>>(b);
        cfg.d = std::shared_ptr<mpz<uint32_t>>(a24);
        a24->add(uint32_t(2));
        *a24 = *a24 >> 2;
        cfg.mod.k = 8;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 256;
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

        a->mul_mod(cfg.mod.mont_R2, cfg.mod);
        b->mul_mod(cfg.mod.mont_R2, cfg.mod);
        a24->mul_mod(cfg.mod.mont_R2, cfg.mod);

        montgomery_prime_projective<uint32_t> ps(cfg, x1, y1);
        montgomery_prime_projective<uint32_t> pr(cfg, x1, y1);
        montgomery_prime_projective<uint32_t> G(cfg, x1, y1);

        pr.doubling(cfg, 1);

        ps.ladder_step(cfg, &pr, G);  // 3P, 4P
        pr.ladder_step(cfg, &ps, G);  // 7P, 6P
        pr.ladder_step(cfg, &ps, G);  // 13P, 12P
        pr.ladder_step(cfg, &ps, G);  // 25P, 24P
        ps.ladder_step(cfg, &pr, G);  // 49P, 50P
        ps.ladder_step(cfg, &pr, G);  // 99P, 100P
        pr.ladder_step(cfg, &ps, G);  // 199P, 198P

        ps.y_recovery(cfg, G, pr);
        mpz<uint32_t> xr, yr;
        ps.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        yr.square_mod(cfg.mod);
        y2.square_mod(cfg.mod);
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Projective Curve448 ECSM by 198 - 32-bit")
    {
        mpz<uint32_t> x1("5", 16);
        mpz<uint32_t> y1("7D235D1295F5B1F66C98AB6E58326FCECBAE5D34F55545D060F75DC2"
                         "8DF3F6EDB8027E2346430D211312C4B150677AF76FD7223D457B5B1A",
                         16);
        mpz<uint32_t> x2("59536c7648daa4b00a65f15968bec707de03876c9ec097eb96dff118"
                         "153cccea8ce4ee058825d81d7b173a212d3904bb0934dac3fcdbc0c4",
                         16);
        mpz<uint32_t> y2("853c9029f3a9c5222e0ed215d5211d6b2680c2fb1263c48206054758"
                         "19d532e9a590bd642f40b450f4dfdb4ee01164f42d3a12ef5f32a85d",
                         16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(curve448, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(curve448_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m448, 16);
        auto a = new mpz<uint32_t>(a448, 16);
        auto b = new mpz<uint32_t>(b448, 16);
        auto a24 = new mpz<uint32_t>(a448, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(a);
        cfg.b = std::shared_ptr<mpz<uint32_t>>(b);
        cfg.d = std::shared_ptr<mpz<uint32_t>>(a24);
        a24->add(uint32_t(2));
        *a24 = *a24 >> 2;
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

        a->mul_mod(cfg.mod.mont_R2, cfg.mod);
        b->mul_mod(cfg.mod.mont_R2, cfg.mod);
        a24->mul_mod(cfg.mod.mont_R2, cfg.mod);

        montgomery_prime_projective<uint32_t> ps(cfg, x1, y1);
        montgomery_prime_projective<uint32_t> pr(cfg, x1, y1);
        montgomery_prime_projective<uint32_t> G(cfg, x1, y1);

        pr.doubling(cfg, 1);

        ps.ladder_step(cfg, &pr, G);  // 3P, 4P
        pr.ladder_step(cfg, &ps, G);  // 7P, 6P
        pr.ladder_step(cfg, &ps, G);  // 13P, 12P
        pr.ladder_step(cfg, &ps, G);  // 25P, 24P
        ps.ladder_step(cfg, &pr, G);  // 49P, 50P
        ps.ladder_step(cfg, &pr, G);  // 99P, 100P
        pr.ladder_step(cfg, &ps, G);  // 199P, 198P

        ps.y_recovery(cfg, G, pr);
        mpz<uint32_t> xr, yr;
        ps.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        yr.square_mod(cfg.mod);
        y2.square_mod(cfg.mod);
        EXPECT(yr.get_str(16) == y2.get_str(16));
    }
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

