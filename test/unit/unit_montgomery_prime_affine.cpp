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
#include "ecc/montgomery_prime_affine.hpp"

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

const lest::test specification[] =
{
    CASE("Affine Curve25519 point - 32-bit")
    {
        mpz<uint32_t> x(g_x25519, 16);
        mpz<uint32_t> y(g_y25519, 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(curve25519, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(curve25519_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m25519, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(a25519, 16));
        cfg.b = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(b25519, 16));
        cfg.mod.k = 8;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 256;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        montgomery_prime_affine<uint32_t> p(cfg, x, y);
        EXPECT(p.x() == x);
        EXPECT(p.x().get_str(16, true) == "216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A");
        EXPECT(p.y().get_str(16, true) == "6666666666666666666666666666666666666666666666666666666666666658");
        EXPECT(p.z() == int32_t(1));
    },
    CASE("Affine Curve25519 point addition and subtraction zero x - 32-bit")
    {
        mpz<uint32_t> x1("9", 16);
        mpz<uint32_t> y1("20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9", 16);
        mpz<uint32_t> x2("20D342D51873F1B7D9750C687D1571148F3F5CED1E350B5C5CAE469CDD684EFB", 16);
        mpz<uint32_t> y2("6C4A81FEE8FF1751FAF5FF6BA2D45D0C889A614D7272C6E14328FB9A38D20A8A", 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(curve25519, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(curve25519_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m25519, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(a25519, 16));
        cfg.b = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(b25519, 16));
        cfg.mod.k = 8;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 256;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        montgomery_prime_affine<uint32_t> p1(cfg, x1, y1);
        montgomery_prime_affine<uint32_t> p2(cfg, x1, y1);
        EXPECT(p1.x() == x1);
        EXPECT(p1.y() == y1);
        EXPECT(p1.z() == uint32_t(1));

        p1.doubling(cfg, 1);
        mpz<uint32_t> xr, yr;
        p1.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x2.get_str(16));

        yr.square_mod(cfg.mod);
        y2.square_mod(cfg.mod);
        EXPECT(yr.get_str(16) == y2.get_str(16));

        p2.y() = p2.y().negate();
        p1.addition(cfg, p2);
        p1.convert_from(cfg, &xr, &yr);
        EXPECT(xr.get_str(16) == x1.get_str(16));
        yr.square_mod(cfg.mod);
        y1.square_mod(cfg.mod);
        EXPECT(yr.get_str(16) == y1.get_str(16));
    },
    CASE("Affine Curve25519 point addition x=10 - 32-bit")
    {
        mpz<uint32_t> x1("a", 16);
        mpz<uint32_t> y1("7FA11E2C10248F175E1C49E162A38AF68B311C6719C9B2F6A042B8742E891F65", 16);
        mpz<uint32_t> x2("24A527D340A8614CDE0FF034C01D63A2B27C112C1853B4FFA0BE3E7AA02555F9", 16);
        mpz<uint32_t> y2("787B20645ADF84606107BBAF8B3E3AAD593FD53C41253AFE7405FA0B98B63FEE", 16);

        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(curve25519, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(curve25519_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m25519, 16);
        cfg.a = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(a25519, 16));
        cfg.b = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(b25519, 16));
        cfg.mod.k = 8;
        cfg.mod.blog2 = 32;
        cfg.mod.mod_bits = 256;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        montgomery_prime_affine<uint32_t> p1(cfg, x1, y1);
        montgomery_prime_affine<uint32_t> p2(cfg, x1, y1);
        EXPECT(p1.x() == x1);
        EXPECT(p1.y() == y1);
        EXPECT(p1.z() == uint32_t(1));

        p1.doubling(cfg, 1);
        mpz<uint32_t> xr, yr;
        p1.convert_from(cfg, &xr, &yr);
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

