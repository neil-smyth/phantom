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
#include "ecc/weierstrass_binary_affine.hpp"

namespace phantom {
using namespace core;      // NOLINT
using namespace elliptic;  // NOLINT

size_t num163_bits = 192;
size_t num163_bytes = 24;
const char* p163 = "800000000000000000000000000000000000000c9";
const char* p163_inv = "1000000000000000000000000000000010000000000000001";
const char* order_m163 = "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831";
const char* a163 = "1";
const char* b163 = "20a601907b8c953ca1481eb10512f78744a3205fd";
const char* g_x163 = "3f0eba16286a2d57ea0991168d4994637e8343e36";
const char* g_y163 = "0d51fbc6c71a0094fa2cdd545b11c5c0c797324f1";


const lest::test specification[] =
{
    CASE("Affine point - 32-bit")
    {
        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(p163, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(p163_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m163, 16);
        cfg.a = std::shared_ptr<mp_gf2n<uint32_t>>(new mp_gf2n<uint32_t>(a163, p163, 16));
        cfg.b = std::shared_ptr<mp_gf2n<uint32_t>>(new mp_gf2n<uint32_t>(b163, p163, 16));
        cfg.mod.k = 6;
        cfg.mod.mod_bits = 163;
        cfg.mod.blog2 = 32;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        mp_gf2n<uint32_t> x(uint32_t(1), cfg.mod.mod);
        mp_gf2n<uint32_t> y(int32_t(0), cfg.mod.mod);

        weierstrass_binary_affine<uint32_t> p(cfg, x, y);
        EXPECT(p.x() == x);
        EXPECT(p.x() == uint32_t(1));
        EXPECT(p.y() == y);
        EXPECT(p.y() == uint32_t(0));
    },
    CASE("Affine point doubling - 32-bit")
    {
        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(p163, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(p163_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m163, 16);
        cfg.a = std::shared_ptr<mp_gf2n<uint32_t>>(new mp_gf2n<uint32_t>(a163, p163, 16));
        cfg.b = std::shared_ptr<mp_gf2n<uint32_t>>(new mp_gf2n<uint32_t>(b163, p163, 16));
        cfg.mod.k = 6;
        cfg.mod.mod_bits = 163;
        cfg.mod.blog2 = 32;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        mp_gf2n<uint32_t> x("3F0EBA16286A2D57EA0991168D4994637E8343E36", p163, 16);
        mp_gf2n<uint32_t> y("D51FBC6C71A0094FA2CDD545B11C5C0C797324F1", p163, 16);

        weierstrass_binary_affine<uint32_t> p(cfg, x, y);
        p.doubling(cfg, 1);
        EXPECT(p.x().get_str(16, true) == "1AEB33FED9C49E0200A0C561EA66D5AB85BD4C2D4");
        EXPECT(p.y().get_str(16, true) == "530608192CD47D0C24C20076475FD625CC82895E8");
    },
    CASE("Affine point doubling and addition - 32-bit")
    {
        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(p163, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(p163_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m163, 16);
        cfg.a = std::shared_ptr<mp_gf2n<uint32_t>>(new mp_gf2n<uint32_t>(a163, p163, 16));
        cfg.b = std::shared_ptr<mp_gf2n<uint32_t>>(new mp_gf2n<uint32_t>(b163, p163, 16));
        cfg.mod.k = 6;
        cfg.mod.mod_bits = 163;
        cfg.mod.blog2 = 32;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        mp_gf2n<uint32_t> x("3F0EBA16286A2D57EA0991168D4994637E8343E36", p163, 16);
        mp_gf2n<uint32_t> y("D51FBC6C71A0094FA2CDD545B11C5C0C797324F1", p163, 16);

        weierstrass_binary_affine<uint32_t> pbase(cfg, x, y);
        weierstrass_binary_affine<uint32_t> p(cfg, x, y);
        p.doubling(cfg, 1);
        p.addition(cfg, pbase);
        EXPECT(p.x().get_str(16, true) == "634000577F86AA315009D6F9B906691F6EDD691FE");
        EXPECT(p.y().get_str(16, true) == "401A3DE0D6C2EC014E6FBA5653587BD45DC2230BE");
    },
    CASE("Affine point doubling and subtraction - 32-bit")
    {
        ecc_config<uint32_t> cfg;
        cfg.mod.mod = mpz<uint32_t>(p163, 16);
        cfg.mod.mod_inv = mpz<uint32_t>(p163_inv, 16);
        cfg.order_m = mpz<uint32_t>(order_m163, 16);
        cfg.a = std::shared_ptr<mp_gf2n<uint32_t>>(new mp_gf2n<uint32_t>(a163, p163, 16));
        cfg.b = std::shared_ptr<mp_gf2n<uint32_t>>(new mp_gf2n<uint32_t>(b163, p163, 16));
        cfg.mod.k = 6;
        cfg.mod.mod_bits = 163;
        cfg.mod.blog2 = 32;
        cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

        mp_gf2n<uint32_t> x("3F0EBA16286A2D57EA0991168D4994637E8343E36", p163, 16);
        mp_gf2n<uint32_t> y("D51FBC6C71A0094FA2CDD545B11C5C0C797324F1", p163, 16);

        weierstrass_binary_affine<uint32_t> pbase(cfg, x, y);
        weierstrass_binary_affine<uint32_t> p(cfg, x, y);
        pbase.negate(cfg);
        p.doubling(cfg, 1);
        p.addition(cfg, pbase);
        EXPECT(p.x().get_str(16, true) == "3F0EBA16286A2D57EA0991168D4994637E8343E36");
        EXPECT(p.y().get_str(16, true) == "D51FBC6C71A0094FA2CDD545B11C5C0C797324F1");
    },
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

