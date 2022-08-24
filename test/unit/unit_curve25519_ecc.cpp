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
#include "ecc/ecc.hpp"
#include "schemes/key_exchange/ecdh/ctx_ecdh.hpp"

namespace phantom {
using namespace core;      // NOLINT
using namespace schemes;   // NOLINT
using namespace elliptic;  // NOLINT

const char* curve25519 = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";
const char* curve25519_inv = "2000000000000000000000000000000000000000000000000000000000000004c";
const char* order_m25519 = "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";
const char* a25519 = "76D06";
const char* b25519 = "1";
const char* g_x25519 = "9";
const char* g_y25519 = "20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9";
std::unique_ptr<mod_custom<uint32_t>> cst192;

static ecc_config<uint32_t> setup_32_curve25519(reduction_e redtype)
{
    ecc_config<uint32_t> cfg;
    cfg.mod.mod = mpz<uint32_t>(curve25519, 16);
    cfg.mod.mod_inv = mpz<uint32_t>(curve25519_inv, 16);
    cfg.order_m = mpz<uint32_t>(order_m25519, 16);
    cfg.a_is_minus_3 = true;
    auto a = new mpz<uint32_t>(a25519, 16);
    cfg.a = std::shared_ptr<mpz<uint32_t>>(a);
    auto b = new mpz<uint32_t>(b25519, 16);
    cfg.b = std::shared_ptr<mpz<uint32_t>>(b);
    auto a24 = new mpz<uint32_t>(a25519, 16);
    *a24 = (*a24 + uint32_t(2)) >> 2;
    cfg.d = std::shared_ptr<mpz<uint32_t>>(a24);
    cfg.mod.k = 8;
    cfg.mod.blog2 = 32;
    cfg.mod.mod_bits = 256;
    cfg.mod.reduction = redtype;

    mpz<uint32_t> temp;
    temp.setbit(cfg.mod.blog2 * cfg.mod.k * 2);
    mpz<uint32_t>::tdiv_qr(cfg.mod.mod_inv, cfg.mod.mont_R2, temp, cfg.mod.mod);

    if (REDUCTION_MONTGOMERY == cfg.mod.reduction) {
        mpz<uint32_t> R, temp_m, s, t;
        R.setbit(std::numeric_limits<uint32_t>::digits * cfg.mod.k);
        temp_m = cfg.mod.mod;
        mpz<uint32_t>::gcdext(temp, s, t, R, temp_m);
        cfg.mod.mont_inv = 0;
        if (t.get_limbsize() > 0) {
            // (R[0] - t[0]) mod B, R[0] is always 0
            cfg.mod.mont_inv = t.is_negative()? t[0] : -t[0];
        }

        a->mul_mont(cfg.mod.mont_R2, cfg.mod);
        b->mul_mont(cfg.mod.mont_R2, cfg.mod);
        a24->mul_mont(cfg.mod.mont_R2, cfg.mod);
    }

    return cfg;
}

const lest::test specification[] =
{
    CASE("Affine scalar multiplication with empty secret - 32-bit")
    {
        mpz<uint32_t> x1;
        mpz<uint32_t> y1;
        ecc_config<uint32_t> cfg = setup_32_curve25519(reduction_e::REDUCTION_BARRETT);

        ecc<uint32_t> ec(cfg, field_e::MONTGOMERY_PRIME_FIELD, type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_BINARY);
        retcode_e rc;

        auto secret = phantom_vector<uint8_t>();

        montgomery_prime_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == SECRET_IS_ZERO);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == SCALAR_MUL_ERROR);
        EXPECT(xr == x1);
        EXPECT(yr == y1);
    },
    CASE("Affine scalar multiplication with zero secret - 32-bit")
    {
        mpz<uint32_t> x1;
        mpz<uint32_t> y1;
        ecc_config<uint32_t> cfg = setup_32_curve25519(reduction_e::REDUCTION_BARRETT);

        ecc<uint32_t> ec(cfg, field_e::MONTGOMERY_PRIME_FIELD, type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_BINARY);
        retcode_e rc;

        mpz<uint8_t> k("0", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        montgomery_prime_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == SECRET_IS_ZERO);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == SCALAR_MUL_ERROR);
        EXPECT(xr == x1);
        EXPECT(yr == y1);
    },
    CASE("Affine scalar multiplication, binary, k = 1 - 32-bit")
    {
        mpz<uint32_t> x1("216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A", 16);
        mpz<uint32_t> y1("6666666666666666666666666666666666666666666666666666666666666658", 16);
        ecc_config<uint32_t> cfg = setup_32_curve25519(reduction_e::REDUCTION_BARRETT);

        ecc<uint32_t> ec(cfg, field_e::MONTGOMERY_PRIME_FIELD, type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("1", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        montgomery_prime_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr == x1);
        EXPECT(yr == y1);
    },
    CASE("Affine scalar multiplication, binary, k = 1, PRE_2 - 32-bit")
    {
        mpz<uint32_t> x1("216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A", 16);
        mpz<uint32_t> y1("6666666666666666666666666666666666666666666666666666666666666658", 16);
        ecc_config<uint32_t> cfg = setup_32_curve25519(reduction_e::REDUCTION_BARRETT);

        ecc<uint32_t> ec(cfg, field_e::MONTGOMERY_PRIME_FIELD,
            type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_PRE_2, false);

        mpz<uint8_t> k("1", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        montgomery_prime_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr == x1);
        EXPECT(yr == y1);
    },
    CASE("Montgomery Projective scalar multiplication, binary, k = 2 - 32-bit")
    {
        mpz<uint32_t> x1("9", 16);
        mpz<uint32_t> y1("20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9", 16);
        mpz<uint32_t> x2("20d342d51873f1b7d9750c687d1571148f3f5ced1e350b5c5cae469cdd684efb", 16);
        mpz<uint32_t> y2("6c4a81fee8ff1751faf5ff6ba2d45d0c889a614d7272c6e14328fb9a38d20a8a", 16);

        ecc_config<uint32_t> cfg = setup_32_curve25519(reduction_e::REDUCTION_BARRETT);

        ecc<uint32_t> ec(cfg, field_e::MONTGOMERY_PRIME_FIELD,
            type_e::POINT_COORD_PROJECTIVE, scalar_coding_e::ECC_MONT_LADDER);

        mpz<uint8_t> k("2", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        montgomery_prime_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16) == x2.get_str(16));
    },
    CASE("Montgomery Projective scalar multiplication, binary, k = 10 - 32-bit")
    {
        mpz<uint32_t> x1("9", 16);
        mpz<uint32_t> y1("20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9", 16);
        mpz<uint32_t> x2("41eda655b159060471fb4ce5d7cb3fe43ee51843d2080e0383ce42892c3a9c7b", 16);
        mpz<uint32_t> y2("434070198545e6fc5c24bf947e913366ae1604e822325851a55d79e32ccd3bf6", 16);

        ecc_config<uint32_t> cfg = setup_32_curve25519(reduction_e::REDUCTION_MONTGOMERY);

        ecc<uint32_t> ec(cfg, field_e::MONTGOMERY_PRIME_FIELD,
            type_e::POINT_COORD_PROJECTIVE, scalar_coding_e::ECC_MONT_LADDER);

        mpz<uint8_t> k("10", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        montgomery_prime_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16) == x2.get_str(16));
    },
    CASE("Montgomery Projective scalar multiplication, binary, k = 10 - 32-bit")
    {
        mpz<uint32_t> x1("9", 16);
        mpz<uint32_t> y1("20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9", 16);
        mpz<uint32_t> x2("7bbaacfdebfedf294b312f5db54bd7e8b9450c7e344ce76a82b26f149350d786", 16);
        mpz<uint32_t> y2("6a835f76bd362041c7939ed323faf7c76a6d82a79bdc76cc7d2fc5db94c74c74", 16);

        ecc_config<uint32_t> cfg = setup_32_curve25519(reduction_e::REDUCTION_BARRETT);

        ecc<uint32_t> ec(cfg, field_e::MONTGOMERY_PRIME_FIELD,
            type_e::POINT_COORD_PROJECTIVE, scalar_coding_e::ECC_MONT_LADDER);

        mpz<uint8_t> k("6277101735386680763835789423176059013767194773182842284080", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        montgomery_prime_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16) == x2.get_str(16));
    },
    CASE("Montgomery Projective scalar multiplication, binary, "
         "k = 449A44BA44226A50185AFCC10A4C1462DD5E46824B15163B9D7C52F06BE346A0 - 32-bit")
    {
        mpz<uint32_t> x1("4C1CABD0A603A9103B35B326EC2466727C5FB124A4C19435DB3030586768DBE6", 16);
        mpz<uint32_t> y1("2", 10);
        mpz<uint32_t> x2("5285a2775507b454f7711c4903cfec324f088df24dea948e90c6e99d3755dac3", 16);

        ecc_config<uint32_t> cfg = setup_32_curve25519(reduction_e::REDUCTION_MONTGOMERY);

        ecc<uint32_t> ec(cfg, field_e::MONTGOMERY_PRIME_FIELD,
            type_e::POINT_COORD_PROJECTIVE, scalar_coding_e::ECC_MONT_LADDER);

        mpz<uint8_t> k("449A44BA44226A50185AFCC10A4C1462DD5E46824B15163B9D7C52F06BE346A0", 16);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        montgomery_prime_projective<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16) == x2.get_str(16));
    },
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

