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
using namespace elliptic;  // NOLINT
using namespace schemes;   // NOLINT

size_t num192_bits = 192;
size_t num192_bytes = 24;
const char* p192 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF";
const char* p192_inv = "1000000000000000000000000000000010000000000000001";
const char* order_m192 = "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831";
const char* a192 = "-3";
const char* b192 = "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1";
const char* g_x192 = "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012";
const char* g_y192 = "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811";
std::unique_ptr<mod_custom<uint32_t>> cst192;

size_t num255_bits = 255;
size_t num255_bytes = 32;
const char* curve25519 = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";
const char* curve25519_inv = "2000000000000000000000000000000000000000000000000000000000000004c";
const char* order_m25519 = "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";
const char* a25519 = "76D06";
const char* b25519 = "1";
const char* g_x25519 = "9";
const char* g_y25519 = "20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9";

size_t num_ed448_bits      = 448;
size_t num_ed448_bytes     = 56;
const char* edwards448     = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
                             "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const char* edwards448_inv = "100000000000000000000000000000000000000000000000000000001"
                             "00000000000000000000000000000000000000000000000000000002";
const char* order_m448     = "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                             "7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3";
const char* d448           = "-98a9";
const char* g_x448         = "4F1970C66BED0DED221D15A622BF36DA9E146570470F1767EA6DE324"
                             "A3D3A46412AE1AF72AB66511433B80E18B00938E2626A82BC70CC05E";
const char* g_y448         = "693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E"
                             "05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14";

const char* g_xed25519 = "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a";
const char* g_yed25519 = "6666666666666666666666666666666666666666666666666666666666666658";
const char* d25519 = "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3";

static ecc_config<uint32_t> setup_32_p192()
{
    ecc_config<uint32_t> cfg;
    cfg.mod.mod = mpz<uint32_t>(p192, 16);
//    cfg.mod.mod_inv = mpz<uint32_t>(p192_inv, 16);
    cfg.order_m = mpz<uint32_t>(order_m192, 16);
    cfg.a_is_minus_3 = true;
    auto a = new mpz<uint32_t>(a192, 16);
    cfg.a = std::shared_ptr<mpz<uint32_t>>(a);
    cfg.b = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(b192, 16));
    cfg.mod.k = 6;
    cfg.mod.blog2 = 32;
    cfg.mod.mod_bits = 192;
    cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

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
    }

    cst192 = std::unique_ptr<mod_custom<uint32_t>>(new mod_solinas_secp192r1<uint32_t>());
    cfg.mod.cst = cst192.get();
    return cfg;
}

static ecc_config<uint32_t> setup_32_p255()
{
    ecc_config<uint32_t> cfg;
    cfg.mod.mod = mpz<uint32_t>(curve25519, 16);
    cfg.order_m = mpz<uint32_t>(order_m25519, 16);
    cfg.a_is_minus_3 = true;
    auto a = new mpz<uint32_t>(a25519, 16);
    auto b = new mpz<uint32_t>(b25519, 16);
    auto a24 = new mpz<uint32_t>(a25519, 16);
    a24->add(uint32_t(2));
    *a24 = *a24 >> 2;
    cfg.a = std::shared_ptr<mpz<uint32_t>>(a);
    cfg.b = std::shared_ptr<mpz<uint32_t>>(b);
    cfg.d = std::shared_ptr<mpz<uint32_t>>(a24);
    cfg.mod.k = 8;
    cfg.mod.blog2 = 32;
    cfg.mod.mod_bits = 255;
    cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

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

static ecc_config<uint32_t> setup_32_edwards448()
{
    ecc_config<uint32_t> cfg;
    cfg.mod.mod = mpz<uint32_t>(edwards448, 16);
    cfg.a_is_minus_3 = false;
    auto d = new mpz<uint32_t>(d448, 16);
    cfg.d = std::shared_ptr<mpz<uint32_t>>(d);
    cfg.mod.k = 14;
    cfg.mod.blog2 = 32;
    cfg.mod.mod_bits = 448;
    cfg.mod.reduction = reduction_e::REDUCTION_BARRETT;

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

        d->mul_mont(cfg.mod.mont_R2, cfg.mod);
    }

    return cfg;
}

static ecc_config<uint32_t> setup_32_edwards25519()
{
    ecc_config<uint32_t> cfg;
    cfg.mod.mod = mpz<uint32_t>(curve25519, 16);
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

        d->mul_mont(cfg.mod.mont_R2, cfg.mod);
    }

    return cfg;
}

const lest::test specification[] =
{
    CASE("Affine scalar multiplication with empty secret - 32-bit")
    {
        mpz<uint32_t> x1;
        mpz<uint32_t> y1;
        ecc_config<uint32_t> cfg = setup_32_p192();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_PRIME_FIELD,
            type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_BINARY);
        retcode_e rc;

        auto secret = phantom_vector<uint8_t>();

        weierstrass_prime_affine<uint32_t> p(cfg, x1, y1);
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
        ecc_config<uint32_t> cfg = setup_32_p192();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_PRIME_FIELD,
            type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_BINARY);
        retcode_e rc;

        mpz<uint8_t> k("0", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        weierstrass_prime_affine<uint32_t> p(cfg, x1, y1);
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
        mpz<uint32_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y1("7192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        ecc_config<uint32_t> cfg = setup_32_p192();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_PRIME_FIELD,
            type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("1", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_prime_affine<uint32_t> p(cfg, x1, y1);
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
        mpz<uint32_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y1("7192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        ecc_config<uint32_t> cfg = setup_32_p192();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_PRIME_FIELD,
            type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_PRE_2, false);

        mpz<uint8_t> k("1", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_prime_affine<uint32_t> p(cfg, x1, y1);
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
    CASE("Affine scalar multiplication, binary, k = 2 - 32-bit")
    {
        mpz<uint32_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y1("7192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        mpz<uint32_t> x2("DAFEBF5828783F2AD35534631588A3F629A70FB16982A888", 16);
        mpz<uint32_t> y2("DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB", 16);

        ecc_config<uint32_t> cfg = setup_32_p192();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_PRIME_FIELD,
            type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("2", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_prime_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr == x2);
        EXPECT(yr == y2);
    },
    CASE("Affine scalar multiplication, binary, k = large - 32-bit")
    {
        mpz<uint32_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y1("7192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        mpz<uint32_t> x2("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y2("F8E6D46A003725879CEFEE1294DB32298C06885EE186B7EE", 16);

        ecc_config<uint32_t> cfg = setup_32_p192();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_PRIME_FIELD,
            type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("6277101735386680763835789423176059013767194773182842284080", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_prime_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr == x2);
        EXPECT(yr == y2);
    },
    CASE("Affine scalar multiplication, NAF-2, k = large - 32-bit")
    {
        mpz<uint32_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y1("7192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        mpz<uint32_t> x2("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y2("F8E6D46A003725879CEFEE1294DB32298C06885EE186B7EE", 16);

        ecc_config<uint32_t> cfg = setup_32_p192();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_PRIME_FIELD,
            type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_NAF_2, false);

        mpz<uint8_t> k("6277101735386680763835789423176059013767194773182842284080", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_prime_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Affine scalar multiplication, PRE_2, k = large - 32-bit")
    {
        mpz<uint32_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y1("7192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        mpz<uint32_t> x2("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y2("F8E6D46A003725879CEFEE1294DB32298C06885EE186B7EE", 16);

        ecc_config<uint32_t> cfg = setup_32_p192();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_PRIME_FIELD,
            type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_PRE_2, false);

        mpz<uint8_t> k("6277101735386680763835789423176059013767194773182842284080", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_prime_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Affine scalar multiplication, PRE_4, k = large - 32-bit")
    {
        mpz<uint32_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y1("7192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        mpz<uint32_t> x2("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y2("F8E6D46A003725879CEFEE1294DB32298C06885EE186B7EE", 16);

        ecc_config<uint32_t> cfg = setup_32_p192();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_PRIME_FIELD,
            type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_PRE_4, false);

        mpz<uint8_t> k("6277101735386680763835789423176059013767194773182842284080", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_prime_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Affine scalar multiplication, PRE_6, k = large - 32-bit")
    {
        mpz<uint32_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y1("7192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        mpz<uint32_t> x2("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y2("F8E6D46A003725879CEFEE1294DB32298C06885EE186B7EE", 16);

        ecc_config<uint32_t> cfg = setup_32_p192();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_PRIME_FIELD,
            type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_PRE_6, false);

        mpz<uint8_t> k("6277101735386680763835789423176059013767194773182842284080", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_prime_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Projective scalar multiplication, binary, k = 1 - 32-bit")
    {
        mpz<uint32_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y1("7192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        ecc_config<uint32_t> cfg = setup_32_p192();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_PRIME_FIELD,
            type_e::POINT_COORD_PROJECTIVE, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("1", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_prime_projective<uint32_t> p(cfg, x1, y1);
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
    CASE("Projective scalar multiplication, binary, k = 2 - 32-bit")
    {
        mpz<uint32_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y1("7192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        mpz<uint32_t> x2("DAFEBF5828783F2AD35534631588A3F629A70FB16982A888", 16);
        mpz<uint32_t> y2("DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB", 16);

        ecc_config<uint32_t> cfg = setup_32_p192();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_PRIME_FIELD,
            type_e::POINT_COORD_PROJECTIVE, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("2", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_prime_projective<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr == x2);
        EXPECT(yr == y2);
    },
    CASE("Projective scalar multiplication, binary, k = large - 32-bit")
    {
        mpz<uint32_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y1("7192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        mpz<uint32_t> x2("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y2("F8E6D46A003725879CEFEE1294DB32298C06885EE186B7EE", 16);

        ecc_config<uint32_t> cfg = setup_32_p192();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_PRIME_FIELD,
            type_e::POINT_COORD_PROJECTIVE, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("6277101735386680763835789423176059013767194773182842284080", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_prime_projective<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr == x2);
        EXPECT(yr == y2);
    },
    CASE("Projective scalar multiplication, NAF-2, k = large - 32-bit")
    {
        mpz<uint32_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y1("7192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        mpz<uint32_t> x2("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y2("F8E6D46A003725879CEFEE1294DB32298C06885EE186B7EE", 16);

        ecc_config<uint32_t> cfg = setup_32_p192();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_PRIME_FIELD,
            type_e::POINT_COORD_PROJECTIVE, scalar_coding_e::ECC_NAF_2, false);

        mpz<uint8_t> k("6277101735386680763835789423176059013767194773182842284080", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_prime_projective<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Projective scalar multiplication, NAF-3, k = large - 32-bit")
    {
        mpz<uint32_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y1("7192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        mpz<uint32_t> x2("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y2("F8E6D46A003725879CEFEE1294DB32298C06885EE186B7EE", 16);

        ecc_config<uint32_t> cfg = setup_32_p192();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_PRIME_FIELD,
            type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_NAF_3, false);

        mpz<uint8_t> k("6277101735386680763835789423176059013767194773182842284080", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_prime_projective<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Jacobian scalar multiplication, binary, k = 1 - 32-bit")
    {
        mpz<uint32_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y1("7192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        ecc_config<uint32_t> cfg = setup_32_p192();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_PRIME_FIELD,
            type_e::POINT_COORD_JACOBIAN, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("1", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_prime_jacobian<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16) == x1.get_str(16));
        EXPECT(yr.get_str(16) == y1.get_str(16));
    },
    CASE("Jacobian scalar multiplication, binary, k = 2 - 32-bit")
    {
        mpz<uint32_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y1("7192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        mpz<uint32_t> x2("DAFEBF5828783F2AD35534631588A3F629A70FB16982A888", 16);
        mpz<uint32_t> y2("DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB", 16);

        ecc_config<uint32_t> cfg = setup_32_p192();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_PRIME_FIELD,
            type_e::POINT_COORD_JACOBIAN, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("2", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_prime_jacobian<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Jacobian scalar multiplication, binary, k = large - 32-bit")
    {
        mpz<uint32_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y1("7192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        mpz<uint32_t> x2("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y2("F8E6D46A003725879CEFEE1294DB32298C06885EE186B7EE", 16);

        ecc_config<uint32_t> cfg = setup_32_p192();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_PRIME_FIELD,
            type_e::POINT_COORD_JACOBIAN, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("6277101735386680763835789423176059013767194773182842284080", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_prime_jacobian<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Jacobian scalar multiplication, NAF-2, k = large - 32-bit")
    {
        mpz<uint32_t> x1("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y1("7192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16);
        mpz<uint32_t> x2("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16);
        mpz<uint32_t> y2("F8E6D46A003725879CEFEE1294DB32298C06885EE186B7EE", 16);

        ecc_config<uint32_t> cfg = setup_32_p192();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_PRIME_FIELD,
            type_e::POINT_COORD_JACOBIAN, scalar_coding_e::ECC_NAF_2, false);

        mpz<uint8_t> k("6277101735386680763835789423176059013767194773182842284080", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_prime_jacobian<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Projective XZ Montgomery ladder scalar multiplication, ECC_MONT_LADDER, k = large - 32-bit")
    {
        mpz<uint32_t> x1("9", 16);
        mpz<uint32_t> y1("20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9", 16);
        mpz<uint32_t> x2("7bbaacfdebfedf294b312f5db54bd7e8b9450c7e344ce76a82b26f149350d786", 16);
        mpz<uint32_t> y2("6a835f76bd362041c7939ed323faf7c76a6d82a79bdc76cc7d2fc5db94c74c74", 16);

        ecc_config<uint32_t> cfg = setup_32_p255();

        ecc<uint32_t> ec(cfg, field_e::MONTGOMERY_PRIME_FIELD,
            type_e::POINT_COORD_PROJECTIVE, scalar_coding_e::ECC_MONT_LADDER, false);

        mpz<uint8_t> k("6277101735386680763835789423176059013767194773182842284080", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_prime_jacobian<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16) == x2.get_str(16));
    },
    CASE("Affine Edwards448 scalar multiplication, binary, k = 2 - 32-bit")
    {
        mpz<uint32_t> x1(g_x448, 16);
        mpz<uint32_t> y1(g_y448, 16);
        mpz<uint32_t> x2("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9"
                         "55555555555555555555555555555555555555555555555555555555", 16);
        mpz<uint32_t> y2("ae05e9634ad7048db359d6205086c2b0036ed7a035884dd7b7e36d72"
                         "8ad8c4b80d6565833a2a3098bbbcb2bed1cda06bdaeafbcdea9386ed", 16);

        ecc_config<uint32_t> cfg = setup_32_edwards448();

        ecc<uint32_t> ec(cfg, field_e::EDWARDS_PRIME_FIELD, type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("2", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        edwards_prime_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Affine Edwards448 scalar multiplication, binary, k = 315879992934921009807084090 - 32-bit")
    {
        mpz<uint32_t> x1(g_x448, 16);
        mpz<uint32_t> y1(g_y448, 16);
        mpz<uint32_t> x2("c1ed0c5162d9465f43f22b73801fef0d858f1458706fda34958bc159"
                         "87317f420a78927e2860414c35f93fcc3a797472c28734c7f68a5363", 16);
        mpz<uint32_t> y2("158f2d5aac19a3680075adcd14be18266d5c3b7a02b2968bb2efd07e"
                         "718ff019c2890f7e376467e459a288a36558e0cdf8eb4dde33122620", 16);

        ecc_config<uint32_t> cfg = setup_32_edwards448();

        ecc<uint32_t> ec(cfg, field_e::EDWARDS_PRIME_FIELD, type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("315879992934921009807084090", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        edwards_prime_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Projective Edwards448 scalar multiplication, binary, k = 2 - 32-bit")
    {
        mpz<uint32_t> x1(g_x448, 16);
        mpz<uint32_t> y1(g_y448, 16);
        mpz<uint32_t> x2("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9"
                         "55555555555555555555555555555555555555555555555555555555", 16);
        mpz<uint32_t> y2("ae05e9634ad7048db359d6205086c2b0036ed7a035884dd7b7e36d72"
                         "8ad8c4b80d6565833a2a3098bbbcb2bed1cda06bdaeafbcdea9386ed", 16);

        ecc_config<uint32_t> cfg = setup_32_edwards448();

        ecc<uint32_t> ec(cfg, field_e::EDWARDS_PRIME_FIELD, type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("2", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        edwards_prime_projective<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Projective Edwards448 scalar multiplication, binary, k = 315879992934921009807084090 - 32-bit")
    {
        mpz<uint32_t> x1(g_x448, 16);
        mpz<uint32_t> y1(g_y448, 16);
        mpz<uint32_t> x2("c1ed0c5162d9465f43f22b73801fef0d858f1458706fda34958bc159"
                         "87317f420a78927e2860414c35f93fcc3a797472c28734c7f68a5363", 16);
        mpz<uint32_t> y2("158f2d5aac19a3680075adcd14be18266d5c3b7a02b2968bb2efd07e"
                         "718ff019c2890f7e376467e459a288a36558e0cdf8eb4dde33122620", 16);

        ecc_config<uint32_t> cfg = setup_32_edwards448();

        ecc<uint32_t> ec(cfg, field_e::EDWARDS_PRIME_FIELD, type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("315879992934921009807084090", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        edwards_prime_projective<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
    CASE("Projective Edwards448 scalar multiplication, binary, "
         "k = 36144925721603087658594284515452164870581325872720374094707712194495455132720 - 32-bit")
    {
        mpz<uint32_t> x1(g_xed25519, 16);
        mpz<uint32_t> y1(g_yed25519, 16);
        mpz<uint32_t> x2("55d0e09a2b9d34292297e08d60d0f620c513d47253187c24b12786bd777645ce", 16);
        mpz<uint32_t> y2("1a5107f7681a02af2523a6daf372e10e3a0764c9d3fe4bd5b70ab18201985ad7", 16);

        ecc_config<uint32_t> cfg = setup_32_edwards25519();

        ecc<uint32_t> ec(cfg, field_e::EDWARDS_PRIME_FIELD,
            type_e::POINT_COORD_PROJECTIVE, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("36144925721603087658594284515452164870581325872720374094707712194495455132720", 10);
        phantom_vector<uint8_t> vec = {
            0x4f, 0xe9, 0x4d, 0x90, 0x06, 0xf0, 0x20, 0xa5,
            0xa3, 0xc0, 0x80, 0xd9, 0x68, 0x27, 0xff, 0xfd,
            0x3c, 0x01, 0x0a, 0xc0, 0xf1, 0x2e, 0x7a, 0x42,
            0xcb, 0x33, 0x28, 0x4f, 0x86, 0x83, 0x7c, 0x30
        };
        std::reverse(vec.begin(), vec.end());
        k.set_bytes(vec);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        edwards_prime_projective<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mpz<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16) == x2.get_str(16));
        EXPECT(yr.get_str(16) == y2.get_str(16));
    },
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

