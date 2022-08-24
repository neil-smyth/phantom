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

size_t num163_bits     = 192;
size_t num163_bytes    = 24;
const char* p163       = "800000000000000000000000000000000000000c9";
const char* p163_inv   = "1000000000000000000000000000000010000000000000001";
const char* order_m163 = "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831";
const char* a163       = "1";
const char* b163       = "20a601907b8c953ca1481eb10512f78744a3205fd";
const char* g_x163     = "3f0eba16286a2d57ea0991168d4994637e8343e36";
const char* g_y163     = "0d51fbc6c71a0094fa2cdd545b11c5c0c797324f1";

static ecc_config<uint32_t> setup_32_b163()
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
    cfg.mod.reduction = reduction_e::REDUCTION_NAIVE;
    return cfg;
}

static ecc_config<uint32_t> setup_32_b233_koblitz()
{
    ecc_config<uint32_t> cfg;
    cfg.mod.mod = mpz<uint32_t>("20000000000000000000000000000000000000004000000000000000001", 16);
    cfg.mod.mod_inv = mpz<uint32_t>(p163_inv, 16);
    cfg.order_m = mpz<uint32_t>(order_m163, 16);
    cfg.a_is_1 = false;
    cfg.a_is_minus_3 = false;
    cfg.a_is_zero = true;
    cfg.b_is_1 = true;
    cfg.a = std::shared_ptr<mp_gf2n<uint32_t>>(
        new mp_gf2n<uint32_t>("0", "20000000000000000000000000000000000000004000000000000000001", 16));
    cfg.b = std::shared_ptr<mp_gf2n<uint32_t>>(
        new mp_gf2n<uint32_t>("1", "20000000000000000000000000000000000000004000000000000000001", 16));
    cfg.mod.k = 8;
    cfg.mod.mod_bits = 233;
    cfg.mod.blog2 = 32;
    cfg.mod.reduction = reduction_e::REDUCTION_NAIVE;
    return cfg;
}

const lest::test specification[] =
{
    CASE("Affine scalar multiplication with empty secret - 32-bit")
    {
        mp_gf2n<uint32_t> x1;
        mp_gf2n<uint32_t> y1;
        ecc_config<uint32_t> cfg = setup_32_b163();

        ecc<uint32_t> ec(cfg,
                         field_e::WEIERSTRASS_BINARY_FIELD,
                         type_e::POINT_COORD_AFFINE,
                         scalar_coding_e::ECC_BINARY);
        retcode_e rc;

        auto secret = phantom_vector<uint8_t>();

        weierstrass_binary_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == SECRET_IS_ZERO);

        mp_gf2n<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == SCALAR_MUL_ERROR);
        EXPECT(xr.get_str(16, true) == x1.get_str(16, true));
        EXPECT(yr.get_str(16, true) == y1.get_str(16, true));
    },
    CASE("Affine scalar multiplication with zero secret - 32-bit")
    {
        mp_gf2n<uint32_t> x1;
        mp_gf2n<uint32_t> y1;
        ecc_config<uint32_t> cfg = setup_32_b163();

        ecc<uint32_t> ec(cfg,
                         field_e::WEIERSTRASS_BINARY_FIELD,
                         type_e::POINT_COORD_AFFINE,
                         scalar_coding_e::ECC_BINARY);
        retcode_e rc;

        mpz<uint8_t> k("0", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        weierstrass_binary_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == SECRET_IS_ZERO);

        mp_gf2n<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == SCALAR_MUL_ERROR);
        EXPECT(xr.get_str(16, true) == x1.get_str(16, true));
        EXPECT(yr.get_str(16, true) == y1.get_str(16, true));
    },
    CASE("Affine scalar multiplication, binary, k = 1 - 32-bit")
    {
        mp_gf2n<uint32_t> x1("3F0EBA16286A2D57EA0991168D4994637E8343E36", p163, 16);
        mp_gf2n<uint32_t> y1("D51FBC6C71A0094FA2CDD545B11C5C0C797324F1", p163, 16);
        ecc_config<uint32_t> cfg = setup_32_b163();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_BINARY_FIELD,
            type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("1", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_binary_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mp_gf2n<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16, true) == x1.get_str(16, true));
        EXPECT(yr.get_str(16, true) == y1.get_str(16, true));
    },
    CASE("Affine scalar multiplication, binary, k = 3 - 32-bit")
    {
        mp_gf2n<uint32_t> x1("3F0EBA16286A2D57EA0991168D4994637E8343E36", p163, 16);
        mp_gf2n<uint32_t> y1("D51FBC6C71A0094FA2CDD545B11C5C0C797324F1", p163, 16);
        ecc_config<uint32_t> cfg = setup_32_b163();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_BINARY_FIELD,
            type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("3", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_binary_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mp_gf2n<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16, true) == "634000577F86AA315009D6F9B906691F6EDD691FE");
        EXPECT(yr.get_str(16, true) == "401A3DE0D6C2EC014E6FBA5653587BD45DC2230BE");
    },
    CASE("Affine scalar multiplication, binary, k = 16 - 32-bit")
    {
        mp_gf2n<uint32_t> x1("3F0EBA16286A2D57EA0991168D4994637E8343E36", p163, 16);
        mp_gf2n<uint32_t> y1("D51FBC6C71A0094FA2CDD545B11C5C0C797324F1", p163, 16);
        ecc_config<uint32_t> cfg = setup_32_b163();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_BINARY_FIELD,
            type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("16", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_binary_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mp_gf2n<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16, true) == "41FBD3ADBAB2C4349F5518C8BC4BD531F079DC92B");
        EXPECT(yr.get_str(16, true) == "611E336597E3A9C3AB428144731DC459A5500F1E");
    },
    CASE("Affine scalar multiplication, binary, k = 20 - 32-bit")
    {
        mp_gf2n<uint32_t> x1("3F0EBA16286A2D57EA0991168D4994637E8343E36", p163, 16);
        mp_gf2n<uint32_t> y1("D51FBC6C71A0094FA2CDD545B11C5C0C797324F1", p163, 16);
        ecc_config<uint32_t> cfg = setup_32_b163();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_BINARY_FIELD,
            type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("20", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_binary_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mp_gf2n<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16, true) == "AED08C6DDCF8E345006BD2F6989C3F92CB508A82");
        EXPECT(yr.get_str(16, true) == "253947FD52A1D327DCAF5224172C24E81BE22C2B3");
    },
    CASE("Affine scalar multiplication, binary, k = large - 32-bit")
    {
        mp_gf2n<uint32_t> x1("3F0EBA16286A2D57EA0991168D4994637E8343E36", p163, 16);
        mp_gf2n<uint32_t> y1("D51FBC6C71A0094FA2CDD545B11C5C0C797324F1", p163, 16);
        ecc_config<uint32_t> cfg = setup_32_b163();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_BINARY_FIELD,
            type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("5846006549323611672814742442876390689256843201586", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_binary_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mp_gf2n<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16, true) == "3F0EBA16286A2D57EA0991168D4994637E8343E36");
        EXPECT(yr.get_str(16, true) == "325F41D0EF702DC310254C42D65851A3B91471AC7");
    },
    CASE("Affine scalar multiplication, binary, k = large - 32-bit")
    {
        mp_gf2n<uint32_t> x1("17232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126",
                             "20000000000000000000000000000000000000004000000000000000001",
                             16);
        mp_gf2n<uint32_t> y1("1db537dece819b7f70f555a67c427a8cd9bf18aeb9b56e0c11056fae6a3",
                             "20000000000000000000000000000000000000004000000000000000001",
                             16);
        ecc_config<uint32_t> cfg = setup_32_b233_koblitz();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_BINARY_FIELD,
            type_e::POINT_COORD_AFFINE, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("3450873173395281893717377931138512760570940988862252126328087024741342", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_binary_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mp_gf2n<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16, true) == "17232BA853A7E731AF129F22FF4149563A419C26BF50A4C9D6EEFAD6126");
        EXPECT(yr.get_str(16, true) == "A961C769D267C4EDFE7CA84830333DAE3FE848806E5CAC5C7EB9578785");
    },
    CASE("Jacobian scalar multiplication, binary, k = large - 32-bit")
    {
        mp_gf2n<uint32_t> x1("17232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126",
                             "20000000000000000000000000000000000000004000000000000000001",
                             16);
        mp_gf2n<uint32_t> y1("1db537dece819b7f70f555a67c427a8cd9bf18aeb9b56e0c11056fae6a3",
                             "20000000000000000000000000000000000000004000000000000000001",
                             16);
        ecc_config<uint32_t> cfg = setup_32_b233_koblitz();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_BINARY_FIELD,
            type_e::POINT_COORD_JACOBIAN, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("2", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_binary_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mp_gf2n<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16, true) == "1A96A52534C02824C92539163F2ED13243FEB57B45ADBE4CF7EC61957F6");
        EXPECT(yr.get_str(16, true) == "1F9D11CCD5FF37C021BB64DFF8DF25AF3EBC5C3F9BFC5CB17B2203703A8");
    },
    CASE("Jacobian scalar multiplication, binary, k = large - 32-bit")
    {
        mp_gf2n<uint32_t> x1("17232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126",
                             "20000000000000000000000000000000000000004000000000000000001",
                             16);
        mp_gf2n<uint32_t> y1("1db537dece819b7f70f555a67c427a8cd9bf18aeb9b56e0c11056fae6a3",
                             "20000000000000000000000000000000000000004000000000000000001",
                             16);
        ecc_config<uint32_t> cfg = setup_32_b233_koblitz();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_BINARY_FIELD,
            type_e::POINT_COORD_JACOBIAN, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("3", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_binary_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mp_gf2n<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16, true) == "4656E0AABBE341407715CA4A7FAC287B41BAA1F789C29BFA27E53A7A46");
        EXPECT(yr.get_str(16, true) == "F79A7245FBA513DF787A64C618E97EBCC078638EBAAA562E9862BC00CE");
    },
    CASE("Jacobian scalar multiplication, binary, k = large - 32-bit")
    {
        mp_gf2n<uint32_t> x1("17232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126",
                             "20000000000000000000000000000000000000004000000000000000001",
                             16);
        mp_gf2n<uint32_t> y1("1db537dece819b7f70f555a67c427a8cd9bf18aeb9b56e0c11056fae6a3",
                             "20000000000000000000000000000000000000004000000000000000001",
                             16);
        ecc_config<uint32_t> cfg = setup_32_b233_koblitz();

        ecc<uint32_t> ec(cfg, field_e::WEIERSTRASS_BINARY_FIELD,
            type_e::POINT_COORD_JACOBIAN, scalar_coding_e::ECC_BINARY);

        mpz<uint8_t> k("3450873173395281893717377931138512760570940988862252126328087024741342", 10);
        auto secret = phantom_vector<uint8_t>(k.get_limbs().begin(), k.get_limbs().end());

        retcode_e rc;

        weierstrass_binary_affine<uint32_t> p(cfg, x1, y1);
        rc = ec.setup(p);
        EXPECT(rc == POINT_OK);
        rc = ec.scalar_point_mul(secret);
        EXPECT(rc == POINT_OK);

        mp_gf2n<uint32_t> xr, yr;
        rc = ec.get(&xr, &yr);
        EXPECT(rc == POINT_OK);
        EXPECT(xr.get_str(16, true) == "17232BA853A7E731AF129F22FF4149563A419C26BF50A4C9D6EEFAD6126");
        EXPECT(yr.get_str(16, true) == "A961C769D267C4EDFE7CA84830333DAE3FE848806E5CAC5C7EB9578785");
    }
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

