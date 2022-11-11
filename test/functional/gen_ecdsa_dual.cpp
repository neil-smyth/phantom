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
#include "ecc/weierstrass_prime_affine.hpp"
#include "ecc/curves.hpp"

using namespace phantom;    // NOLINT
using namespace core;       // NOLINT
using namespace elliptic;   // NOLINT

int calc(ec_params_t curve)
{
    ecc_config<uint32_t> cfg;
    cfg.mod.mod = mpz<uint32_t>(curve.p, 16);
    cfg.order_m = mpz<uint32_t>(curve.order_m, 16);
    cfg.a = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(curve.a, 16));
    cfg.b = std::shared_ptr<mpz<uint32_t>>(new mpz<uint32_t>(curve.b, 16));
    cfg.mod.k = (curve.num_bits + std::numeric_limits<uint32_t>::digits - 1) >> bits_log2<uint32_t>::value();
    cfg.mod.mod_bits = cfg.mod.mod.sizeinbase(2);
    cfg.mod.blog2 = 32;
    cfg.mod.reduction = reduction_e::REDUCTION_MONTGOMERY;

    mpz<uint32_t> temp;
    temp.setbit(cfg.mod.blog2 * cfg.mod.k * 2);
    mpz<uint32_t>::tdiv_qr(cfg.mod.mod_inv, cfg.mod.mont_R2, temp, cfg.mod.mod);

    mpz<uint32_t> x(curve.g_x, 16);
    mpz<uint32_t> y(curve.g_y, 16);
    weierstrass_prime_affine<uint32_t> p(cfg, x, y);

    mpz<uint32_t> R, temp_m, s, t;
    R.setbit(cfg.mod.blog2 * cfg.mod.k);
    temp_m = cfg.mod.mod;
    mpz<uint32_t>::gcdext(temp, s, t, R, temp_m);
    cfg.mod.mont_inv = 0;
    if (t.get_limbsize() > 0) {
        // (R[0] - t[0]) mod B, R[0] is always 0
        cfg.mod.mont_inv = t.is_negative()? t[0] : -t[0];
    }

    std::cout << "bits = " << (((((cfg.mod.mod_bits + 7) >> 3) + 1) >> 1) << 3) << std::endl;
    p.doubling(cfg, ((((cfg.mod.mod_bits + 7) >> 3) + 1) >> 1) << 3);

    mpz<uint32_t> xr, yr;
    p.convert_from(cfg, &xr, &yr);

    std::cout << curve.name << ":" << std::endl;
    std::cout << "x = " << xr.get_str(16) << std::endl;
    std::cout << "y = " << yr.get_str(16) << std::endl;

    return 0;
}

int main(int argc, char* argv[])
{
    (void) argc;
    (void) argv;

    calc(curves::param_ec_secp192r1);
    calc(curves::param_ec_secp224r1);
    calc(curves::param_ec_secp256r1);
    calc(curves::param_ec_secp384r1);
    calc(curves::param_ec_secp521r1);

    return 0;
}
