/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <memory>


namespace phantom {
namespace elliptic {

/// Elliptic Curve parameters
struct ec_params_t {
    size_t      num_bits;
    size_t      num_bytes;
    const char* p;
    const char* order_m;
    const char* a;
    const char* b;
    const char* g_x;
    const char* g_y;
    const char* g_x_dual;
    const char* g_y_dual;
    const char* name;
};

/** 
 * @brief Elliptic curve parameters
 */
class curves
{
public:
    static const ec_params_t param_ec_secp192r1;
    static const ec_params_t param_ec_secp224r1;
    static const ec_params_t param_ec_secp256r1;
    static const ec_params_t param_ec_secp384r1;
    static const ec_params_t param_ec_secp521r1;

    static const ec_params_t param_ec_sect163r2;
    static const ec_params_t param_ec_sect233r1;
    static const ec_params_t param_ec_sect283r1;
    static const ec_params_t param_ec_sect409r1;
    static const ec_params_t param_ec_sect571r1;

    static const ec_params_t param_ec_sect163k1;
    static const ec_params_t param_ec_sect233k1;
    static const ec_params_t param_ec_sect283k1;
    static const ec_params_t param_ec_sect409k1;
    static const ec_params_t param_ec_sect571k1;

    static const ec_params_t param_ec_curve25519;
    static const ec_params_t param_ec_curve448;
    static const ec_params_t param_ec_edwards25519;
    static const ec_params_t param_ec_edwards448;
};

}  // namespace elliptic
}  // namespace phantom
