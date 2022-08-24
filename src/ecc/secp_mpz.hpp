/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <cstdint>
#include <cmath>
#include <iomanip>
#include <limits>
#include <vector>

#include "core/mpz.hpp"
#include "core/template_helpers.hpp"


namespace phantom {
namespace elliptic {

/**
 * @brief Solinas modular reduction
 * 
 * @tparam T 
 */
template<typename T>
class secp_mpz : public core::mpz<T>
{
public:
    enum curve_e {
        secp192r1 = 0,
        secp224r1,
        secp256r1,
        secp384r1,
        secp521r1,
    };

    template<curve_e curve>
    static core::mpz<uint64_t>& mod_solinas(core::mpz<uint64_t>* a, const core::mod_config<uint64_t>& cfg)
    {
        if (*a < cfg.mod) {
            return *a;
        }

        phantom_vector<uint64_t> v;
        a->get_words(v);
        v.resize(6);
        uint64_t t[3] = { v[0], v[1], v[2]};
        uint64_t s1[3] = { v[3], v[3], 0};
        uint64_t s2[3] = { 0, v[4], v[4]};
        uint64_t s3[3] = { v[5], v[5], v[5]};
        v.resize(4);

        uint64_t cc = 0;
        for (size_t i=0; i < 3; i++) {
            uint64_t temp = t[i] + cc;
            cc     = temp < cc;
            temp  += s1[i];
            cc    += temp < s1[i];
            temp  += s2[i];
            cc    += temp < s2[i];
            temp  += s3[i];
            cc    += temp < s3[i];
            v[i]   = temp;
        }
        v[3] = cc;
        a->set_words(v);

        while (*a >= cfg.mod) {
            *a = *a - cfg.mod;
        }
        return *a;
    }

    template<curve_e curve>
    static core::mpz<uint32_t>& mod_solinas(core::mpz<uint32_t>* a, const core::mod_config<uint32_t>& cfg)
    {
        return *a;
    }

    template<curve_e curve>
    static core::mpz<uint16_t>& mod_solinas(core::mpz<uint16_t>* a, const core::mod_config<uint16_t>& cfg)
    {
        return *a;
    }
};

}  // namespace elliptic
}  // namespace phantom
