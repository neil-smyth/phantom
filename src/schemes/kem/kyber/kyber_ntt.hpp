/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include "./phantom.hpp"


namespace phantom {


class kyber_ntt
{
public:
    static void fwd_ntt(int16_t *r, const size_t k, const size_t n, uint16_t q, uint16_t mont_inv);
    static void invntt_tomont(int16_t *r, const size_t k, const size_t n, uint16_t q, uint16_t mont_inv);
    static void tomont(int16_t *r, const size_t k, const size_t n, uint16_t q, uint16_t mont_inv);
    static void mul_acc_mont(int16_t *r, size_t k, size_t k2, const int16_t *a, const int16_t *b, const size_t n,
                                   uint16_t q, uint16_t mont_inv);
    
    static const int16_t zetas[128];

private:
    static void ntt(int16_t *r, uint16_t q, uint16_t mont_inv);
    static void invntt(int16_t *r, uint16_t q, uint16_t mont_inv);
    static void mul_montgomery(int16_t *r, const int16_t *a, const int16_t *b, uint16_t q, uint16_t mont_inv);
    static void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta, uint16_t q, uint16_t mont_inv);
};

}  // namespace phantom
