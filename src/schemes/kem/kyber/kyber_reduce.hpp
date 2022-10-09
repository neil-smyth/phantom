/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <phantom_types.hpp>


namespace phantom {


class kyber_reduce
{
public:
    static int16_t montgomery(int32_t a, uint16_t q, uint16_t mont_inv)
    {
        int16_t t;

        t = (int16_t)a * mont_inv;
        t = (a - (int32_t)t * q) >> 16;
        return t;
    }

    static int16_t barrett(int16_t a, uint16_t q)
    {
        int16_t t;
        const int16_t v = ((1<<26) + q/2)/q;

        t  = ((int32_t)v*a + (1<<25)) >> 26;
        t *= q;
        return a - t;
    }

    static void poly_barrett(int16_t *inout, size_t n, size_t k, uint16_t q)
    {
        for (size_t i=0; i < n*k; i++) {
            inout[i] = barrett(inout[i], q);
        }
    }

    static int16_t mont_mul(int16_t a, int16_t b, uint16_t q, uint16_t mont_inv)
    {
        return montgomery((int32_t)a*b, q, mont_inv);
    }
};


}  // namespace phantom
