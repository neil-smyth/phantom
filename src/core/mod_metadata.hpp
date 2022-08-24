/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <cstdint>
#include <limits>

#include "core/bit_manipulation.hpp"
#include "core/number.hpp"


namespace phantom {
namespace core {

/** 
 * @brief Template class for pre-inversion division
 * 
 * Initialization methods to compute normalized pre-inversion parameters
 */
template<typename T>
struct mod_metadata {
    T m;
    T m_low;
    T m_inv;
    T norm;
    T b_norm;

    void init(T modulus)
    {
        m      = modulus;
        m_inv  = number<T>::uinverse(modulus);
        norm   = bit_manipulation::clz(modulus);
        b_norm = std::numeric_limits<T>::digits - norm;
    }

    void init_2(T mh, T ml)
    {
        norm   = bit_manipulation::clz(mh);
        b_norm = std::numeric_limits<T>::digits - norm;
        if (norm) {
            mh   = (mh << norm) | (ml >> b_norm);
            ml <<= norm;
        }
        m      = mh;
        m_low  = ml;
        m_inv  = number<T>::uinverse_3by2(mh, ml);
    }

    void init_3(T d2, T d1, T d0)
    {
        norm = bit_manipulation::clz(d2);
        b_norm = std::numeric_limits<T>::digits - norm;
        if (norm) {
            d2 = (d2 << norm) | (d1 >> b_norm);
            d1 = (d1 << norm) | (d0 >> b_norm);
        }
        m     = d2;
        m_low = d1;
        m_inv = number<T>::uinverse_3by2(d2, d1);
    }
};

}  // namespace core
}  // namespace phantom
