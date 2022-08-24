/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <cstdint>
#include <limits>
#include <type_traits>
#include <cstring>


namespace phantom {
namespace core {

/** 
 * @brief Implementation of GF256 arithmetic
 * 
 * Concrete implementation with various types
 */
class gf256_impl
{
public:
    static void add(uint32_t r[8], const uint32_t x[8]);
    static void mul(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]);
    static void sqr(uint32_t r[8], const uint32_t x[8]);
    static void inv(uint32_t r[8], const uint32_t x[8]);
};

/** 
 * @brief GF256 adaptor class.
 * 
 * Adaptor class that provides a wrapper interface to various concrete implementations.
 */
template<typename T>
class gf256
{
public:
    /// Word size of the template type
    static const size_t wordsize = std::numeric_limits<T>::digits;

    /// Key size in template type words
    static const size_t key_words = 256 / wordsize;

    /**
     * Polynomial addition/subtraction, r = r + x.
     * @param[in,out] r Polynomial input and result.
     * @param[in] x Polynomial to be added.
     */
    static void add(T r[key_words], const T x[key_words])
    {
        gf256_impl::add(r, x);
    }

    /**
     * Polynomial multiplication, r = a * b (mod x^8 + x^4 + x^3 + x + 1).
     * @param[out] r Product.
     * @param[in] a Left multiplicand.
     * @param[in] b Right multiplicand.
     */
    static void mul(T r[key_words], const T a[key_words], const T b[key_words])
    {
        gf256_impl::mul(r, a, b);
    }

    /**
     * Polynomial squaring, r = a ^ 2 (mod x^8 + x^4 + x^3 + x + 1)
     * @param[in,out] r Product.
     * @param[in] x Value to be squared.
     */
    static void sqr(T r[key_words], const T x[key_words])
    {
        gf256_impl::sqr(r, x);
    }

    /**
     * Polynomial inversion, r = 1 / x (mod x^8 + x^4 + x^3 + x + 1).
     * @param[in,out] r Inverse.
     * @param[in] x Value to be inverted.
     */
    static void inv(T r[key_words], const T x[key_words])
    {
        gf256_impl::inv(r, x);
    }
};

/// Forward declaration of common sizes
extern template class gf256<uint32_t>;

}  // namespace core
}  // namespace phantom
