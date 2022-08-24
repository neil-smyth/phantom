/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <cmath>
#include "./phantom.hpp"


namespace phantom {

/**
 * @brief Arithmetic for polynomials in relation to Fast Fourier Transforms
 * 
 * @tparam T Underlying data type (must be float or double)
 * @tparam std::enable_if<std::is_floating_point<T>::value>::type 
 */
template<typename T, typename std::enable_if<std::is_floating_point<T>::value>::type* = nullptr>
class fft_poly
{
    /// Check for valid types
    static_assert(std::is_same<T, float>::value  ||
                  std::is_same<T, double>::value,
                  "number instantiated with unsupported type");

public:

    /**
     * Multiplication of two polynomials: a *= b [FFT representation]
     * @param a Product and 1st input polynomial
     * @param b 2nd input polynomial
     * @param logn Length of polynomials (log base-2)
     */
    static void mul(T *_RESTRICT_ a, const T *_RESTRICT_ b, size_t logn)
    {
        size_t n  = static_cast<size_t>(1) << logn;
        size_t hn = n >> 1;
        for (size_t u = 0; u < hn; u++) {
            fft<T>::complex_mul(a[u], a[u + hn], a[u], a[u + hn], b[u], b[u + hn]);
        }
    }

    /**
     * Multiplication of a polynomial with a real constant value: a *= x [normal or FFT representation]
     * @param a Product and input polynomial
     * @param b Real constant value
     * @param logn Length of polynomials (log base-2)
     */
    static void mul_const(T *a, T x, size_t logn)
    {
        size_t n = static_cast<size_t>(1) << logn;
        for (size_t u = 0; u < n; u++) {
            a[u] = a[u] * x;
        }
    }

    /**
     * Divide polynomial a by polynomial b, modulo X^N+1 [FFT representation]
     * @param a Input polynomial a
     * @param b Input polynomial b
     * @param logn Length of polynomials (log base-2)
     */
    static void div(T *_RESTRICT_ a, const T *_RESTRICT_ b, size_t logn)
    {
        size_t n = static_cast<size_t>(1) << logn;
        size_t hn = n >> 1;
        for (size_t u = 0; u < hn; u ++) {
            T a_re = a[u];
            T a_im = a[u + hn];
            T b_re = b[u];
            T b_im = b[u + hn];
            fft<T>::complex_div(a[u], a[u + hn], a_re, a_im, b_re, b_im);
        }
    }

    /**
     * Given a and b, compute c = 1/(a*adj(a)+b*adj(b)) [FFT representation]
     * @param c Result polynomial is auto-adjoint so imaginary values are omitted
     * @param a Input polynomial a
     * @param b Input polynomial b
     * @param logn Length of polynomials (log base-2)
     */
    static void invnorm2(T *_RESTRICT_ c, const T *_RESTRICT_ a, const T *_RESTRICT_ b, size_t logn)
    {
        size_t n  = static_cast<size_t>(1) << logn;
        size_t hn = n >> 1;
        for (size_t u = 0; u < hn; u++) {
            T a_re = a[u];
            T a_im = a[u + hn];
            T b_re = b[u];
            T b_im = b[u + hn];
            c[u]   = 1 / (a_re * a_re + a_im * a_im + b_re * b_re + b_im * b_im);
        }
    }

    /**
     * Adjoint of polynomial a [FFT representation]
     * @param a Input polynomial a
     * @param logn Length of polynomials (log base-2)
     */
    static void adjoint(T *a, size_t logn)
    {
        size_t n = static_cast<size_t>(1) << logn;
        for (size_t u = (n >> 1); u < n; u++) {
            a[u] = -a[u];
        }
    }

    /**
     * @brief Multiply polynomial a with it's own adjoint [FFT representation]
     * Since each coefficient is multiplied with its own conjugate, the result contains only real values
     * @param a Input polynomial a
     * @param logn Length of polynomials (log base-2)
     */
    static void mul_self_adjoint(T *a, size_t logn)
    {
        size_t n  = static_cast<size_t>(1) << logn;
        size_t hn = n >> 1;
        for (size_t u = 0; u < hn; u ++) {
            T a_re    = a[u];
            T a_im    = a[u + hn];
            a[u]      = (a_re * a_re) + (a_im * a_im);
            a[u + hn] = 0;
        }
    }

    /**
     * Multiply polynomial a with the adjoint of polynomial b [FFT representation]
     * @param a Input polynomial a
     * @param b Input polynomial b
     * @param logn Length of polynomials (log base-2)
     */
    static void mul_adjoint(T *_RESTRICT_ a, const T *_RESTRICT_ b, size_t logn)
    {
        size_t n  = static_cast<size_t>(1) << logn;
        size_t hn = n >> 1;
        for (size_t u = 0; u < hn; u++) {
            T a_re =  a[u];
            T a_im =  a[u + hn];
            T b_re =  b[u];
            T b_im = -b[u + hn];
            fft<T>::complex_mul(a[u], a[u + hn], a_re, a_im, b_re, b_im);
        }
    }

    /**
     * Multiply polynomial a with polynomial b, where b is auto-adjoint [FFT representation]
     * @param a Input polynomial a
     * @param b Input polynomial b
     * @param logn Length of polynomials (log base-2)
     */
    static void mul_auto_adjoint(T *_RESTRICT_ a, const T *_RESTRICT_ b, size_t logn)
    {
        size_t n  = static_cast<size_t>(1) << logn;
        size_t hn = n >> 1;
        for (size_t u = 0; u < hn; u++) {
            a[u]      = a[u]      * b[u];
            a[u + hn] = a[u + hn] * b[u];
        }
    }

    /**
     * Divide polynomial a by polynomial b, where b is auto-adjoint [FFT representation]
     * @param a Input polynomial a
     * @param b Input polynomial b
     * @param logn Length of polynomials (log base-2)
     */
    static void div_auto_adjoint(T *_RESTRICT_ a, const T *_RESTRICT_ b, size_t logn)
    {
        size_t n  = static_cast<size_t>(1) << logn;
        size_t hn = n >> 1;
        for (size_t u = 0; u < hn; u++) {
            T ib      = 1 / b[u];
            a[u]      = a[u]      * ib;
            a[u + hn] = a[u + hn] * ib;
        }
    }
};

}  // namespace phantom
