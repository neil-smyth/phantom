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
 * @brief Templated abstract base class for FFT.
 * 
 * Concrete implementations of complex arithmetic and pure virtual fwd, inv, splitfft and mergefft methods.
 */
template<typename T>
class fft
{
public:
    /// Check for valid types
    static_assert(std::is_same<T, float>::value  ||
                  std::is_same<T, double>::value,
                  "number instantiated with unsupported type");

    const size_t m_logn;
    const size_t m_n;

    virtual ~fft() {}

    explicit fft(size_t logn) : m_logn(logn), m_n(1 << logn)
    {
        // If n is 0 or odd we cannot continue
        if (0 == m_n || 1 == (m_n&1)) {
            throw std::invalid_argument("FFT length cannot be 0 or odd");
        }
    }

    /// Pre-computed FFT coefficients from Octave, grouped by N
    static const T coeff_tab[2 * 1024];

    // Addition of two complex numbers (d = a + b)
    static void complex_add(T& d_re, T& d_im, const T a_re, const T a_im, const T b_re, const T b_im)
    {
        d_re = a_re + b_re;
        d_im = a_im + b_im;
    }

    // Subtraction of two complex numbers (d = a - b)
    static void complex_sub(T& d_re, T& d_im, const T a_re, const T a_im, const T b_re, const T b_im)
    {
        d_re = a_re - b_re;
        d_im = a_im - b_im;
    };

    // Multplication of two complex numbers (d = a * b)
    static void complex_mul(T& d_re, T& d_im, const T a_re, const T a_im, const T b_re, const T b_im)
    {
        d_re = (a_re * b_re) - (a_im * b_im);
        d_im = (a_re * b_im) + (a_im * b_re);
    }

    // Squaring of a complex number (d = a * a)
    static void complex_mul(T& d_re, T& d_im, const T a_re, const T a_im)
    {
        d_re = (a_re * a_re) - (a_im * a_im);
        d_im = (a_re * a_im) + (a_im * a_re);
    }

    // Inversion of a complex number (d = 1 / a)
    static void complex_inv(T& d_re, T& d_im, const T a_re, const T a_im)
    {
        T inv_m = 1 / ((a_re * a_re) + (a_im * a_im));
        d_re    = a_re * inv_m;
        d_im    = -a_im * inv_m;
    }

    // Division of complex numbers (d = a / b)
    static void complex_div(T& d_re, T& d_im, const T a_re, const T a_im, const T b_re, const T b_im)
    {
        T inv_m = 1 / ((b_re * b_re) + (b_im * b_im));
        T t_re  = b_re * inv_m;
        T t_im  = -b_im * inv_m;
        d_re    = (a_re * t_re) - (a_im * t_im);
        d_im    = (a_re * t_im) + (a_im * t_re);
    }

    /**
     * Forward FFT
     * @param f Polynomial
     */
    virtual void fwd(T* f) = 0;

    /**
     * Inverse FFT
     * @param f Polynomial
     */
    virtual void inv(T* f) = 0;

    /**
     * Falcon split operation [FFT representation]
     * @param f0 Output polynomial f0 (modulo X^(N/2)+1)
     * @param f1 Output polynomial f1 (modulo X^(N/2)+1)
     * @param f Input polynomial f = f0(x^2) + x*f1(x^2)
     * @param logn Length of the data arrays (log base-2)
     */
    virtual void split_fft(T *_RESTRICT_ f0, T *_RESTRICT_ f1,
        const T *_RESTRICT_ f, size_t logn) = 0;

    /**
     * Falcon merge operation [FFT representation]
     * @param f Output polynomial f = f0(x^2) + x*f1(x^2)
     * @param f0 Input polynomial f0 (modulo X^(N/2)+1)
     * @param f1 Input polynomial f1 (modulo X^(N/2)+1)
     * @param logn Length of the data arrays (log base-2)
     */
    virtual void merge_fft(T *_RESTRICT_ f,
        const T *_RESTRICT_ f0, const T *_RESTRICT_ f1, size_t logn) = 0;
};

// Forward declaration of common sizes
extern template class fft<float>;
extern template class fft<double>;

}  // namespace phantom
