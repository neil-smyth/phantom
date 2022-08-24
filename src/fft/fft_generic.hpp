/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include "fft/fft.hpp"

namespace phantom {

/**
 * @brief A concrete implementation of the fft class for generic use
 * 
 * @tparam T 
 */
template<typename T>
class fft_generic : public fft<T>
{
public:
    explicit fft_generic(size_t logn) : fft<T>(logn) {}

    /**
     * Forward FFT
     * @param f Polynomial
     */
    void fwd(T* f) override
    {
        // First iteration: compute f[j] + i * f[j+N/2] for all j < N/2
        // (because GM[1] = w^rev(1) = w^(N/2) = i).
        // In our chosen representation, this is a no-op: everything is
        // already where it should be.

        size_t hn = fft<T>::m_n >> 1;
        size_t t  = hn;

        for (size_t u = 1, m = 2; u < fft<T>::m_logn; u++, m <<= 1) {
            size_t ht = t >> 1;
            size_t hm = m >> 1;
            const T* p_coeff = fft<T>::coeff_tab + (m << 1);

            for (size_t i1 = 0, j1 = 0; i1 < hm; i1++, j1 += t) {
                size_t j2 = j1 + ht;

                T s_re = *p_coeff++;
                T s_im = *p_coeff++;
                for (size_t j = j1; j < j2; j++) {
                    T x_re = f[j];
                    T x_im = f[j + hn];
                    T y_re = f[j + ht];
                    T y_im = f[j + ht + hn];

                    fft<T>::complex_mul(y_re, y_im, y_re, y_im, s_re, s_im);
                    fft<T>::complex_add(f[j], f[j + hn], x_re, x_im, y_re, y_im);
                    fft<T>::complex_sub(f[j + ht], f[j + ht + hn], x_re, x_im, y_re, y_im);
                }
            }

            t = ht;
        }
    }

    /**
     * Inverse FFT
     * @param f Polynomial
     */
    void inv(T* f) override
    {
        size_t t  = 1;
        size_t m  = fft<T>::m_n;
        size_t hn = fft<T>::m_n >> 1;

        for (size_t u = fft<T>::m_logn; u > 1; u--) {
            size_t hm = m >> 1;
            size_t dt = t << 1;
            const T* p_coeff = fft<T>::coeff_tab + m;

            for (size_t i1 = 0, j1 = 0; j1 < hn; i1++, j1 += dt) {
                size_t j2 = j1 + t;

                T s_re = *p_coeff++;
                T s_im = -(*p_coeff++);
                for (size_t j = j1; j < j2; j++) {
                    T x_re = f[j];
                    T x_im = f[j + hn];
                    T y_re = f[j + t];
                    T y_im = f[j + t + hn];

                    fft<T>::complex_add(f[j], f[j + hn], x_re, x_im, y_re, y_im);
                    fft<T>::complex_sub(x_re, x_im, x_re, x_im, y_re, y_im);
                    fft<T>::complex_mul(f[j + t], f[j + t + hn], x_re, x_im, s_re, s_im);
                }
            }

            t = dt;
            m = hm;
        }

        // Last iteration is a no-op, provided that we divide by N/2
        // instead of N. We need to make a special case for logn = 0.
        if (fft<T>::m_logn > 0) {
            T ni = ldexp(2, -static_cast<int>(fft<T>::m_logn));
            for (size_t u = 0; u < fft<T>::m_n; u++) {
                f[u] = f[u] * ni;
            }
        }
    }

    /**
     * Falcon split operation [FFT representation]
     * @param f0 Output polynomial f0 (modulo X^(N/2)+1)
     * @param f1 Output polynomial f1 (modulo X^(N/2)+1)
     * @param f Input polynomial f = f0(x^2) + x*f1(x^2)
     * @param logn Length of the data arrays (log base-2)
     */
    void split_fft(T *_RESTRICT_ f0, T *_RESTRICT_ f1,
        const T *_RESTRICT_ f, size_t logn) override
    {
        // The FFT representation we use is in bit-reversed order
        // (element i contains f(w^(rev(i))), where rev() is the
        // bit-reversal function over the ring degree. This changes
        // indexes with regards to the Falcon specification.
        size_t n  = static_cast<size_t>(1) << logn;
        size_t hn = n >> 1;
        size_t qn = hn >> 1;

        // We process complex values by pairs. For logn = 1, there is only
        // one complex value (the other one is the implicit conjugate),
        // so we add the two lines below because the loop will be
        // skipped.
        f0[0] = f[0];
        f1[0] = f[hn];

        const T* p_coeff = fft<T>::coeff_tab + n;

        for (size_t u = 0; u < qn; u++) {
            T t_re, t_im;

            T a_re = f[(u << 1)];
            T a_im = f[(u << 1) + hn];
            T b_re = f[(u << 1) + 1];
            T b_im = f[(u << 1) + 1 + hn];

            fft<T>::complex_add(t_re, t_im, a_re, a_im, b_re, b_im);
            f0[u     ] = t_re * 0.5;
            f0[u + qn] = t_im * 0.5;

            T c_re = *p_coeff++;
            T c_im = -(*p_coeff++);
            fft<T>::complex_sub(t_re, t_im, a_re, a_im, b_re, b_im);
            fft<T>::complex_mul(t_re, t_im, t_re, t_im, c_re, c_im);
            f1[u     ] = t_re * 0.5;
            f1[u + qn] = t_im * 0.5;
        }
    }


    /**
     * Falcon merge operation [FFT representation]
     * @param f Output polynomial f = f0(x^2) + x*f1(x^2)
     * @param f0 Input polynomial f0 (modulo X^(N/2)+1)
     * @param f1 Input polynomial f1 (modulo X^(N/2)+1)
     * @param logn Length of the data arrays (log base-2)
     */
    void merge_fft(T *_RESTRICT_ f,
        const T *_RESTRICT_ f0, const T *_RESTRICT_ f1, size_t logn) override
    {
        size_t n  = static_cast<size_t>(1) << logn;
        size_t hn = n >> 1;
        size_t qn = hn >> 1;

        // An extra copy to handle the special case logn = 1.
        f[0]  = f0[0];
        f[hn] = f1[0];

        const T* p_coeff = fft<T>::coeff_tab + n;

        for (size_t u = 0; u < qn; u ++) {
            T b_re, b_im, t_re, t_im;

            T c_re = *p_coeff++;
            T c_im = *p_coeff++;

            T a_re = f0[u];
            T a_im = f0[u + qn];
            fft<T>::complex_mul(b_re, b_im, f1[u], f1[u + qn], c_re, c_im);
            fft<T>::complex_add(t_re, t_im, a_re, a_im, b_re, b_im);
            f[(u << 1)]          = t_re;
            f[(u << 1) + hn]     = t_im;
            fft<T>::complex_sub(t_re, t_im, a_re, a_im, b_re, b_im);
            f[(u << 1) + 1]      = t_re;
            f[(u << 1) + 1 + hn] = t_im;
        }
    }
};

}  // namespace phantom
