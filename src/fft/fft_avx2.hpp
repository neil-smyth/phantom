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

#if defined(__AVX2__)

namespace phantom {

/**
 * @brief A concrete implementation of the fft class for use with AVX2 instruction set
 * 
 * @tparam T 
 */
template<typename T>
class fft_avx2 : public fft<T>
{
public:
    explicit fft_avx2(size_t logn) : fft<T>(logn) {}

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

                if (ht >= 4) {
                    __m256d s_re, s_im;

                    s_re = _mm256_set1_pd(*p_coeff++);
                    s_im = _mm256_set1_pd(*p_coeff++);
                    for (size_t j = j1; j < j2; j += 4) {
                            __m256d x_re, x_im, y_re, y_im;
                            __m256d z_re, z_im;

                            x_re = _mm256_loadu_pd(&f[j]);
                            x_im = _mm256_loadu_pd(&f[j + hn]);
                            z_re = _mm256_loadu_pd(&f[j+ht]);
                            z_im = _mm256_loadu_pd(&f[j+ht + hn]);
                            y_re = _mm256_fmsub_pd(z_re, s_re, _mm256_mul_pd(z_im, s_im));
                            y_im = _mm256_fmadd_pd(z_re, s_im, _mm256_mul_pd(z_im, s_re));
                            _mm256_storeu_pd(&f[j], _mm256_add_pd(x_re, y_re));
                            _mm256_storeu_pd(&f[j + hn], _mm256_add_pd(x_im, y_im));
                            _mm256_storeu_pd(&f[j + ht], _mm256_sub_pd(x_re, y_re));
                            _mm256_storeu_pd(&f[j + ht + hn], _mm256_sub_pd(x_im, y_im));
                    }
                }
                else {
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

                if (t >= 4) {
                    __m256d s_re, s_im;

                    s_re = _mm256_set1_pd(*p_coeff++);
                    s_im = _mm256_set1_pd(*p_coeff++);
                    for (size_t j = j1; j < j2; j += 4) {
                        __m256d x_re, x_im, y_re, y_im;
                        __m256d z_re, z_im;

                        x_re = _mm256_loadu_pd(&f[j]);
                        x_im = _mm256_loadu_pd(&f[j + hn]);
                        y_re = _mm256_loadu_pd(&f[j+t]);
                        y_im = _mm256_loadu_pd(&f[j+t + hn]);
                        _mm256_storeu_pd(&f[j], _mm256_add_pd(x_re, y_re));
                        _mm256_storeu_pd(&f[j + hn], _mm256_add_pd(x_im, y_im));
                        x_re = _mm256_sub_pd(y_re, x_re);
                        x_im = _mm256_sub_pd(x_im, y_im);
                        z_re = _mm256_fmsub_pd(x_im, s_im, _mm256_mul_pd(x_re, s_re));
                        z_im = _mm256_fmadd_pd(x_re, s_im, _mm256_mul_pd(x_im, s_re));
                        _mm256_storeu_pd(&f[j+t], z_re);
                        _mm256_storeu_pd(&f[j+t + hn], z_im);
                    }
                }
                else {
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

        if (n >= 8) {
            __m256d half, sv;

            half = _mm256_set1_pd(0.5);
            sv = _mm256_set_pd(-0.0, 0.0, -0.0, 0.0);
            for (size_t u = 0; u < qn; u += 2) {
                __m256d ab_re, ab_im, ff0, ff1, ff2, ff3, gmt;

                ab_re = _mm256_loadu_pd(&f[(u << 1)]);
                ab_im = _mm256_loadu_pd(&f[(u << 1) + hn]);
                ff0 = _mm256_mul_pd(_mm256_hadd_pd(ab_re, ab_im), half);
                ff0 = _mm256_permute4x64_pd(ff0, 0xD8);
                _mm_storeu_pd(&f0[u], _mm256_extractf128_pd(ff0, 0));
                _mm_storeu_pd(&f0[u + qn], _mm256_extractf128_pd(ff0, 1));

                ff1 = _mm256_mul_pd(_mm256_hsub_pd(ab_re, ab_im), half);
                gmt = _mm256_loadu_pd(p_coeff);
                ff2 = _mm256_shuffle_pd(ff1, ff1, 0x5);
                ff3 = _mm256_hadd_pd(
                        _mm256_mul_pd(ff1, gmt),
                        _mm256_xor_pd(_mm256_mul_pd(ff2, gmt), sv));
                ff3 = _mm256_permute4x64_pd(ff3, 0xD8);
                _mm_storeu_pd(&f1[u], _mm256_extractf128_pd(ff3, 0));
                _mm_storeu_pd(&f1[u + qn], _mm256_extractf128_pd(ff3, 1));

                p_coeff += 4;
            }
        }
        else {
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

        if (n >= 16) {
            for (size_t u = 0; u < qn; u += 4) {
                __m256d a_re, a_im, b_re, b_im, c_re, c_im;
                __m256d gm1, gm2, g_re, g_im;
                __m256d t_re, t_im, u_re, u_im;
                __m256d tu1_re, tu2_re, tu1_im, tu2_im;

                a_re = _mm256_loadu_pd(&f0[u]);
                a_im = _mm256_loadu_pd(&f0[u + qn]);
                c_re = _mm256_loadu_pd(&f1[u]);
                c_im = _mm256_loadu_pd(&f1[u + qn]);

                gm1  = _mm256_loadu_pd(p_coeff);
                gm2  = _mm256_loadu_pd(p_coeff + 4);
                g_re = _mm256_unpacklo_pd(gm1, gm2);
                g_im = _mm256_unpackhi_pd(gm1, gm2);
                g_re = _mm256_permute4x64_pd(g_re, 0xD8);
                g_im = _mm256_permute4x64_pd(g_im, 0xD8);

                b_re = _mm256_fmsub_pd(c_re, g_re, _mm256_mul_pd(c_im, g_im));
                b_im = _mm256_fmadd_pd(c_re, g_im, _mm256_mul_pd(c_im, g_re));

                t_re = _mm256_add_pd(a_re, b_re);
                t_im = _mm256_add_pd(a_im, b_im);
                u_re = _mm256_sub_pd(a_re, b_re);
                u_im = _mm256_sub_pd(a_im, b_im);

                tu1_re = _mm256_unpacklo_pd(t_re, u_re);
                tu2_re = _mm256_unpackhi_pd(t_re, u_re);
                tu1_im = _mm256_unpacklo_pd(t_im, u_im);
                tu2_im = _mm256_unpackhi_pd(t_im, u_im);

                _mm256_storeu_pd(&f[(u << 1)],          _mm256_permute2f128_pd(tu1_re, tu2_re, 0x20));
                _mm256_storeu_pd(&f[(u << 1) + 4],      _mm256_permute2f128_pd(tu1_re, tu2_re, 0x31));
                _mm256_storeu_pd(&f[(u << 1) + hn],     _mm256_permute2f128_pd(tu1_im, tu2_im, 0x20));
                _mm256_storeu_pd(&f[(u << 1) + 4 + hn], _mm256_permute2f128_pd(tu1_im, tu2_im, 0x31));

                p_coeff += 8;
            }
        }
        else {
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
    }
};

}  // namespace phantom

#endif
