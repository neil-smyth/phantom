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
#include <cmath>
#include <limits>
#include <vector>

#include "./phantom_memory.hpp"


namespace phantom {
namespace core {

/** 
 * @brief Polynomial with small coefficients class
 * 
 * Templated class for single machine word polyomials
 */
template<typename T>
class poly
{
public:
    /// Add a scalar word to a polynomial
    static void add_scalar(T *inout, size_t n, T in)
    {
        if (n > 0) {
            inout[0] = inout[0] + in;
        }
    }

    /// Subtract a scalar word from a polynomial
    static void sub_scalar(T *inout, size_t n, T in)
    {
        if (n > 0) {
            inout[0] = inout[0] - in;
        }
    }

    /// Multiply a polynomial by a scalar word
    static void mul_scalar(T *inout, size_t n, T in)
    {
        for (size_t i=n; i--;) {
            inout[i] *= in;
        }
    }

    /// Reduce polynomials coefficients modulo a scalar value
    static void mod_unsigned(T *inout, size_t n, T q)
    {
        if (std::is_unsigned<T>::value) {
            for (size_t i=n; i--;) {
                inout[i] += ((q - inout[i] - 1) >> (std::numeric_limits<T>::digits - 1)) * q;
            }
        }
        else {
            using U = typename std::make_unsigned<T>::type;
            for (size_t i=n; i--;) {
                inout[i] += (static_cast<U>(inout[i]) >> (std::numeric_limits<U>::digits - 1)) * q;
                inout[i] -= (static_cast<U>(q - inout[i] - 1) >> (std::numeric_limits<U>::digits - 1)) * q;
            }
        }
    }

    /// Add two polynomials
    static void add(T *out, size_t n, const T *in1, const T *in2)
    {
        for (size_t i = n; i--;) {
            out[i] = in1[i] + in2[i];
        }
    }

    /// Add two polynomials in-place
    static void add_inplace(T *_RESTRICT_ out, size_t n, const T *_RESTRICT_ in1)
    {
        for (size_t i = n; i--;) {
            out[i] += in1[i];
        }
    }

    /// Subtract two polynomials
    static void sub(T *out, size_t n, const T *in1, const T *in2)
    {
        for (size_t i = n; i--;) {
            out[i] = in1[i] - in2[i];
        }
    }

    /// Subtract two polynomials in-place
    static void sub_inplace(T *_RESTRICT_ out, size_t n, const T *_RESTRICT_ in1)
    {
        for (size_t i = n; i--;) {
            out[i] -= in1[i];
        }
    }

    /// Negate a polynomial
    static void negate(T* a, size_t n)
    {
        for (size_t i = 0; i < n; i++) {
            a[i] = -a[i];
        }
    }

    /// Add two polynomials modulo q
    static void add_mod(T *out, size_t n, const T *in1, const T *in2, T q)
    {
        if (std::is_unsigned<T>::value) {
            for (size_t i=n; i--;) {
                T temp = in1[i] + in2[i];
                temp  += ((q - temp - 1) >> (std::numeric_limits<T>::digits - 1)) * q;
                out[i] = temp;
            }
        }
        else {
            using U = typename std::make_unsigned<T>::type;
            for (size_t i=n; i--;) {
                T temp = in1[i] + in2[i];
                temp  += (static_cast<U>(temp) >> (std::numeric_limits<U>::digits - 1)) * q;
                temp  -= (static_cast<U>(q - temp - 1) >> (std::numeric_limits<U>::digits - 1)) * q;
                out[i] = temp;
            }
        }
    }

    /// Subtract two polynomials modulo q
    static void sub_mod(T *out, size_t n, const T *in1, const T *in2, T q)
    {
        if (std::is_unsigned<T>::value) {
            for (size_t i=n; i--;) {
                T temp = in1[i] - in2[i];
                temp  += ((q - temp - 1) >> (std::numeric_limits<T>::digits - 1)) * q;
                out[i] = temp;
            }
        }
        else {
            using U = typename std::make_unsigned<T>::type;
            for (size_t i=n; i--;) {
                T temp = in1[i] - in2[i];
                temp  += (static_cast<U>(temp) >> (std::numeric_limits<U>::digits - 1)) * q;
                temp  -= (static_cast<U>(q - temp - 1) >> (std::numeric_limits<U>::digits - 1)) * q;
                out[i] = temp;
            }
        }
    }

    /// Add each coefficient of two polynomials
    static void add_single(T *out, size_t n, const T *in)
    {
        for (size_t i=n; i--;) {
            out[i] += in[i];
        }
    }

    /// Subtract each coefficient of two polynomials
    static void sub_single(T *out, size_t n, const T *in)
    {
        for (size_t i=n; i--;) {
            out[i] -= in[i];
        }
    }

    /// Multiply two polynomials
    static void mul_generic(T *out, size_t n, const T *in1, const T *in2)
    {
        for (size_t i=0; i < n; i++) {
            out[i] = in1[i] * in2[0];
        }

        for (size_t j=1; j < n; j++) {
            out[n-1+j] = in1[n-1] * in2[j];
        }

        for (size_t i=0; i < n-1; i++) {
            for (size_t j=1; j < n; j++) {
                out[i+j] += in1[i] * in2[j];
            }
        }
    }

    /// Optimized polynomial multiplication (if length is a multiple of 4)
    template<typename U, typename V, size_t N, size_t N_SB = (N>>2)>
    static void mul(T* out, const T* in1, const T* in2)
    {
        if (N_SB*4 == N) {
            toom_cook_4way<U, V, N, N_SB>(out, in1, in2);
        }
        else {
            poly<T>::mul_generic(out, N, in1, in2);
        }
    }

    /// Multiply two polynomials and accumulate with the output polynomial
    static void mul_acc_generic(T *out, size_t n, const T *in1, const T *in2)
    {
        for (size_t i=0; i < n; i++) {
            out[i] += in1[i] * in2[0];
        }

        for (size_t j=1; j < n; j++) {
            out[n-1+j] += in1[n-1] * in2[j];
        }

        for (size_t i=0; i < n-1; i++) {
            for (size_t j=1; j < n; j++) {
                out[i+j] += in1[i] * in2[j];
            }
        }
    }

    /// Optimized multiply accumulate of polynomials
    template<typename U, typename V, size_t N, size_t N_SB = (N>>2)>
    static void mul_acc(T* out, const T* in1, const T* in2)
    {
        auto c = phantom_vector<T>(2 * N);

        if (N_SB*4 == N) {
            // Optimised Toom-Cook multiply-accumulation
            toom_cook_4way<U, V, N, N_SB>(c.data(), in1, in2);
        }
        else {
            // Generic fallback multiply-accumulation
            poly<T>::mul_acc_generic(c.data(), N, in1, in2);
        }

        // Reduction of the polynomial length modulo N
        for (size_t i=N; i < 2*N; i++) {
            out[i - N] += (c[i - N] - c[i]);
        }
    }

    /// Determine the degree of a polynomial
    static ssize_t degree(const T *v, size_t n)
    {
        ssize_t deg = -1;
        if (0 != v) {
            ssize_t j = n;
            while (0 == v[--j]) {
                if (0 == j) {
                    break;
                }
            }
            deg = j;
        }
        return deg;
    }

    /// Centre the coefficients of a polynomial modulo q
    static void centre(T *v, T q, size_t n)
    {
        if (std::is_unsigned<T>::value) {
            using S = typename std::make_signed<T>::type;
            T q2 = q >> 1;
            for (size_t i=0; i < n; i++) {
                T mask;
                mask = static_cast<S>(q2 - v[i]) >> (std::numeric_limits<T>::digits - 1);
                v[i] -= q * (mask);
            }
        }
        else {
            using U = typename std::make_unsigned<T>::type;
            T q2 = q >> 1;
            for (size_t i=0; i < n; i++) {
                U mask;
                mask = static_cast<U>(q2 - v[i]) >> (std::numeric_limits<U>::digits - 1);
                v[i] -= q & -mask;
            }
        }
    }

    /// Determine the absolute maximum coefficient in a polynomial
    static size_t abs_max(const T *v, size_t n)
    {
        T max = 0;
        for (size_t i=0; i < n; i++) {
            T uT = (v[i] < 0)? -v[i] : v[i];
            if (uT > max) {
                max = uT;
            }
        }

        return max;
    }

    /// Determine the scalar product of two polynomials
    template<typename U>
    static U scalar_product(const T *t, const T *u, size_t n)
    {
        U sum = 0;
        for (size_t i=0; i < n; i++) {
            sum += t[i] * u[i];
        }

        return sum;
    }

    /// Calculate the Euclidean distance between two polynomials
    static T euclidean_distance(const T *t, const T *u, size_t n)
    {
        double sum = 0;
        for (size_t i=0; i < n; i++) {
            double diff = t[i] - u[i];
            sum += diff * diff;
        }
        return sqrt(sum);
    }

private:
    poly() {}
    ~poly() {}

    /// Karatsuba polynomial multiplication
    template<typename U, typename V, size_t KARATSUBA_N>
    static void karatsuba(const T *a_1, const T *b_1, T *result_final)
    {
        #define OVERFLOWING_MUL(X, Y) (static_cast<T>(static_cast<U>(X) * static_cast<U>(Y)))

        alignas(DEFAULT_MEM_ALIGNMENT) T d01[KARATSUBA_N / 2 - 1];
        alignas(DEFAULT_MEM_ALIGNMENT) T d0123[KARATSUBA_N / 2 - 1];
        alignas(DEFAULT_MEM_ALIGNMENT) T d23[KARATSUBA_N / 2 - 1];
        alignas(DEFAULT_MEM_ALIGNMENT) T result_d01[KARATSUBA_N - 1];

        memset(result_d01, 0, (KARATSUBA_N - 1)*sizeof(T));
        memset(d01, 0, (KARATSUBA_N / 2 - 1)*sizeof(T));
        memset(d0123, 0, (KARATSUBA_N / 2 - 1)*sizeof(T));
        memset(d23, 0, (KARATSUBA_N / 2 - 1)*sizeof(T));
        memset(result_final, 0, (2 * KARATSUBA_N - 1)*sizeof(T));

        T acc1, acc2, acc3, acc4, acc5, acc6, acc7, acc8, acc9, acc10;

        for (size_t i = 0; i < KARATSUBA_N / 4; i++) {
            acc1 = a_1[i];  // a0
            acc2 = a_1[i + KARATSUBA_N / 4];  // a1
            acc3 = a_1[i + 2 * KARATSUBA_N / 4];  // a2
            acc4 = a_1[i + 3 * KARATSUBA_N / 4];  // a3
            for (size_t j = 0; j < KARATSUBA_N / 4; j++)
            {

                acc5 = b_1[j];  // b0
                acc6 = b_1[j + KARATSUBA_N / 4];  // b1

                result_final[i + j + 0 * KARATSUBA_N / 4] =
                    result_final[i + j + 0 * KARATSUBA_N / 4] +
                    OVERFLOWING_MUL(acc1, acc5);
                result_final[i + j + 2 * KARATSUBA_N / 4] =
                    result_final[i + j + 2 * KARATSUBA_N / 4] +
                    OVERFLOWING_MUL(acc2, acc6);

                acc7 = acc5 + acc6;  // b01
                acc8 = acc1 + acc2;  // a01
                d01[i + j] = d01[i + j] + (T)(acc7 * (V)acc8);
                //--------------------------------------------------------

                acc7 = b_1[j + 2 * KARATSUBA_N / 4];  // b2
                acc8 = b_1[j + 3 * KARATSUBA_N / 4];  // b3
                result_final[i + j + 4 * KARATSUBA_N / 4] =
                    result_final[i + j + 4 * KARATSUBA_N / 4] +
                    OVERFLOWING_MUL(acc7, acc3);

                result_final[i + j + 6 * KARATSUBA_N / 4] =
                    result_final[i + j + 6 * KARATSUBA_N / 4] +
                    OVERFLOWING_MUL(acc8, acc4);

                acc9 = acc3 + acc4;
                acc10 = acc7 + acc8;
                d23[i + j] = d23[i + j] + OVERFLOWING_MUL(acc9, acc10);
                //--------------------------------------------------------

                acc5 = acc5 + acc7;  // b02
                acc7 = acc1 + acc3;  // a02
                result_d01[i + j + 0 * KARATSUBA_N / 4] =
                    result_d01[i + j + 0 * KARATSUBA_N / 4] +
                    OVERFLOWING_MUL(acc5, acc7);

                acc6 = acc6 + acc8;  // b13
                acc8 = acc2 + acc4;
                result_d01[i + j + 2 * KARATSUBA_N / 4] =
                    result_d01[i + j + 2 * KARATSUBA_N / 4] +
                    OVERFLOWING_MUL(acc6, acc8);

                acc5 = acc5 + acc6;
                acc7 = acc7 + acc8;
                d0123[i + j] = d0123[i + j] + OVERFLOWING_MUL(acc5, acc7);
            }
        }

        // 2nd last stage

        for (size_t i = 0; i < KARATSUBA_N / 2 - 1; i++) {
            d0123[i] = d0123[i] - result_d01[i + 0 * KARATSUBA_N / 4] - result_d01[i + 2 * KARATSUBA_N / 4];
            d01[i] = d01[i] - result_final[i + 0 * KARATSUBA_N / 4] - result_final[i + 2 * KARATSUBA_N / 4];
            d23[i] = d23[i] - result_final[i + 4 * KARATSUBA_N / 4] - result_final[i + 6 * KARATSUBA_N / 4];
        }

        for (size_t i = 0; i < KARATSUBA_N / 2 - 1; i++) {
            result_d01[i + 1 * KARATSUBA_N / 4] = result_d01[i + 1 * KARATSUBA_N / 4] + d0123[i];
            result_final[i + 1 * KARATSUBA_N / 4] = result_final[i + 1 * KARATSUBA_N / 4] + d01[i];
            result_final[i + 5 * KARATSUBA_N / 4] = result_final[i + 5 * KARATSUBA_N / 4] + d23[i];
        }

        // Last stage
        for (size_t i = 0; i < KARATSUBA_N - 1; i++) {
            result_d01[i] = result_d01[i] - result_final[i] - result_final[i + KARATSUBA_N];
        }

        for (size_t i = 0; i < KARATSUBA_N - 1; i++) {
            result_final[i + 1 * KARATSUBA_N / 2] = result_final[i + 1 * KARATSUBA_N / 2] + result_d01[i];
        }

    }

    /// Toom-Cook 4-way polynomial multiplication
    template<typename U, typename V, size_t n, size_t N_SB>
    static void toom_cook_4way(T *result, const T *a1, const T *b1)
    {
        size_t N_RES    = n << 1;
        size_t N_SB_RES = 2 * N_SB - 1;

        T inv3 = 43691, inv9 = 36409, inv15 = 61167;

        alignas(DEFAULT_MEM_ALIGNMENT) T scratch[7*N_SB + 7*N_SB + 7*N_SB_RES];
        T *aw1 = scratch;
        T *aw2 = aw1 + N_SB;
        T *aw3 = aw2 + N_SB;
        T *aw4 = aw3 + N_SB;
        T *aw5 = aw4 + N_SB;
        T *aw6 = aw5 + N_SB;
        T *aw7 = aw6 + N_SB;
        T *bw1 = aw7 + N_SB;
        T *bw2 = bw1 + N_SB;
        T *bw3 = bw2 + N_SB;
        T *bw4 = bw3 + N_SB;
        T *bw5 = bw4 + N_SB;
        T *bw6 = bw5 + N_SB;
        T *bw7 = bw6 + N_SB;
        T *w1  = bw7 + N_SB;
        T *w2  = w1 + N_SB_RES;
        T *w3  = w2 + N_SB_RES;
        T *w4  = w3 + N_SB_RES;
        T *w5  = w4 + N_SB_RES;
        T *w6  = w5 + N_SB_RES;
        T *w7  = w6 + N_SB_RES;

        // Initialise w1..w7 with all zeros
        std::fill(w1, w7 + N_SB_RES, 0);

        T *A0 = const_cast<T*>(a1);
        T *A1 = const_cast<T*>(&a1[N_SB]);
        T *A2 = const_cast<T*>(&a1[2 * N_SB]);
        T *A3 = const_cast<T*>(&a1[3 * N_SB]);
        T *B0 = const_cast<T*>(b1);
        T *B1 = const_cast<T*>(&b1[N_SB]);
        T *B2 = const_cast<T*>(&b1[2 * N_SB]);
        T *B3 = const_cast<T*>(&b1[3 * N_SB]);
        T *C  = result;

        // Evaluation
        T r0, r1, r2, r3, r4, r5, r6, r7;

        for (size_t j = 0; j < N_SB; j++) {
            r0     = A0[j];
            r1     = A1[j];
            r2     = A2[j];
            r3     = A3[j];
            r4     = r0 + r2;
            r5     = r1 + r3;
            r6     = r4 + r5;
            r7     = r4 - r5;
            aw3[j] = r6;
            aw4[j] = r7;
            r4     = ((r0 << 2) + r2) << 1;
            r5     = (r1 << 2) + r3;
            r6     = r4 + r5;
            r7     = r4 - r5;
            aw5[j] = r6;
            aw6[j] = r7;
            r4     = (r3 << 3) + (r2 << 2) + (r1 << 1) + r0;
            aw2[j] = r4;
            aw7[j] = r0;
            aw1[j] = r3;
        }

        for (size_t j = 0; j < N_SB; j++) {
            r0     = B0[j];
            r1     = B1[j];
            r2     = B2[j];
            r3     = B3[j];
            r4     = r0 + r2;
            r5     = r1 + r3;
            r6     = r4 + r5;
            r7     = r4 - r5;
            bw3[j] = r6;
            bw4[j] = r7;
            r4     = ((r0 << 2) + r2) << 1;
            r5     = (r1 << 2) + r3;
            r6     = r4 + r5;
            r7     = r4 - r5;
            bw5[j] = r6;
            bw6[j] = r7;
            r4     = (r3 << 3) + (r2 << 2) + (r1 << 1) + r0;
            bw2[j] = r4;
            bw7[j] = r0;
            bw1[j] = r3;
        }

        // Multiplication
        karatsuba<U, V, N_SB>(aw1, bw1, w1);
        karatsuba<U, V, N_SB>(aw2, bw2, w2);
        karatsuba<U, V, N_SB>(aw3, bw3, w3);
        karatsuba<U, V, N_SB>(aw4, bw4, w4);
        karatsuba<U, V, N_SB>(aw5, bw5, w5);
        karatsuba<U, V, N_SB>(aw6, bw6, w6);
        karatsuba<U, V, N_SB>(aw7, bw7, w7);

        // Interpolation
        for (size_t i = 0; i < N_SB_RES; i++) {
            r0 = w1[i];
            r1 = w2[i];
            r2 = w3[i];
            r3 = w4[i];
            r4 = w5[i];
            r5 = w6[i];
            r6 = w7[i];

            r1 = r1 + r4;
            r5 = r5 - r4;
            r3 = ((r3 - r2) >> 1);
            r4 = r4 - r0;
            r4 = r4 - (r6 << 6);
            r4 = (r4 << 1) + r5;
            r2 = r2 + r3;
            r1 = r1 - (r2 << 6) - r2;
            r2 = r2 - r6;
            r2 = r2 - r0;
            r1 = r1 + 45 * r2;
            r4 = static_cast<T>(((r4 - (r2 << 3)) * static_cast<U>(inv3)) >> 3);
            r5 = r5 + r1;
            r1 = static_cast<T>(((r1 + (r3 << 4)) * static_cast<U>(inv9)) >> 1);
            r3 = -(r3 + r1);
            r5 = static_cast<T>(((30 * r1 - r5) * static_cast<U>(inv15)) >> 2);
            r2 = r2 - r4;
            r1 = r1 - r5;

            C[i      ] += r6;
            C[i +  64] += r5;
            C[i + 128] += r4;
            C[i + 192] += r3;
            C[i + 256] += r2;
            C[i + 320] += r1;
            C[i + 384] += r0;
        }
    }

};



// Forward declaration of common sizes
extern template class poly<uint8_t>;
extern template class poly<uint16_t>;
extern template class poly<uint32_t>;
#if defined(IS_64BIT)
extern template class poly<uint64_t>;
#endif

}  // namespace core
}  // namespace phantom
