/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include "core/ntt.hpp"
#include <iostream>
#include "core/number.hpp"
#include "core/bit_manipulation.hpp"
#include "core/reduction_montgomery.hpp"
#include "core/const_time.hpp"
#include "logging/logger.hpp"
#include "./phantom_memory.hpp"


namespace phantom {
namespace core {

/// @class ntt_binary A parameterisable binary Number Theoretic Transform (NTT)
template<class R, typename T>
class ntt_binary : public ntt_base<T>
{
    static_assert(std::is_same<T, uint8_t>::value  ||
                  std::is_same<T, uint16_t>::value ||
                  std::is_same<T, uint32_t>::value ||
                  std::is_same<T, uint64_t>::value,
                  "number instantiated with unsupported type");

private:
    const reduction<R, T>& m_reduce;   ///< Reduction object (passed by reference)
    const size_t           m_n;        ///< Length of the NTT
    const T                m_invn;     ///< Modular inverse of the length
    phantom_vector<T>      m_fwd;      ///< Table for the NTT
    phantom_vector<T>      m_inv;      ///< Table for the INTT
    log_level_e            m_logging;  ///< Base logging level

public:
    /// Constructor with user-defined generator and inverse generator
    ntt_binary(const reduction<R, T>& reduce, T g, T invg, size_t n, log_level_e logging = LOG_LEVEL_NONE) :
        m_reduce(reduce),
        m_n(n),
        m_invn(m_reduce.inverse_2k(m_n)),
        m_logging(logging)
    {
        LOG_DEBUG("Using provided primitive nth-root: g = " << g << ", invg = " << invg, m_logging);

        // Generate the necessary NTT lookup tables
        init(g, invg, n);
    }

    /// Constructor with user-defined generator
    ntt_binary(const reduction<R, T>& reduce, T g, size_t n, log_level_e logging = LOG_LEVEL_NONE) :
        m_reduce(reduce),
        m_n(n),
        m_invn(m_reduce.inverse_2k(m_n)),
        m_logging(logging)
    {
        T q      = m_reduce.get_q();
        T invg   = number<T>::umod_mul_inverse(g, q);

        LOG_DEBUG("Using provided primitive nth-root: g = " << g << ", invg = " << invg, m_logging);

        // Generate the necessary NTT lookup tables
        init(g, invg, n);
    }

    /// Constructor that must calculate generator and inverse generator
    ntt_binary(const reduction<R, T>& reduce, size_t n, log_level_e logging = LOG_LEVEL_NONE) :
        m_reduce(reduce),
        m_n(n),
        m_invn(m_reduce.inverse_2k(m_n)),
        m_logging(logging)
    {
        // No generator or inverse generator polynomial are provided,
        // therefore they are computed
        T q      = m_reduce.get_q();
        T g      = find_prim_root(q, m_n);
        T invg   = number<T>::umod_mul_inverse(g, q);

        LOG_DEBUG("Deriving primitive nth-root: g = " << g << ", invg = " << invg, m_logging);

        // Generate the necessary NTT lookup tables
        init(g, invg, n);
    }

    /// Class destructor
    virtual ~ntt_binary() {}

    /// Cooley-Tukey NTT algorithm
    void fwd(T *a, size_t logn, size_t stride = 1) override
    {
        const T* p = m_fwd.data();
        const size_t n = 1 << logn;

        if (0 == logn) {
            return;
        }

        for (size_t m = 1, t = n; m < n; m <<= 1) {
            const size_t ht = t >> 1;
            for (size_t i = 0; i < m; i++) {
                const size_t j1 = i * t;
                const size_t j2 = j1 + ht;
                const T s = p[m + i];
                T* _RESTRICT_ a0 = a + j1 * stride;
                T* _RESTRICT_ a1 = a + j2 * stride;
                for (size_t j = 0; j < ht * stride; j += stride) {
                    const T u = a0[j];
                    const T v = m_reduce.mul(a1[j], s);
                    a0[j] = m_reduce.add(u, v);
                    a1[j] = m_reduce.sub(u, v);
                }
            }
            t = ht;
        }
    }

    /// Gentleman-Sande inverse NTT algorithm
    void inv(T *a, size_t logn, size_t stride = 1) override
    {
        const T* p = m_inv.data();
        const size_t n = 1 << logn;

        if (0 == logn) {
            return;
        }

        size_t t = 1;
        size_t m = n;
        while (m > 1) {
            const size_t hm = m >> 1;
            const size_t dt = t << 1;
            for (size_t i = 0; i < hm; i++) {
                const size_t j1 = i * dt;
                const size_t j2 = j1 + t;
                const T s = p[hm + i];
                T* _RESTRICT_ a0 = a + j1 * stride;
                T* _RESTRICT_ a1 = a + j2 * stride;
                for (size_t j = 0; j < t * stride; j += stride) {
                    const T u = a0[j];
                    const T v = a1[j];
                    const T w = m_reduce.sub(u, v);
                    a0[j] = m_reduce.add(u, v);
                    a1[j] = m_reduce.mul(w, s);
                }
            }
            t = dt;
            m = hm;
        }

        // Finally, divide each element of the ring polynomial by n. This is
        // achieved by first computing 1/n (division of 1 by 2 log(n) times) and
        // performing modular multiplication of each element.
        for (m = 0; m < n * stride; m += stride) {
            a[m] = m_reduce.mul(a[m], m_invn);
        }
    }

    /// Modular multiplication of a polynomial in the NTT domain
    void mul(T* out, const T *x, const T *y, size_t stride = 1) override
    {
        for (size_t i = 0; i < m_n; i+=stride) {
            out[i] = m_reduce.mul(x[i], y[i]);
        }
    }

    /// Modular squaring of a polynomial in the NTT domain
    void sqr(T* out, const T* x, size_t stride = 1) override
    {
        for (size_t i = 0; i < m_n; i+=stride) {
            out[i] = m_reduce.sqr(x[i]);
        }
    }

    /// Modular negation of a polynomial in the NTT domain
    void negate(T* a, size_t stride = 1) override
    {
        for (size_t i = 0; i < m_n; i+=stride) {
            a[i] = m_reduce.negate(a[i]);
        }
    }

    /// Modular inversion of a polynomial in the NTT domain
    bool inverse(T *a, size_t stride = 1) override
    {
        T q = m_reduce.get_q();
        for (size_t i = 0; i < m_n; i+=stride) {
            T x = a[i];
            if (0 == x) {
                return false;
            }
            a[i] = m_reduce.pow(x, q - 2);
        }
        return true;
    }

private:
    /// LUT initialization
    void init(T g, T invg, size_t n)
    {
        size_t logn = bit_manipulation::log2(static_cast<uint16_t>(n));

        // Create the forward LUT as f[x] = g^rev[x] mod q
        m_fwd = phantom_vector<T>(n);
        gen_table(g, logn, m_fwd.data());

        // Create the inverse LUT as f[x] = (1/g)^rev[x] mod q
        m_inv = phantom_vector<T>(n);
        gen_table(invg, logn, m_inv.data());
    }

    /// Calculate the primitive root given the modulus and N
    static T find_prim_root(T q, size_t n)
    {
        // Iterate from 2 to q-1 inclusive
        for (T m = 2; m < q; m++) {
            T sum = 0;
            T p   = m;

            // Calculate m ^ 2N mod q
            for (T l = 1; l < 2*n; l++) {
                T hi, lo;
                number<T>::umul(&hi, &lo, m, p);
                p = number<T>::umod_nnd(hi, lo, q);
                sum += (p == 1);
            }

            // The 2N-th value we compute must be 1 and we must not have
            // previously computed a root equal to 1
            if (1 != sum || 1 != p) {
                continue;
            }

            return m;
        }

        throw std::invalid_argument("modulus q has no 2n-th primitive root of 1 modulo q");
    }

    /// Generate a table for the specified generator
    void gen_table(T g, size_t logn, T* p)
    {
        size_t n = 1 << logn;

        // Convert the generator to the representation required by the reducer
        T g_base = m_reduce.convert_to(g);

        // Left-to-right square-and-multiply to obtain each coefficient
        T result = m_reduce.convert_to(1);
        for (uint16_t i = 0; i < n; i++) {
            T exp  = bit_manipulation::reverse(i) >> (16 - logn);
            p[exp] = result;
            result = m_reduce.mul(result, g_base);
        }
    }
};

// Forward declaration of common sizes
extern template class ntt_binary<reduction_montgomery<uint32_t>, uint32_t>;

}  // namespace core
}  // namespace phantom
