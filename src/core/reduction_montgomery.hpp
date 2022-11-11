/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <type_traits>
#include <cstdint>
#include <cstring>
#include <limits>
#include <iostream>
#include "core/reduction.hpp"
#include "core/number.hpp"
#include "core/bit_manipulation.hpp"
#include "./phantom_types.hpp"


namespace phantom {
namespace core {


/**
 * @brief A Montgomery class derived from the reducer base class
 * 
 * @tparam T Data type
 */
template<typename T>
class montgomery : public reducer<T>
{
    static_assert(std::is_same<T, uint8_t>::value  ||
                    std::is_same<T, uint16_t>::value ||
                    std::is_same<T, uint32_t>::value ||
                    std::is_same<T, uint64_t>::value,
            "number instantiated with unsupported type");


    static inline T mul_internal(T x, T y, T q, T invq, size_t b2)
    {
#if defined(__GNUG__)
        using U = next_size_t<T>;
        U a = static_cast<U>(x) * static_cast<U>(y);
        U b = ((a * invq) & (-static_cast<T>(1) >> (std::numeric_limits<T>::digits - b2))) * q;
        x  = (a + b) >> b2;
        x -= q;
        x += q & -(x >> (std::numeric_limits<T>::digits - 1));
#else
        T a[2], b[2];
        number<T>::umul(&a[1], &a[0], x, y);
        number<T>::umul(&b[1], &b[0],
            ((a[0] * invq) & (-static_cast<T>(1) >> (std::numeric_limits<T>::digits - b2))), q);
        number<T>::uadd(&b[1], &b[0], a[1], a[0], b[1], b[0]);
        x  = (b[1] << (std::numeric_limits<T>::digits - b2)) | (b[0] >> b2);
        x -= q;
        x += q & -(x >> (std::numeric_limits<T>::digits - 1));
#endif
        return x;
    }

public:
    const T m_q;        ///< The modulus
    const T m_invq;     ///< The inverse modulus
    const size_t m_b2;  ///< The word size in bits
    const T m_mask;     ///< A mask where all used bits in m_b are asserted high
    const T m_R;        ///< The Montgomery parameter R = B mod q
    const T m_R2;       ///< The Montgomery parameter R2 = B^2 mod q

public:
    /// Class constructor
    montgomery(T q, T invq, size_t b, T R, T R2) :
        m_q(q),
        m_invq(invq),
        m_b2(b),
        m_mask(-static_cast<T>(1) >> (std::numeric_limits<T>::digits - b)),
        m_R(R),
        m_R2(R2)
    {
    }

    /// Class constructor
    montgomery(T q, size_t b) :
        m_q(q),
        m_invq(core::number<T>::uninv_minus1(q)),
        m_b2(b),
        m_mask(-static_cast<T>(1) >> (std::numeric_limits<T>::digits - b)),
        m_R(montgomery<T>::gen_R(q, b)),
        m_R2(montgomery<T>::gen_R2(q, m_invq, b))
    {
    }

    /// Class destructor
    virtual ~montgomery()
    {
    }

    /// Return the modulus, q
    virtual T get_q() const
    {
        return m_q;
    }

    /// Return the Montgomery R parameter
    T get_R()
    {
        return m_R;
    }

    /// Return the Montgomery R2 parameter
    T get_R2()
    {
        return m_R2;
    }

    /// Calculate the Montgomery R parameter (B mod q)
    static T gen_R(T q, size_t b2 = std::numeric_limits<T>::digits)
    {
        return (-static_cast<T>(1) >> (std::numeric_limits<T>::digits - b2)) - q + 1;
    }

    /// Calculate the Montgomery R2 parameter (B^2 mod q)
    static T gen_R2(T q, T invq, size_t b2 = std::numeric_limits<T>::digits)
    {
        T z;

        // Compute z = 2^(digits - 1) mod p (this is the value 1 in Montgomery
        // representation), then double it with an addition.
        z = gen_R(q, b2);
        z = z + z;
        z += ((q - z - 1) >> (std::numeric_limits<T>::digits - 1)) * q;

        // Square z log2(B) times to obtain B in Montgomery representation
        T iter = core::bit_manipulation::log2(static_cast<uint32_t>(std::numeric_limits<T>::digits));
        for (size_t i = 0; i < iter; i++) {
            z = mul_internal(z, z, q, invq, b2);
        }

        // Halve the value mod p to get 2^(2*digits - 2).
        z = (z + (q & -(z & 1))) >> 1;
        return z;
    }

    /// Calculate 2^x mod q
    static T gen_Rx(T x, T q, T invq, T R, T R2, size_t b2 = std::numeric_limits<T>::digits)
    {
        T z, y;

        x--;
        y = R2;
        z = R;

        for (size_t i=0; (1U << i) <= x; i++) {
            if ((x & (1U << i)) != 0) {
                z = mul_internal(y, z, q, invq, b2);
            }
            y = mul_internal(y, y, q, invq, b2);
        }

        return z;
    }
};

/** 
 * @brief Low-level Montgomery reduction class
 * 
 * Template class that provides Montgomery reduction for unsigned numbers
 * represented by arrays of data types that can be handled by the processor.
 * Derived from the reduction interface class. Uses static polymorphism with CRTP.
 */
template<typename T>
class reduction_montgomery : public reduction<reduction_montgomery<T>, T>
{
    static_assert(std::is_same<T, uint8_t>::value  ||
                  std::is_same<T, uint16_t>::value ||
                  std::is_same<T, uint32_t>::value ||
                  std::is_same<T, uint64_t>::value,
                  "number instantiated with unsupported type");

#if defined(__GNUG__)
    using U = next_size_t<T>;
#endif

public:
    explicit reduction_montgomery(const reducer<T>& r) : reduction<reduction_montgomery<T>, T>(r) {}
    ~reduction_montgomery() {}

    /// Return the reducer object
    static T static_get_q(const reducer<T>& mont)
    {
        return mont.get_q();
    }

    /// Convert an array to the reduction domain, with granular stride control
    static void static_convert_to(const reducer<T>& r, T *y, const T *x, size_t n, size_t stride = 1)
    {
        const montgomery<T>& mont = static_cast<const montgomery<T>&>(r);
        for (size_t i = 0; i < n; i += stride) {
            y[i] = static_mul(r, x[i], mont.m_R2);
        }
    }

    /// Convert from the reduction domain
    static T static_convert_to(const reducer<T>& r, T x)
    {
        const montgomery<T>& mont = static_cast<const montgomery<T>&>(r);
        return static_mul(r, x, mont.m_R2);
    }

    static T static_convert_from(const reducer<T>& r, T x)
    {
        return static_mul(r, x, 1);
    }

    /// Convert an array from the reduction domain, with granular stride control
    static void static_convert_from(const reducer<T>& r, T *y, const T *x, size_t n, size_t stride = 1)
    {
        for (size_t i = 0; i < n; i += stride) {
            y[i] = static_mul(r, x[i], 1);
        }
    }

    /// Apply reduction to a variable
    static T static_reduce(const reducer<T>& r, T x)
    {
        const montgomery<T>& mont = static_cast<const montgomery<T>&>(r);
#if defined(__GNUG__)
        U d = x - mont.m_q;
        d += mont.m_q & -(d >> (std::numeric_limits<U>::digits - 1));
        return static_cast<T>(d);
#else
        T d[2];
        number<T>::usub(&d[1], &d[0], 0, x, 0, mont.m_q);
        d[0] += mont.m_q & -(d[1] >> (std::numeric_limits<T>::digits-1));
        return d[0];
#endif
    }

    /// Multiply two variables and apply reduction
    static T static_mul(const reducer<T>& r, T x, T y)
    {
        const montgomery<T>& mont = static_cast<const montgomery<T>&>(r);
#if defined(__GNUG__)
        U z, w;
        T d;
        z  = static_cast<U>(x) * static_cast<U>(y);
        w  = ((z * mont.m_invq) & mont.m_mask) * static_cast<U>(mont.m_q);
        d  = static_cast<T>((z + w) >> mont.m_b2);
#else
        T d, z[2], w[2];
        number<T>::umul(&z[1], &z[0], x, y);
        w[0] = z[0] * mont.m_invq;
        number<T>::umul(&w[1], &w[0], w[0] & mont.m_mask, mont.m_q);
        number<T>::uadd(&z[1], &z[0], z[1], z[0], w[1], w[0]);
        d = (z[1] << (std::numeric_limits<T>::digits - mont.m_b2)) | (z[0] >> mont.m_b2);
#endif
        d -= mont.m_q;
        d += mont.m_q & -(d >> (std::numeric_limits<T>::digits - 1));
        return d;
    }

    /// Square a variable and apply reduction
    static T static_sqr(const reducer<T>& r, T x)
    {
        return static_mul(r, x, x);
    }

    /// Divide x by y, returning the result in the Montgomery domain
    static T static_div(const reducer<T>& r, T x, T y)
    {
        const montgomery<T>& mont = static_cast<const montgomery<T>&>(r);

        T e = mont.get_q() - 2;

        // Convert x from the Montgomery representation
        T z1 = y;

        // 1/x = x^(q-2) mod q using a square-and-multiply algorithm
        for (ssize_t i = std::numeric_limits<T>::digits - 2; i >= 0; i--) {
            T z2;
            z1  = static_sqr(r, z1);
            z2  = static_mul(r, z1, x);
            z1 ^= (z1 ^ z2) & -static_cast<T>((e >> i) & 1);
        }

        // x is not in Montgomery representation, so result is correct
        return static_mul(r, x, z1);
    }

    /// Calculate the inverse of x in the Montgomery domain
    static T static_inverse(const reducer<T>& r, T x)
    {
        const montgomery<T>& mont = static_cast<const montgomery<T>&>(r);

        T e = mont.get_q() - 2;

        // Convert x from the Montgomery representation
        T z1 = static_convert_to(mont, x);

        // 1/x = x^(q-2) mod q using a square-and-multiply algorithm
        for (ssize_t i = std::numeric_limits<T>::digits - 2; i >= 0; i--) {
            T z2;
            z1  = static_sqr(r, z1);
            z2  = static_mul(r, z1, x);
            z1 ^= (z1 ^ z2) & -static_cast<T>((e >> i) & 1);
        }

        return z1;
    }

    /// Calculate the inverse of 2^x in the Montgomery domain
    static T static_inverse_2k(const reducer<T>& r, T x)
    {
        const montgomery<T>& mont = static_cast<const montgomery<T>&>(r);

        T xi = mont.m_R;
        for (size_t i = x; i > 1; i >>= 1) {
            xi = static_rshift1(r, xi);
        }
        return xi;
    }

    /// Addition of two words with Montgomery reduction
    static T static_add(const reducer<T>& r, T a, T b)
    {
        const montgomery<T>& mont = static_cast<const montgomery<T>&>(r);

        T d = static_cast<T>(a) + static_cast<T>(b) - static_cast<T>(mont.m_q);
        d += mont.m_q & -(d >> (std::numeric_limits<T>::digits - 1));
        return d;
    }

    /// Subtraction of two words with Montgomery reduction
    static T static_sub(const reducer<T>& r, T a, T b)
    {
        const montgomery<T>& mont = static_cast<const montgomery<T>&>(r);

        T d = static_cast<T>(a) - static_cast<T>(b);
        d += mont.m_q & -(d >> (std::numeric_limits<T>::digits - 1));
        return d;
    }

    /// Negation modulo q
    static T static_negate(const reducer<T>& r, T x)
    {
        const montgomery<T>& mont = static_cast<const montgomery<T>&>(r);
        return core::bit_manipulation::negate_mod(x, mont.m_q);
    }

    /// Right shift by 1 bit modulo q
    static T static_rshift1(const reducer<T>& r, T a)
    {
        const montgomery<T>& mont = static_cast<const montgomery<T>&>(r);
        a += mont.m_q & -(a & 1);
        return (a >> 1);
    }

    /// Left shift by 1 bit modulo q
    static T static_lshift1(const reducer<T>& r, T a)
    {
        const montgomery<T>& mont = static_cast<const montgomery<T>&>(r);
#if defined(__GNUG__)
        U b = static_cast<U>(a) << 1;
        U d = static_cast<U>(mont.m_q) - b;
        b -= mont.m_q & -(d >> (std::numeric_limits<U>::digits - 1));
        return b;
#else
        T b[2], d[2];
        number<T>::uadd(&b[1], &b[0], 0, a, 0, a);
        number<T>::usub(&d[1], &d[0], 0, mont.m_q, b[1], b[0]);
        b[0] -= mont.m_q & -(d[1] >> (std::numeric_limits<T>::digits-1));
        return b[0];
#endif
    }

    /// x^e using square-and-multiply and Montgomery reduction
    static T static_pow(const reducer<T>& r, T x, T e)
    {
        const montgomery<T>& mont = static_cast<const montgomery<T>&>(r);

        T temp, y, cond;
        y = mont.m_R;  // i.e. 1
        cond = static_cast<T>(e & 1) - 1;
        y = (~cond & x) | (cond & y);
        e >>= 1;
        while (e > 0) {
            x = static_sqr(r, x);
            temp = static_mul(r, x, y);
            cond = static_cast<T>(e & 1) - 1;
            y = (~cond & temp) | (cond & y);
            e >>= 1;
        }
        return y;
    }
};

}  // namespace core
}  // namespace phantom
