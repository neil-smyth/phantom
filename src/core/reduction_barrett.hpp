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
#include "core/bit_manipulation.hpp"


namespace phantom {
namespace core {

/**
 * @brief Low-level Barrett reduction using floating point arithmetic
 * 
 * The divisor is computed and stored as an inverse float
 * 
 */
template<typename T>
class barrett_fp : public reducer<T>
{
    static_assert(std::is_same<T, uint8_t>::value  ||
                  std::is_same<T, uint16_t>::value ||
                  std::is_same<T, uint32_t>::value ||
                  std::is_same<T, uint64_t>::value,
                  "number instantiated with unsupported type");

    using U = next_size_t<T>;

public:
    const T m_q;
    const float m_inv_q;
    const size_t m_shift;

public:
    explicit barrett_fp(T q) :
        m_q(q),
        m_inv_q(1.0f / static_cast<float>(q)),
        m_shift(std::numeric_limits<T>::digits - 1)
    {
    }

    virtual ~barrett_fp()
    {
    }

    /// Return the modulus value
    virtual T get_q() const
    {
        return m_q;
    }
};

/** 
 * @brief  Low-level Barrett reduction class.
 * 
 * Template class that provides Barrett reduction for unsigned numbers
 * represented by arrays of data types that can be handled by the processor.
 * To complement Montgomery reduction other operations are also provided to
 * match the reduction interface class.
 * Uses static polymorphism with CRTP.
 */
template<typename T>
class reduction_barrett : public reduction<reduction_barrett<T>, T>
{
    static_assert(std::is_same<T, uint8_t>::value  ||
                  std::is_same<T, uint16_t>::value ||
                  std::is_same<T, uint32_t>::value ||
                  std::is_same<T, uint64_t>::value,
                  "number instantiated with unsupported type");

    using U = next_size_t<T>;

public:
    explicit reduction_barrett(const reducer<T>& r) : reduction<reduction_barrett<T>, T>(r) {}
    virtual ~reduction_barrett() {}

    /// Return the modulus value
    static T static_get_q(const reducer<T>& r)
    {
        return r.get_q();
    }

    /// Convert an array to a representation used for Barrett reduction, i.e. do nothing
    static void static_convert_to(const reducer<T>& r, T *y, const T *x, size_t n)
    {
        // If the address of x and y are different, then we must copy
        if (y != x) {
            for (size_t i = 0; i < n; i++) {
                y[i] = x[i];
            }
        }
    }

    /// Convert a value to a representation used for Barrett reduction, i.e. do nothing
    static T static_convert_to(const reducer<T>& r, T x)
    {
        return x;
    }

    /// Convert a value from a representation used for Barrett reduction, i.e. do nothing
    static T static_convert_from(const reducer<T>& r, T x)
    {
        return x;
    }

    /// Convert an array from a representation used for Barrett reduction, i.e. do nothing
    static void static_convert_from(const reducer<T>& r, T *y, const T *x, size_t n)
    {
        // If the address of x and y are different, then we must copy
        if (y != x) {
            for (size_t i = 0; i < n; i++) {
                y[i] = x[i];
            }
        }
    }

    /// Barrett reduction of a single word
    static T static_reduce(const reducer<T>& r, T x)
    {
        const barrett_fp<T>& fp = static_cast<const barrett_fp<T>&>(r);
        float t = static_cast<float>(x) * fp.m_inv_q;
        return x - fp.m_q * static_cast<U>(t);
    }

    /// Multiplication of two words with Barrett reduction
    static T static_mul(const reducer<T>& r, T x, T y)
    {
        const barrett_fp<T>& fp = static_cast<const barrett_fp<T>&>(r);
        U p = static_cast<U>(x) * static_cast<U>(y);
        float t = static_cast<float>(p) * fp.m_inv_q;
        return p - fp.m_q * static_cast<U>(t);
    }

    /// Squaring of a word with Barrett reduction
    static T static_sqr(const reducer<T>& r, T x)
    {
        const barrett_fp<T>& fp = static_cast<const barrett_fp<T>&>(r);
        U p = static_cast<U>(x) * static_cast<U>(x);
        float t = static_cast<float>(p) * fp.m_inv_q;
        return p - fp.m_q * static_cast<U>(t);
    }

    /// Division with Barrett reduction
    static T static_div(const reducer<T>& r, T x, T y)
    {
        const barrett_fp<T>& fp = static_cast<const barrett_fp<T>&>(r);

        T e = fp.get_q() - 2;

        // Convert y to the Barrett representation
        T z1 = y;

        // 1/y = y^(q-2) mod q using a square-and-multiply algorithm
        for (ssize_t i = bit_manipulation::log2_ceil(e) - 2; i >= 0; i--) {
            T z2;
            z1  = static_sqr(r, z1);
            z2  = static_mul(r, z1, y);
            z1 ^= (z1 ^ z2) & -static_cast<T>((e >> i) & 1);
        }

        // x is not in Barrett representation, so result is correct
        return static_mul(r, x, z1);
    }

    /// Inversion of a word
    static T static_inverse(const reducer<T>& r, T x)
    {
        using S = typename std::make_signed<T>::type;

        const barrett_fp<T>& fp = static_cast<const barrett_fp<T>&>(r);

        T y0, quo, rem;
        S t2;
        S v1 = 0;
        S v2 = 1;
        T y = fp.m_q;

        y0 = y;

        // If x and y both have MSB set then swap and
        // scale the parameters
        if ((y & x) & (static_cast<T>(1) << (std::numeric_limits<T>::digits-1))) {
            quo = y - x;
            y   = x;
            t2  = v2;
            v2  = v1 - v2;
            v1  = t2;
            x   = quo;
        }

        // Whilst the second value has second MSB set
        while (x & (static_cast<T>(1) << (std::numeric_limits<T>::digits-2))) {
            quo = y - x;
            y   = x;
            t2  = v2;
            if (quo < x) {
                v2 = v1 - v2;
                x = quo;
            }
            else if (quo < (x << 1)) {
                v2 = v1 - (v2 << 1);
                x = quo - y;
            }
            else {
                v2 = v1 - 3 * v2;
                x = quo - (y << 1);
            }
            v1  = t2;
        }

        while (x) {
            if (y < (x << 2)) {
                quo = y - x;       // NOTE: Same as loop above
                y   = x;
                t2  = v2;
                if (quo < x) {
                    v2 = v1 - v2;
                    x = quo;
                }
                else if (quo < (x << 1)) {
                    v2 = v1 - (v2 << 1);
                    x = quo - y;
                }
                else {
                    v2 = v1 - 3 * v2;
                    x = quo - (y << 1);
                }
                v1  = t2;
            }
            else {
                quo = y / x;
                rem = y - x * quo;

                y   = x;
                t2  = v2;
                v2  = v1 - quo * v2;
                v1  = t2;
                x   = rem;
            }
        }

        // Ensure that the inverse is positive modulo y
        if (v1 < 0) {
            v1 += y0;
        }

        return v1;
    }

    /// Addition of two words with Barrett reduction
    static T static_add(const reducer<T>& r, T a, T b)
    {
        const barrett_fp<T>& fp = static_cast<const barrett_fp<T>&>(r);
        U d = static_cast<U>(a) + static_cast<U>(b) - static_cast<U>(fp.m_q);
        d += fp.m_q & -(d >> (std::numeric_limits<U>::digits-1));
        return d;
    }

    /// Subtraction of two words with Barrett reduction
    static T static_sub(const reducer<T>& r, T a, T b)
    {
        const barrett_fp<T>& fp = static_cast<const barrett_fp<T>&>(r);
        U d = static_cast<U>(a) - static_cast<U>(b);
        d += fp.m_q & -(d >> (std::numeric_limits<U>::digits-1));
        return d;
    }

    /// Negation modulo q
    static T static_negate(const reducer<T>& r, T x)
    {
        const barrett_fp<T>& fp = static_cast<const barrett_fp<T>&>(r);
        return bit_manipulation::negate_mod(x, fp.m_q);
    }

    /// Right shift by 1 bit modulo q
    static T static_rshift1(const reducer<T>& r, T a)
    {
        const barrett_fp<T>& fp = static_cast<const barrett_fp<T>&>(r);
        a += fp.m_q & -(a & 1);
        return (a >> 1);
    }

    /// Left shift by 1 bit modulo q
    static T static_lshift1(const reducer<T>& r, T a)
    {
        const barrett_fp<T>& fp = static_cast<const barrett_fp<T>&>(r);
        U b = static_cast<U>(a) << 1;
        U d = static_cast<U>(fp.m_q) - b;
        b -= fp.m_q & -(d >> (std::numeric_limits<U>::digits-1));
        return b;
    }

    /// x^e using square-and-multiply and Barrett reduction
    static T static_pow(const reducer<T>& r, T x, T e)
    {
        T temp, y, cond;
        y = 1;
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
