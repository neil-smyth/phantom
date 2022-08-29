/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include "core/reduction.hpp"
#include <type_traits>
#include <cstdint>
#include <cstring>
#include <limits>


namespace phantom {
namespace core {

/** 
 * @brief Low-level reduction using simple additive operations
 * 
 * FOR TEST PURPOSES ONLY
 */
template<typename T>
class reduction_reference : public reduction<T>
{
    static_assert(std::is_same<T, uint8_t>::value  ||
                    std::is_same<T, uint16_t>::value ||
                    std::is_same<T, uint32_t>::value ||
                    std::is_same<T, uint64_t>::value,
            "number instantiated with unsupported type");

public:
    explicit reduction_reference(int32_t q)
    {
        m_q  = q;
        m_q2 = q >> 1;
    }

    virtual ~reduction_reference()
    {
    }

    virtual T get_q() const
    {
        return m_q;
    }

    virtual void convert_to(T *y, const T *x, size_t n) const
    {
        if (y != x) {
            for (size_t i=0; i < n; i++) {
                y[i] = x[i];
            }
        }
    }

    virtual T convert_to(T x) const
    {
        return x;
    }

    virtual T convert_from(T x) const
    {
        return x;
    }

    virtual void convert_from(T *y, const T *x, size_t n) const
    {
        if (y != x) {
            for (size_t i=0; i < n; i++) {
                y[i] = x[i];
            }
        }
    }

    virtual T reduce(T x) const
    {
        while (x >= m_q) {
            x -= m_q;
        }
        while (x < 0) {
            x += m_q;
        }
        return static_cast<T>(x);
    }

    virtual uint64_t mul(uint64_t x, uint64_t y) const
    {
        uint64_t hi, lo;
        mathematics_base<T>::umul(&hi, &lo, x, y);
        uint64_t p = x * y;
        while (p >= m_q) {
            p -= m_q;
        }
        while (p < 0) {
            p += m_q;
        }
        return static_cast<T>(p);
    }

    virtual uint32_t mul(uint32_t x, uint32_t y) const
    {
        uint64_t p = x * y;
        while (p >= m_q) {
            p -= m_q;
        }
        while (p < 0) {
            p += m_q;
        }
        return static_cast<T>(p);
    }

    virtual uint16_t mul(uint16_t x, uint16_t y) const
    {
        uint32_t p = x * y;
        while (p >= m_q) {
            p -= m_q;
        }
        while (p < 0) {
            p += m_q;
        }
        return static_cast<T>(p);
    }

    virtual uint8_t mul(uint8_t x, uint8_t y) const
    {
        uint16_t p = x * y;
        while (p >= m_q) {
            p -= m_q;
        }
        while (p < 0) {
            p += m_q;
        }
        return static_cast<T>(p);
    }

    virtual T sqr(T x) const
    {
        return mul(x, x);
    }

    virtual T div(T x, T y) const
    {
        return reduce(x / y);
    }

    virtual T invert(T x) const
    {
        T xi = std::numeric_limits<T>::digits;
        for (size_t i = x; i > 1; i >>= 1) {
            xi = rshift1(xi);
        }
        return xi;
    }

    virtual T add(T a, T b) const
    {
        return reduce(a + b);
    }

    virtual T sub(T a, T b) const
    {
        return reduce(a - b);
    }

    virtual T negate(T x) const
    {
        return m_q - x;
    }

    virtual T rshift1(T a) const
    {
        a += m_q & -(a & 1);
        return (a >> 1);
    }

    virtual T lshift1(T a) const
    {
        a <<= 1;
        T d = m_q - a;
        a -= m_q & -(d >> (std::numeric_limits<T>::digits - 1));
        return a;
    }

    virtual T pow(T x, T e) const
    {
        T temp, y, cond;
        y = 1;
        cond = static_cast<T>(e & 1) - 1;
        y = (~cond & x) | (cond & y);
        e >>= 1;
        while (e > 0) {
            x = sqr(x);
            temp = mul(x, y);
            cond = static_cast<T>(e & 1) - 1;
            y = (~cond & temp) | (cond & y);
            e >>= 1;
        }
        return y;
    }

private:
    const T m_q;
    const T m_q2;
};

}  // namespace core
}  // namespace phantom


