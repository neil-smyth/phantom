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

#include "core/template_helpers.hpp"


namespace phantom {
namespace core {

/// The mechanism used to perform reduction - an abstract base class
template<typename T>
class reducer
{
    static_assert(std::is_same<T, uint8_t>::value  ||
                  std::is_same<T, uint16_t>::value ||
                  std::is_same<T, uint32_t>::value ||
                  std::is_same<T, uint64_t>::value,
                  "number instantiated with unsupported type");

public:
    virtual ~reducer() {}
    virtual T get_q() const = 0;
};

/**
 * @brief A class providing a range of methods that also perform modular reduction
 * 
 * Uses the adaptor pattern with a concrete implementation C of the reducer class
 * 
 * @tparam C A concrete implementation of the reducer class
 * @tparam T Data type
 */
template<class C, typename T>
class reduction
{
    static_assert(std::is_same<T, uint8_t>::value  ||
                  std::is_same<T, uint16_t>::value ||
                  std::is_same<T, uint32_t>::value ||
                  std::is_same<T, uint64_t>::value,
                  "number instantiated with unsupported type");

    const reducer<T>& m_reducer;

public:
    explicit reduction(const reducer<T>& r) : m_reducer(r)
    {
    }

    virtual ~reduction() {}

    /// Return the reducer object
    T get_q() const
    {
        return C::static_get_q(m_reducer);
    }

    /// Convert an array to the reduction domain, with granular stride control
    void convert_to(T *y, const T *x, size_t n, size_t stride = 1) const
    {
        C::static_convert_to(m_reducer, y, x, n, stride);
    }

    /// Convert to the reduction domain
    T convert_to(T x) const
    {
        return C::static_convert_to(m_reducer, x);
    }

    /// Convert from the reduction domain
    T convert_from(T x) const
    {
        return C::static_convert_from(m_reducer, x);
    }

    /// Convert an array from the reduction domain, with granular stride control
    void convert_from(T *y, const T *x, size_t n, size_t stride = 1) const
    {
        C::static_convert_from(m_reducer, y, x, n, stride);
    }

    /// Apply reduction to a variable
    T reduce(T x) const
    {
        return C::static_reduce(m_reducer, x);
    }

    /// Multiply two variables and apply reduction
    T mul(T x, T y) const
    {
        return C::static_mul(m_reducer, x, y);
    }

    /// Square a variable and apply reduction
    T sqr(T x) const
    {
        return C::static_sqr(m_reducer, x);
    }

    // Divide x by y, returning the result in the reduction domain
    T div(T x, T y) const
    {
        return C::static_div(m_reducer, x, y);
    }

    // Calculate the inverse of x in the reduction domain
    T inverse(T x) const
    {
        return C::static_inverse(m_reducer, x);
    }

    // Calculate the inverse of 2^x in the reduction domain
    T inverse_2k(T x) const
    {
        return C::static_inverse_2k(m_reducer, x);
    }

    // Add two operands in the reduction domain
    T add(T a, T b) const
    {
        return C::static_add(m_reducer, a, b);
    }

    // Subtract two operands in the reduction domain
    T sub(T a, T b) const
    {
        return C::static_sub(m_reducer, a, b);
    }

    // Negate in the reduction domain
    T negate(T x) const
    {
        return C::static_negate(m_reducer, x);
    }

    // Right shift by 1 bit in the reduction domain
    T rshift1(T a) const
    {
        return C::static_rshift1(m_reducer, a);
    }

    // Left shift by 1 bit in the reduction domain
    T lshift1(T a) const
    {
        return C::static_lshift1(m_reducer, a);
    }

    // Calculate x^e in the reduction domain
    T pow(T x, T e) const
    {
        return C::static_pow(m_reducer, x, e);
    }
};

}  // namespace core
}  // namespace phantom
