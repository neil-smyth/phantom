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
#include <vector>
#include <limits>
#include "./core/template_helpers.hpp"


namespace phantom {
namespace core {

/**
 * @brief Constant-time condition logic
 * 
 */
template<typename T>
class const_time_enabled
{

public:
    /// Compare two arrays in constant-time, returns 0 if equal, otherwise returns non-zero
    static T cmp_array_not_equal(volatile const T *in1, volatile const T *in2, size_t n)
    {
        volatile T not_equal = 0;
        for (size_t i=n; i--;) {
            not_equal |= in1[i] ^ in2[i];
        }
        not_equal = (-not_equal) >> (std::numeric_limits<T>::digits - 1);
        return not_equal;
    }

    /// Compare two arrays in constant-time, returns 0 if equal, otherwise returns 1
    static T cmp_array_equal(volatile const T *in1, volatile const T *in2, size_t n)
    {
        volatile T not_equal = 0;
        for (size_t i=n; i--;) {
            not_equal |= in1[i] ^ in2[i];
        }
        not_equal = (-not_equal) >> (std::numeric_limits<T>::digits - 1);
        return not_equal ^ 1;
    }

    /// Returns 1 if a is less than b, 0 otherwise
    static T cmp_lessthan(volatile T a, volatile T b)
    {
        const size_t bits = std::numeric_limits<T>::digits - 1;
        return ((((a ^ b) & ((a - b) ^ b)) ^ (a - b)) & (static_cast<T>(1) << bits)) >> bits;
    }

    /// Return a if c is 1, 0 if c is 0
    static T if_condition_is_true(T c, T a)
    {
        return c * a;
    }

    /// Return a if c is 0, 0 if c is 1
    static T if_condition_is_false(T c, T a)
    {
        return (c - 1) & a;
    }

    /// Return a if c is negative, 0 otherwise
    static T if_negative(T c, T a)
    {
        /// Check for valid types
        static_assert(std::is_signed<T>::value,
                      "if_negative<T>() instantiated with unsigned type");

        const size_t bits = std::numeric_limits<T>::digits - 1;
        return (c >> bits) & a;
    }

    /// Return a if x is more than or equal to y, 0 otherwise
    static T if_gte(T x, T y, T a)
    {
        /// Check for valid types
        static_assert(std::is_same<T, uint8_t>::value  ||
                      std::is_same<T, uint16_t>::value ||
                      std::is_same<T, uint32_t>::value ||
                      std::is_same<T, uint64_t>::value,
                      "if_gte<T>() instantiated with unsupported type");

        using S = signed_type_t<T>;
        const size_t bits = std::numeric_limits<T>::digits - 1;
        return T(S(y - x - 1) >> bits) & a;
    }

    /// Return a if x is less than y, 0 otherwise
    static T if_lte(T x, T y, T a)
    {
        /// Check for valid types
        static_assert(std::is_same<T, uint8_t>::value  ||
                      std::is_same<T, uint16_t>::value ||
                      std::is_same<T, uint32_t>::value ||
                      std::is_same<T, uint64_t>::value,
                      "if_lte<T>() instantiated with unsupported type");

        using S = signed_type_t<T>;
        const size_t bits = std::numeric_limits<T>::digits - 1;
        return T(S(x - y - 1) >> bits) & a;
    }

private:
    const_time_enabled() {}
    ~const_time_enabled() {}
};

}  // namespace core
}  // namespace phantom
