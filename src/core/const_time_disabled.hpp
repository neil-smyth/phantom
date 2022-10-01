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


namespace phantom {

/**
 * @brief Non constant-time condition logic
 * 
 */
template<typename T>
class const_time_disabled
{
    /// Check for valid types
    static_assert(std::is_same<T, uint8_t>::value  ||
                  std::is_same<T, uint16_t>::value ||
                  std::is_same<T, uint32_t>::value ||
                  std::is_same<T, uint64_t>::value,
                  "if_gte<T>() instantiated with unsupported type");

public:
    /// Compare two arrays, returns 0 if equal, otherwise returns 1
    static T cmp_array_not_equal(const T *in1, const T *in2, size_t n)
    {
        for (size_t i=n; i--;) {
            if (in1[i] != in2[i]) {
                return 1;
            }
        }
        return 0;
    }

    /// Returns 1 if a is less than b, 0 otherwise
    static T cmp_lessthan(volatile T a, volatile T b)
    {
        return (a < b)? 1 : 0;
    }

    /// Return a if c is 1, 0 if c is 0
    static T if_condition_is_true(T c, T a)
    {
        return (c)? a : 0;
    }

    /// Return a if c is 0, 0 if c is 1
    static T if_condition_is_false(T c, T a)
    {
        return (c)? 0 : a;
    }

    /// Return a if c a is negative, 0 otherwise
    static T if_negative(T c, T a)
    {
        using S = typename std::make_signed<T>::type;
        return (static_cast<S>(c) < 0)? a : 0;
    }

    /// Return a if x is more than or equal to y, 0 otherwise
    static T if_gte(T x, T y, T a)
    {
        return (x >= y)? a : 0;
    }

    /// Return a if x is less than y, 0 otherwise
    static T if_lte(T x, T y, T a)
    {
        return (x <= y)? a : 0;
    }

private:
    const_time_disabled() {}
    ~const_time_disabled() {}
};

}  // namespace phantom
