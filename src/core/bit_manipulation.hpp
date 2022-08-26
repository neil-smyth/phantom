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
#include <cstring>
#include <limits>
#include <type_traits>


namespace phantom {
namespace core {

/** 
 * @brief Bit manipulation for common types.
 * Efficient routines for commonly used arithmetic algorithms.
 */
class bit_manipulation
{
public:
    /// Log base 2
    /// @{
    static uint64_t log2(uint64_t x);
    static uint32_t log2(uint32_t x);
    static uint16_t log2(uint16_t x);
    static uint8_t log2(uint8_t x);
    /// @}

    /// Ceiling of log base 2
    /// @{
    static uint64_t log2_ceil(uint64_t x);
    static uint32_t log2_ceil(uint32_t x);
    static uint16_t log2_ceil(uint16_t x);
    static uint8_t log2_ceil(uint8_t x);
    /// @}

    /// Count leading zeros
    /// @{
    static uint64_t clz(uint64_t x);
    static uint32_t clz(uint32_t x);
    static uint16_t clz(uint16_t x);
    static uint8_t clz(uint8_t x);
    /// @}

    /// Count trailing zeros
    /// @{
    static uint64_t ctz(uint64_t x);
    static uint32_t ctz(uint32_t x);
    static uint16_t ctz(uint16_t x);
    static uint8_t ctz(uint8_t x);
    /// @}

    /// Bit reversal
    /// @{
    static uint64_t reverse(uint64_t x);
    static uint32_t reverse(uint32_t x);
    static uint16_t reverse(uint16_t x);
    static uint8_t reverse(uint8_t x);
    /// @}

    /// Rotate left by n bits
    /// @{
    static uint64_t rotl(uint64_t x, size_t n);
    static uint32_t rotl(uint32_t x, size_t n);
    static uint16_t rotl(uint16_t x, size_t n);
    static uint8_t rotl(uint8_t x, size_t n);
    /// @}

    /// Square root
    /// @{
    static uint64_t sqrt(uint64_t x);
    static uint32_t sqrt(uint32_t x);
    static uint16_t sqrt(uint16_t x);
    static uint8_t sqrt(uint8_t x);
    static double sqrt(double x);
    static float sqrt(float x);
    /// @}

    /// Inverse square root
    /// @{
    static double inv_sqrt(double x);
    static float inv_sqrt(float x);
    /// @}

    /// Check for NOT zero
    /// @{
    static uint64_t isnotzero(uint64_t x);
    static uint32_t isnotzero(uint32_t x);
    static uint16_t isnotzero(uint16_t x);
    static uint8_t isnotzero(uint8_t x);
    /// @}

    /// Modulo negation
    /// @{
    static uint64_t negate_mod(uint64_t x, uint64_t q);
    static uint32_t negate_mod(uint32_t x, uint32_t q);
    static uint16_t negate_mod(uint16_t x, uint16_t q);
    static uint8_t negate_mod(uint8_t x, uint8_t q);
    /// @}

    /// Fast division by a constant
    /// @{
    static uint32_t fast_div31(uint32_t x);
    /// @}

    /// Hamming weight
    /// @{
    static size_t hamming_weight(uint32_t x);
    /// @}

    /// Compute bit length - MSB must be clear
    static uint32_t bitlength(uint32_t x);

    /// Swap two operands using no additional variables
    template<typename T>
    static void swap(T &x, T &y)  // NOLINT
    {
        x ^= y;
        y ^= x;
        x ^= y;
    }

private:
    /// Templated method for a constant-time check for a non-zero word
    template<typename T,
             typename = typename std::enable_if<std::is_unsigned<T>::value, T>::type>
    static typename std::enable_if<std::is_unsigned<T>::value, T>::type isnotzero_template(T n)
    {
        return ((n | (~n + 1)) >> (std::numeric_limits<T>::digits-1)) & 1;
    }

    /// Templated method for constant-time negation modulo q
    template<typename T,
             typename = typename std::enable_if<std::is_unsigned<T>::value, T>::type>
    static typename std::enable_if<std::is_unsigned<T>::value, T>::type negate_mod_template(T x, T q)
    {
        return (q & -(((x | (~x + 1)) >> (std::numeric_limits<T>::digits-1)) & 1)) - x;
    }

    /// A templated method that implements log base 2
    template<typename T,
             typename = typename std::enable_if<std::is_unsigned<T>::value, T>::type>
    static typename std::enable_if<std::is_unsigned<T>::value, T>::type log2_ceil_template(T x)
    {
        T l = log2(x);
        if (x & (x-1)) {
            l++;
        }
        return l;
    }

    /// A templated method that implements square root
    template<typename T,
             typename = typename std::enable_if<std::is_unsigned<T>::value, T>::type>
    static typename std::enable_if<std::is_unsigned<T>::value, T>::type sqrt_template(T x)
    {
        T op, res, one;

        op  = x;
        res = 0;

        // "one" starts at the highest power of four <= than the argument
        one = (T)1 << (sizeof(T)*8 - 2);  // second-to-top bit set
        while (one > op) {
            one >>= 2;
        }

        while (one != 0) {
            if (op >= res + one) {
                op -= res + one;
                res += one << 1;
            }
            res >>= 1;
            one >>= 2;
        }
        return res;
    }
};

}  // namespace core
}  // namespace phantom

