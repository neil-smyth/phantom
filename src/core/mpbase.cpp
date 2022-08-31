/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "core/mpbase.hpp"

#include <algorithm>
#include <functional>
#include <limits>


namespace phantom {
namespace core {

template<typename T>
void mpbase<T>::zero(T *inout, size_t n)
{
    std::fill(inout, inout + n, 0);
}

template<typename T>
void mpbase<T>::ones_complement(T* out, const T *in, size_t n)
{
    std::transform(in, in + n, out, std::bit_not<T>());
}

template<typename T>
T mpbase<T>::negate(T* out, const T *in, size_t n)
{
    // Copy in to out until a non-zero in value is found
    while (0 == *in) {
        *out = 0;
        if (!--n) {
            // All of in has been consumed so return 0
            return 0;
        }
        in++;
        out++;
    }

    // Negate the 1st non-zero in value and copy to out, then calculate the
    // one's complement of the remaing in values and copy to out
    *out = - *in;
    ones_complement(++out, ++in, --n);

    // Return 1 to indicate the negation is non-zero
    return 1;
}

template<typename T>
void mpbase<T>::copy(T *out, const T *in, size_t n)  // NOLINT
{
    // As a low level function we assume that in != out and any checks are performed at a higher level
    std::copy(in, in + n, out);
}

template<typename T>
void mpbase<T>::fill(T* dst, size_t n, T value)
{
    std::fill(dst, dst + n, value);
}

template<typename T>
size_t mpbase<T>::normalized_size(const T *in, size_t n)
{
    while (n > 0 && 0 == in[n - 1]) {
        n--;
    }
    return n;
}

template<typename T>
T mpbase<T>::lshift(T *out, const T *in, size_t n, size_t count)
{
    size_t bits = std::numeric_limits<T>::digits - count;

    assert(count >= 0 && count < std::numeric_limits<T>::digits);

    in  += n;
    out += n;

    T l  = *--in;
    T h  = l << count;
    T cc = l >> bits;
    while (--n) {
        l      = *--in;
        *--out = h | (l >> bits);
        h      = l << count;
    }
    *--out = h;

    return cc;
}

template<typename T>
T mpbase<T>::lshiftc(T *out, const T *in, size_t n, size_t count)
{
    size_t bits = std::numeric_limits<T>::digits - count;

    assert(count >= 0 && count < std::numeric_limits<T>::digits);

    in  += n;
    out += n;

    T l  = *--in;
    T h  = l << count;
    T cc = l >> bits;
    while (--n) {
        l      = *--in;
        *--out = ~(h | (l >> bits));
        h      = l << count;
    }
    *--out = ~h;

    return cc;
}

template<typename T>
T mpbase<T>::rshift(T *out, const T *in, size_t n, size_t count)
{
    T h, l, cc;
    size_t bits = std::numeric_limits<T>::digits - count;

    assert(count > 0 && count < std::numeric_limits<T>::digits);

    h  = *in++;
    cc = h << bits;
    l  = h >> count;
    while (--n) {
        h      = *in++;
        *out++ = l | (h << bits);
        l      = h >> count;
    }
    *out = l;

    return cc;
}

/**
 * Right shift a data array to remove any trailing zeros
 * @param inout Data to be modified
 * @param n length of the data array
 * @return The number of bits the array is right shifted
 */
template<typename T>
size_t mpbase<T>::make_odd(T* inout, size_t n)
{
    size_t bits  = ctz(inout, n);
    size_t limbs = bits >> bits_log2<T>::value();
    size_t shift = bits & ((1 << bits_log2<T>::value()) - 1);

    if (shift != 0) {
        rshift(inout, inout + limbs, n - limbs, shift);
        n -= limbs;
        n -= ((inout)[(n) - 1] == 0);
    }
    else if (limbs != 0) {
        copy(inout, inout + limbs, n - limbs);  // NOLINT
        n -= limbs;
    }

    return bits;
}

/**
 * Count trailing zeros in an array
 * @param in Data array
 * @param n Length of the data array
 * @return Number of trailing zeros
 */
template<typename T>
size_t mpbase<T>::ctz(const T* in, size_t n)
{
    assert(n >= 0);

    size_t i;
    for (i=0; i < n; i++) {
        if (in[i] != 0) {
            break;
        }
    }

    if (i == n) {
        return 0;
    }

    size_t cnt = bit_manipulation::ctz(in[i]);

    return cnt + i * std::numeric_limits<T>::digits;
}

template<typename T>
T mpbase<T>::getbits(const T *in, uint32_t bi, uint32_t nbits)
{
    if (bi < nbits) {
        return in[0] & ((static_cast<T>(1) << bi) - 1);
    }
    else {
        bi -= nbits;                                                // bit index of low bit to extract
        uint32_t i = bi >> bits_log2<T>::value();                   // word index of low bit to extract
        bi &= ((1 << bits_log2<T>::value()) - 1);                   // bit index in low word
        T r = in[i] >> bi;                                          // extract (low) bits
        uint32_t nbits_in_r = std::numeric_limits<T>::digits - bi;  // number of bits now in r
        if (nbits_in_r < nbits) {                                   // did we get enough bits?
            r += in[i + 1] << nbits_in_r;                           // prepend bits from higher word
        }
        return r & ((static_cast<T>(1) << nbits) - 1);
    }
}

/**
 * Determine if array is all zero's
 * @param in Input data array
 * @param n Length of the data array
 * @return true if in is zero, false otherwise
 */
template<typename T>
bool mpbase<T>::is_zero(const T *in, size_t n)
{
    while (n--) {
        if (in[n]) {
            return false;
        }
    }
    return true;
}

/**
 * Compare two arrays of the same length (length must be normalized)
 * @param in1 Input data array 1
 * @param in2 Input data array 2
 * @param n Length of the data arrays
 * @return 1 if in1 is larger, 0 if equal and -1 is smaller
 */
template<typename T>
int32_t mpbase<T>::cmp(const T *in1, const T *in2, size_t n)
{
    while (n--) {
        if (in1[n] != in2[n]) {
            return (in1[n] > in2[n])? 1 : -1;
        }
    }
    return 0;
}

/**
 * Compare two arrays of different length (length must be normalized)
 * @param in1 Input data array 1
 * @param n1 Length of the data array 1
 * @param in2 Input data array 2
 * @param n2 Length of the data array 2
 * @return 1 if in1 is larger, 0 if equal and -1 if smaller
 */
template<typename T>
int32_t mpbase<T>::cmp_n(const T *in1, size_t n1, const T *in2, size_t n2)
{
    if (n1 < n2) {
        return -1;
    }
    else if (n1 > n2) {
        return 1;
    }
    else {
        return cmp(in1, in2, n1);
    }
}

/**
 * @brief Add a single-word value to an array
 * @param p Array pointer
 * @param incr Word to add
 */
template<typename T>
void mpbase<T>::incr_u(const T* p, T incr)
{
    T* ptr = const_cast<T*>(p);
    T v = *ptr + incr;                // Add 'incr'
    *ptr = v;                         // Set the array value leats significant word
    if (v < incr) {                   // Check if we need to propagate a carry bit
        while (++(*(++ptr)) == 0) {}  // Carry propagation
    }
}

/**
 * @brief Subtract a single-word value from an array
 * @param p Array pointer
 * @param decr Word to subtract
 */
template<typename T>
void mpbase<T>::decr_u(const T* p, T decr)
{
    T* ptr = const_cast<T*>(p);
    T v = *ptr;
    *ptr = v - decr;                  // Subtract 'decr'
    if (v < decr) {                   // Check if we need to propagate a carry bit
        while (++(*(++ptr)) == 0) {}  // Carry propagation
    }
}


// Forward declaration of common type declarations
/// @{
template class mpbase<uint8_t>;
template class mpbase<uint16_t>;
template class mpbase<uint32_t>;
template class mpbase<uint64_t>;
/// @}

}  // namespace core
}  // namespace phantom
