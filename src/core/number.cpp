/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "core/number.hpp"
#include <cassert>


namespace phantom {
namespace core {


// Forward declaration of common sizes
template class number<uint8_t>;
template class number<uint16_t>;
template class number<uint32_t>;
template class number<uint64_t>;


// Compute a double-word product from single word multiplicands (64-bit)
void number_impl::umul_internal(uint64_t * _RESTRICT_ hi, uint64_t * _RESTRICT_ lo, uint64_t u, uint64_t v)
{
#if defined (__x86_64) && defined(__GNUG__)
    // x86-64 assembler for 64-bit multiplication
    __asm__("mulq %3"
                : "=a" (*lo), "=d" (*hi)
                : "%a" (u), "rm" (v)
                : "cc");
#else
#if defined(_M_AMD64) && defined(_MSC_VER)
    // x86-64 MSVC intrinsic for 64-bit multiplication
    *lo = _umul128(u, v, hi);
#else
#if defined(__SIZEOF_INT128__)
    // The compiler has defined 128-bit integer types so they are used
    using uint128_t = unsigned __int128;
    uint128_t p = static_cast<uint128_t>(u) * static_cast<uint128_t>(v);
    *hi = (uint64_t)(p >> 64);
    *lo = (uint64_t)(p & 0xffffffffffffffff);
#else
    // Perform 64-bit multiplication using 32-bit numbers stored in uint64_t's
    uint64_t ulo = u & 0xffffffff;
    uint64_t uhi = u >> 32;
    uint64_t vlo = v & 0xffffffff;
    uint64_t vhi = v >> 32;
#if defined(__x86_64) || defined(_IA64) || defined(__aarch64__) || defined(_M_AMD64)
    // On a 64-bit platform the low and high product is computed directly using uint64_t
    uint64_t t0  = ulo * vlo;
    uint64_t t1  = uhi * vlo + (t0 >> 32);
    uint64_t t2  = vhi * ulo + (t1 & 0xffffffff);
    *lo = ((t2 & 0xffffffff) << 32) + (t0 & 0xffffffff);
    *hi = uhi * vhi + (t2 >> 32) + (t1 >> 32);
#else
    // On a 32-bit or lower platform the low and high product are computed using uint32_t
    uint32_t t0_lo, t0_hi, t1_lo, t1_hi, t2_lo, t2_hi, hi_lo, hi_hi;
    umul32(&t0_hi, &t0_lo, ulo, vlo);
    umul32(&t1_hi, &t1_lo, uhi, vlo);
    umul32(&t2_hi, &t2_lo, ulo, vhi);
    umul32(&hi_hi, &hi_lo, uhi, vhi);
    uint64_t t1 = (static_cast<uint64_t>(t1_hi) << 32) + t1_lo + t0_hi;
    uint64_t t2 = (static_cast<uint64_t>(t2_hi) << 32) + t2_lo + (t1 & 0xffffffff);
    *lo  = ((static_cast<uint64_t>(t2) & 0xffffffff) << 32) + t0_lo;
    *hi  = (static_cast<uint64_t>(hi_hi) << 32) + hi_lo + (t2 >> 32) + (t1 >> 32);
#endif
#endif
#endif
#endif
}

// Compute a double-word product from single word multiplicands (32-bit)
void number_impl::umul_internal(uint32_t * _RESTRICT_ hi, uint32_t * _RESTRICT_ lo, uint32_t u, uint32_t v)
{
#if defined(__x86_64) || defined(_IA64) || defined(__aarch64__) || defined(_WIN64)
    uint64_t p = static_cast<uint64_t>(u) * static_cast<uint64_t>(v);
    *hi = p >> 32;
    *lo = p & 0xffffffff;
#else
    umul32(hi, lo, u, v);
#endif
}

// Compute a double-word product from single word multiplicands (16-bit)
void number_impl::umul_internal(uint16_t * _RESTRICT_ hi, uint16_t * _RESTRICT_ lo, uint16_t u, uint16_t v)
{
    uint32_t t = u * v;
    *hi = t >> 16;
    *lo = t & 0xffff;
}

// Compute a double-word product from single word multiplicands (8-bit)
void number_impl::umul_internal(uint8_t * _RESTRICT_ hi, uint8_t * _RESTRICT_ lo, uint8_t u, uint8_t v)
{
    uint16_t t = u * v;
    *hi = t >> 8;
    *lo = t & 0xff;
}

#if !defined(__x86_64) && !defined(_IA64) && !defined(__aarch64__) && !defined(_WIN64)
/// A helper method for multiplication of 32-bit multiplicands on a non-64-bit platform
void number_impl::umul32(uint32_t * _RESTRICT_ hi, uint32_t * _RESTRICT_ lo, uint32_t u, uint32_t v)
{
    uint32_t ulo = (u & 0xffff);
    uint32_t uhi = (u >> 16);
    uint32_t vlo = (v & 0xffff);
    uint32_t vhi = (v >> 16);
    uint32_t t0 = ulo * vlo;
    uint32_t t1 = uhi * vlo + (t0 >> 16);
    uint32_t t2 = vhi * ulo + (t1 & 0xffff);
    *lo  = ((t2 & 0xffff) << 16) + (t0 & 0xffff);
    *hi  = uhi * vhi + (t2 >> 16) + (t1 >> 16);
}
#endif

// Compute a quotient and remainder from a 2-word numerator and single-word divisor (8-bit)
void number_impl::udiv_qrnnd_internal(uint8_t * const q, uint8_t * const r, uint8_t n1, uint8_t n0, uint8_t d)
{
    uint16_t n = (static_cast<uint16_t>(n1) << 8) | static_cast<uint16_t>(n0);
    *q = n / d;
    *r = n % d;
}

// Compute a quotient and remainder from a 2-word numerator and single-word divisor (16-bit)
void number_impl::udiv_qrnnd_internal(uint16_t * const q, uint16_t * const r, uint16_t n1, uint16_t n0, uint16_t d)
{
    uint32_t n = (static_cast<uint32_t>(n1) << 16) | static_cast<uint32_t>(n0);
    *q = n / d;
    *r = n % d;
}

// Compute a quotient and remainder from a 2-word numerator and single-word divisor (32-bit)
void number_impl::udiv_qrnnd_internal(uint32_t * const q, uint32_t * const r, uint32_t n1, uint32_t n0, uint32_t d)
{
    uint64_t n = (static_cast<uint64_t>(n1) << 32ULL) | static_cast<uint64_t>(n0);
    *q = n / d;
    *r = n % d;
}

// A template function for udiv_qrnnd
template <typename T>
void udiv_qrnnd_generic(T * const q, T * const r, T n1, T n0, T d)
{
    T d1, d0, q1, q0, r1, r0, m;
    bool norm = false;

    d1 = d >> (std::numeric_limits<T>::digits/2);

    if (0 == d1) {
        n1 = (n1 << (std::numeric_limits<T>::digits/2)) | (n0 >> (std::numeric_limits<T>::digits/2));
        n0 = n0 << (std::numeric_limits<T>::digits/2);
        d1 = d;
        d <<= std::numeric_limits<T>::digits/2;
        norm = true;
    }

    d0 = d & ((static_cast<T>(1) << (std::numeric_limits<T>::digits/2)) - 1);

    r1 = n1 % d1;
    q1 = n1 / d1;
    m  = q1 * d0;
    r1 = (r1 << (std::numeric_limits<T>::digits/2)) |
         (n0 >> (std::numeric_limits<T>::digits/2));
    if (r1 < m) {
        q1--;
        r1 += d;
        if (r1 >= d) {  // i.e. we didn't get carry when adding to r1
            if (r1 < m) {
                q1--;
                r1 += d;
            }
        }
    }
    r1 -= m;

    r0 = r1 % d1;
    q0 = r1 / d1;
    m  = q0 * d0;
    r0 = (r0 << (std::numeric_limits<T>::digits/2)) |
         (n0 & ((static_cast<T>(1) << (std::numeric_limits<T>::digits/2)) - 1));
    if (r0 < m) {
        q0--;
        r0 += d;
        if (r0 >= d) {
            if (r0 < m) {
                q0--;
                r0 += d;
            }
        }
    }
    r0 -= m;

    if (norm) {
        r0 >>= std::numeric_limits<T>::digits/2;
    }

    *q = (q1 << (std::numeric_limits<T>::digits/2)) | q0;
    *r = r0;
}

// Compute a quotient and remainder from a 2-word numerator and single-word divisor (64-bit)
void number_impl::udiv_qrnnd_internal(uint64_t * const q, uint64_t * const r, uint64_t n1, uint64_t n0, uint64_t d)
{
#if defined(__SIZEOF_INT128__)
    // The compiler has defined 128-bit integer types so they are used
    using uint128_t = unsigned __int128;

    uint128_t n = (static_cast<uint128_t>(n1) << 64ULL) | static_cast<uint128_t>(n0);
    *q = n / d;
    *r = n % d;
#else
    assert(0 != d);
    assert(n1 < d);
    udiv_qrnnd_generic<uint64_t>(q, r, n1, n0, d);
#endif
}

// Compute -1/q mod 2^7 (works for all odd integers represented by 8 bits)
uint8_t number_impl::uninv_internal(uint8_t q)
{
    uint8_t y = 2 - q;
    y *= 2 - q * y;
    y *= 2 - q * y;
    return static_cast<uint8_t>(0x7f & -y);
}

// Compute -1/q mod 2^15 (works for all odd integers represented by 16 bits)
uint16_t number_impl::uninv_internal(uint16_t q)
{
    uint16_t y = 2 - q;
    y *= 2 - q * y;
    y *= 2 - q * y;
    y *= 2 - q * y;
    return static_cast<uint16_t>(0x7fff & -y);
}

// Compute -1/q mod 2^31 (works for all odd integers represented by 32 bits)
uint32_t number_impl::uninv_internal(uint32_t q)
{
    uint32_t y = 2 - q;
    y *= 2 - q * y;
    y *= 2 - q * y;
    y *= 2 - q * y;
    y *= 2 - q * y;
    return static_cast<uint32_t>(0x7fffffff & -y);
}

// Compute -1/q mod 2^63 (works for all odd integers represented by 64 bits)
uint64_t number_impl::uninv_internal(uint64_t q)
{
    uint64_t y = 2 - q;
    y *= 2 - q * y;
    y *= 2 - q * y;
    y *= 2 - q * y;
    y *= 2 - q * y;
    y *= 2 - q * y;
    return static_cast<uint64_t>(0x7fffffffffffffff & -y);
}

}  // namespace core
}  // namespace phantom
