/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "core/bit_manipulation.hpp"


namespace phantom {
namespace core {

uint64_t bit_manipulation::log2(uint64_t x)
{
    uint64_t r, shift;
    r =     (x > 0xFFFFFFFF) << 5; x >>= r;
    shift = (x > 0x0000FFFF) << 4; x >>= shift; r |= shift;
    shift = (x > 0x000000FF) << 3; x >>= shift; r |= shift;
    shift = (x > 0x0000000F) << 2; x >>= shift; r |= shift;
    shift = (x > 0x00000003) << 1; x >>= shift; r |= shift;
    r |= (x >> 1);
    return r;
}

uint32_t bit_manipulation::log2(uint32_t x)
{
    uint32_t r, shift;
    r =     (x > 0xFFFF) << 4; x >>= r;
    shift = (x > 0x00FF) << 3; x >>= shift; r |= shift;
    shift = (x > 0x000F) << 2; x >>= shift; r |= shift;
    shift = (x > 0x0003) << 1; x >>= shift; r |= shift;
    r |= (x >> 1);
    return r;
}

uint16_t bit_manipulation::log2(uint16_t x)
{
    uint16_t r, shift;
    r =     (x > 0xFF) << 3; x >>= r;
    shift = (x > 0x0F) << 2; x >>= shift; r |= shift;
    shift = (x > 0x03) << 1; x >>= shift; r |= shift;
    r |= (x >> 1);
    return r;
}

uint8_t bit_manipulation::log2(uint8_t x)
{
    uint8_t r, shift;
    r =     (x > 0xF) << 2; x >>= r;
    shift = (x > 0x3) << 1; x >>= shift; r |= shift;
    r |= (x >> 1);
    return r;
}


uint64_t bit_manipulation::log2_ceil(uint64_t x)
{
    return log2_ceil_template<uint64_t>(x);
}

uint32_t bit_manipulation::log2_ceil(uint32_t x)
{
    return log2_ceil_template<uint32_t>(x);
}

uint16_t bit_manipulation::log2_ceil(uint16_t x)
{
    return log2_ceil_template<uint16_t>(x);
}

uint8_t bit_manipulation::log2_ceil(uint8_t x)
{
    return log2_ceil_template<uint8_t>(x);
}


uint64_t bit_manipulation::clz(uint64_t x)
{
    if (0ULL == x) {
        return 64;
    }
#if defined (__x86_64) && defined(__GNUC__)
    uint64_t n;
    __asm__("bsrq %1,%0" : "=r" (n) : "rm" (x));
    return n ^ 63;
#else
#if defined(_M_AMD64) && defined(_MSC_VER)
    return __lzcnt64(x);
#else
    uint64_t n = 0ULL;
    if (x <= 0x00000000ffffffff) n += 32, x <<= 32;
    if (x <= 0x0000ffffffffffff) n += 16, x <<= 16;
    if (x <= 0x00ffffffffffffff) n +=  8, x <<= 8;
    if (x <= 0x0fffffffffffffff) n +=  4, x <<= 4;
    if (x <= 0x3fffffffffffffff) n +=  2, x <<= 2;
    if (x <= 0x7fffffffffffffff) n +=  1;
    return n;
#endif
#endif
}

uint32_t bit_manipulation::clz(uint32_t x)
{
    if (0 == x) {
        return 32;
    }

    uint32_t n = 0;
    if (x <= 0x0000ffff) n += 16, x <<= 16;
    if (x <= 0x00ffffff) n +=  8, x <<= 8;
    if (x <= 0x0fffffff) n +=  4, x <<= 4;
    if (x <= 0x3fffffff) n +=  2, x <<= 2;
    if (x <= 0x7fffffff) n++;
    return n;
}

uint16_t bit_manipulation::clz(uint16_t x)
{
    if (0 == x) {
        return 16;
    }

    uint16_t n = 0;
    if (x <= 0x00ff) n +=  8, x <<= 8;
    if (x <= 0x0fff) n +=  4, x <<= 4;
    if (x <= 0x3fff) n +=  2, x <<= 2;
    if (x <= 0x7fff) n++;
    return n;
}

uint8_t bit_manipulation::clz(uint8_t x)
{
    if (0 == x) {
        return 8;
    }

    uint8_t n = 0;
    if (x <= 0x0f) n +=  4, x <<= 4;
    if (x <= 0x3f) n +=  2, x <<= 2;
    if (x <= 0x7f) n++;
    return n;
}


uint64_t bit_manipulation::ctz(uint64_t x)
{
    if (0 == x) {
        return 64;
    }

#if defined (__x86_64) || defined(__GNUC__)
    uint64_t c;
    __asm__("bsfq %1,%q0" : "=r" (c) : "rm" (x));
    return c;
#else
#if defined(_M_AMD64) && defined(_MSC_VER)
    uint64_t c = 0;

    if (_BitScanForward64(&c, x)) {
        return c;
    }
    else {
        return 32;
    }
#else
    uint64_t c = 64;
    x &= -static_cast<int64_t>(x);
    if (x) c--;
    if (x & 0x00000000FFFFFFFF) c -= 32;
    if (x & 0x0000FFFF0000FFFF) c -= 16;
    if (x & 0x00FF00FF00FF00FF) c -= 8;
    if (x & 0x0F0F0F0F0F0F0F0F) c -= 4;
    if (x & 0x3333333333333333) c -= 2;
    if (x & 0x5555555555555555) c -= 1;
    return c;
#endif
#endif
}

uint32_t bit_manipulation::ctz(uint32_t x)
{
    if (0 == x) {
        return 32;
    }

    uint32_t c = 32;
    x &= -(int32_t)x;
    if (x) c--;
    if (x & 0x0000FFFF) c -= 16;
    if (x & 0x00FF00FF) c -= 8;
    if (x & 0x0F0F0F0F) c -= 4;
    if (x & 0x33333333) c -= 2;
    if (x & 0x55555555) c -= 1;
    return c;
}

uint16_t bit_manipulation::ctz(uint16_t x)
{
    if (0 == x) {
        return 16;
    }

    uint16_t c = 16;
    x &= -(int16_t)x;
    if (x) c--;
    if (x & 0x00FF) c -= 8;
    if (x & 0x0F0F) c -= 4;
    if (x & 0x3333) c -= 2;
    if (x & 0x5555) c -= 1;
    return c;
}

uint8_t bit_manipulation::ctz(uint8_t x)
{
    if (0 == x) {
        return 8;
    }

    uint8_t c = 8;
    x &= -(int8_t)x;
    if (x) c--;
    if (x & 0x0F) c -= 4;
    if (x & 0x33) c -= 2;
    if (x & 0x55) c -= 1;
    return c;
}


uint64_t bit_manipulation::reverse(uint64_t x)
{
    x = (((x & 0xaaaaaaaaaaaaaaaa) >>  1) | ((x & 0x5555555555555555) <<  1));  // Swap odd and even
    x = (((x & 0xcccccccccccccccc) >>  2) | ((x & 0x3333333333333333) <<  2));  // Swap pairs
    x = (((x & 0xf0f0f0f0f0f0f0f0) >>  4) | ((x & 0x0f0f0f0f0f0f0f0f) <<  4));  // Swap nibbles
    x = (((x & 0xff00ff00ff00ff00) >>  8) | ((x & 0x00ff00ff00ff00ff) <<  8));  // Swap bytes
    x = (((x & 0xffff0000ffff0000) >> 16) | ((x & 0x0000ffff0000ffff) << 16));  // Swap pairs of bytes
    return (x >> 32) | (x << 32);                                               // Swap 4-byte pairs
}

uint32_t bit_manipulation::reverse(uint32_t x)
{
    x = (((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1));  // Swap odd and even
    x = (((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2));  // Swap pairs
    x = (((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4));  // Swap nibbles
    x = (((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8));  // Swap bytes
    return (x >> 16) | (x << 16);                             // Swap pairs of bytes
}

uint16_t bit_manipulation::reverse(uint16_t x)
{
    x = (((x & 0xaaaa) >> 1) | ((x & 0x5555) << 1));  // Swap odd and even
    x = (((x & 0xcccc) >> 2) | ((x & 0x3333) << 2));  // Swap pairs
    x = (((x & 0xf0f0) >> 4) | ((x & 0x0f0f) << 4));  // Swap nibbles
    return (x >> 8) | (x << 8);                       // Swap bytes
}

uint8_t bit_manipulation::reverse(uint8_t x)
{
    return ((x * 0x0802LU & 0x22110LU) | (x * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16;
}


uint64_t bit_manipulation::rotl(uint64_t w, size_t n)
{
    size_t bits = n & 0x3F;
    return (w << bits) | (w >> (64 - bits));
}

uint32_t bit_manipulation::rotl(uint32_t w, size_t n)
{
    size_t bits = n & 0x1F;
    return (w << bits) | (w >> (32 - bits));
}

uint16_t bit_manipulation::rotl(uint16_t w, size_t n)
{
    size_t bits = n & 0xF;
    return (w << bits) | (w >> (16 - bits));
}

uint8_t bit_manipulation::rotl(uint8_t w, size_t n)
{
    size_t bits = n & 0x7;
    return (w << bits) | (w >> (8 - bits));
}

uint64_t bit_manipulation::sqrt(uint64_t x)
{
    return sqrt_template<uint64_t>(x);
}

uint32_t bit_manipulation::sqrt(uint32_t x)
{
    return sqrt_template<uint32_t>(x);
}

uint16_t bit_manipulation::sqrt(uint16_t x)
{
    return sqrt_template<uint16_t>(x);
}

uint8_t bit_manipulation::sqrt(uint8_t x)
{
    return sqrt_template<uint8_t>(x);
}

double bit_manipulation::sqrt(const double x)
{
   static union{int64_t i; double d;} u;
   u.d = x;
   u.i = 0x5fe6eb50c7b537a9 - (u.i >> 1);
   return (int64_t(3) - x * u.d * u.d) * x * u.d * 0.5f;
}

float bit_manipulation::sqrt(const float x)
{
   static union{int32_t i; float f;} u;
   u.f = x;
   u.i = 0x5f375a86 - (u.i >> 1);
   return (int32_t(3) - x * u.f * u.f) * x * u.f * 0.5f;
}

double bit_manipulation::inv_sqrt(double x)
{
    union {
        double d;
        uint64_t i;
    } conv;
    conv.d = x;
    double x2 = conv.d * 0.5;
    // The magic number for doubles is from https://cs.uwaterloo.ca/~m32rober/rsqrt.pdf
    conv.i = 0x5fe6eb50c7b537a9 - (conv.i >> 1);
    conv.d = conv.d * (1.5 - (x2 * conv.d * conv.d));   // 1st iteration
    // conv.d = conv.d * (1.5 - (x2 * conv.d * conv.d));   // 2nd iteration, accuracy unnecessary
    return conv.d;
}

float bit_manipulation::inv_sqrt(float x)
{
    union {
        float f;
        uint32_t i;
    } conv;
    conv.f = x;
    float x2 = conv.f * 0.5;
    // The magic number for doubles is from https://cs.uwaterloo.ca/~m32rober/rsqrt.pdf
    conv.i = 0x5f3759df - (conv.i >> 1);
    conv.f = conv.f * (1.5 - (x2 * conv.f * conv.f));   // 1st iteration
    // conv.f = conv.f * (1.5 - (x2 * conv.f * conv.f));   // 2nd iteration, accuracy unnecessary
    return conv.f;
}

uint64_t bit_manipulation::isnotzero(uint64_t x)
{
    return isnotzero_template<uint64_t>(x);
}

uint32_t bit_manipulation::isnotzero(uint32_t x)
{
    return isnotzero_template<uint32_t>(x);
}

uint16_t bit_manipulation::isnotzero(uint16_t x)
{
    return isnotzero_template<uint16_t>(x);
}

uint8_t bit_manipulation::isnotzero(uint8_t x)
{
    return isnotzero_template<uint8_t>(x);
}

uint64_t bit_manipulation::negate_mod(uint64_t x, uint64_t q)
{
    return negate_mod_template<uint64_t>(x, q);
}

uint32_t bit_manipulation::negate_mod(uint32_t x, uint32_t q)
{
    return negate_mod_template<uint32_t>(x, q);
}

uint16_t bit_manipulation::negate_mod(uint16_t x, uint16_t q)
{
    return negate_mod_template<uint16_t>(x, q);
}

uint8_t bit_manipulation::negate_mod(uint8_t x, uint8_t q)
{
    return negate_mod_template<uint8_t>(x, q);
}

uint32_t bit_manipulation::fast_div31(uint32_t x)
{
    const uint32_t d = 0x8421084;
    return ((d * static_cast<uint64_t>(x)) + 30) >> 32;
}

size_t bit_manipulation::hamming_weight(uint32_t x)
{
     x = x - ((x >> 1) & 0x55555555);
     x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
     return (((x + (x >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
}

uint32_t bit_manipulation::bitlength(uint32_t x)
{
    // This algorithm is inspired from an algorithm devised by
    // Robert Harley and explained in Hacker's Delight, 2nd edition
    // (section 5.3).
    //
    // We first propagate the highest non-zero bit to the right, so
    // that the value becomes equal to 2^bl-1; at that point, we thus
    // have 32 possible values for x (0, and powers of 2 from 2^0 to
    // 2^30). Then, we multiply the value with a specific constant
    // that makes it so that the top 5 bits of the 32-bit result will
    // contain 32 different values for the 32 possible values of x
    // at this point. These top 5 bits thus contain a permutation of
    // the 0..31 result we need; a table look-up implements the
    // reverse permutation.
    static const unsigned vv[] = {
         0, 31,  4,  5,  6, 10,  7, 15,
        11, 20,  8, 18, 16, 25, 12, 27,
        21, 30,  3,  9, 14, 19, 17, 24,
        26, 29,  2, 13, 23, 28,  1, 22
    };

    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    return vv[(x * 0xF04653AE) >> 27];
}

}  // namespace core
}  // namespace phantom
