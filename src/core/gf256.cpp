/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "core/gf256.hpp"


namespace phantom {
namespace core {


// r = r + x
void gf256_impl::add(uint32_t r[8], const uint32_t x[8])
{
    r[0] ^= x[0];
    r[1] ^= x[1];
    r[2] ^= x[2];
    r[3] ^= x[3];
    r[4] ^= x[4];
    r[5] ^= x[5];
    r[6] ^= x[6];
    r[7] ^= x[7];
}

// r = a * b (mod x^8 + x^4 + x^3 + x + 1)
void gf256_impl::mul(uint32_t r[8], const uint32_t a[8], const uint32_t b[8])
{
    uint32_t a2[8];
    a2[0] = a[0];
    a2[1] = a[1];
    a2[2] = a[2];
    a2[3] = a[3];
    a2[4] = a[4];
    a2[5] = a[5];
    a2[6] = a[6];
    a2[7] = a[7];

    r[0]   = a2[0] & b[0];
    r[1]   = a2[1] & b[0];
    r[2]   = a2[2] & b[0];
    r[3]   = a2[3] & b[0];
    r[4]   = a2[4] & b[0];
    r[5]   = a2[5] & b[0];
    r[6]   = a2[6] & b[0];
    r[7]   = a2[7] & b[0];
    a2[0] ^= a2[7];
    a2[2] ^= a2[7];
    a2[3] ^= a2[7];

    r[0]  ^= a2[7] & b[1];
    r[1]  ^= a2[0] & b[1];
    r[2]  ^= a2[1] & b[1];
    r[3]  ^= a2[2] & b[1];
    r[4]  ^= a2[3] & b[1];
    r[5]  ^= a2[4] & b[1];
    r[6]  ^= a2[5] & b[1];
    r[7]  ^= a2[6] & b[1];
    a2[7] ^= a2[6];
    a2[1] ^= a2[6];
    a2[2] ^= a2[6];

    r[0]  ^= a2[6] & b[2];
    r[1]  ^= a2[7] & b[2];
    r[2]  ^= a2[0] & b[2];
    r[3]  ^= a2[1] & b[2];
    r[4]  ^= a2[2] & b[2];
    r[5]  ^= a2[3] & b[2];
    r[6]  ^= a2[4] & b[2];
    r[7]  ^= a2[5] & b[2];
    a2[6] ^= a2[5];
    a2[0] ^= a2[5];
    a2[1] ^= a2[5];

    r[0]  ^= a2[5] & b[3];
    r[1]  ^= a2[6] & b[3];
    r[2]  ^= a2[7] & b[3];
    r[3]  ^= a2[0] & b[3];
    r[4]  ^= a2[1] & b[3];
    r[5]  ^= a2[2] & b[3];
    r[6]  ^= a2[3] & b[3];
    r[7]  ^= a2[4] & b[3];
    a2[5] ^= a2[4];
    a2[7] ^= a2[4];
    a2[0] ^= a2[4];

    r[0]  ^= a2[4] & b[4];
    r[1]  ^= a2[5] & b[4];
    r[2]  ^= a2[6] & b[4];
    r[3]  ^= a2[7] & b[4];
    r[4]  ^= a2[0] & b[4];
    r[5]  ^= a2[1] & b[4];
    r[6]  ^= a2[2] & b[4];
    r[7]  ^= a2[3] & b[4];
    a2[4] ^= a2[3];
    a2[6] ^= a2[3];
    a2[7] ^= a2[3];

    r[0]  ^= a2[3] & b[5];
    r[1]  ^= a2[4] & b[5];
    r[2]  ^= a2[5] & b[5];
    r[3]  ^= a2[6] & b[5];
    r[4]  ^= a2[7] & b[5];
    r[5]  ^= a2[0] & b[5];
    r[6]  ^= a2[1] & b[5];
    r[7]  ^= a2[2] & b[5];
    a2[3] ^= a2[2];
    a2[5] ^= a2[2];
    a2[6] ^= a2[2];

    r[0]  ^= a2[2] & b[6];
    r[1]  ^= a2[3] & b[6];
    r[2]  ^= a2[4] & b[6];
    r[3]  ^= a2[5] & b[6];
    r[4]  ^= a2[6] & b[6];
    r[5]  ^= a2[7] & b[6];
    r[6]  ^= a2[0] & b[6];
    r[7]  ^= a2[1] & b[6];
    a2[2] ^= a2[1];
    a2[4] ^= a2[1];
    a2[5] ^= a2[1];

    r[0]  ^= a2[1] & b[7];
    r[1]  ^= a2[2] & b[7];
    r[2]  ^= a2[3] & b[7];
    r[3]  ^= a2[4] & b[7];
    r[4]  ^= a2[5] & b[7];
    r[5]  ^= a2[6] & b[7];
    r[6]  ^= a2[7] & b[7];
    r[7]  ^= a2[0] & b[7];
}

// r = a ^ 2 (mod x^8 + x^4 + x^3 + x + 1)
void gf256_impl::sqr(uint32_t r[8], const uint32_t x[8])
{
    uint32_t r8, r10, r12, r14;

    r14   = x[7];
    r12   = x[6];
    r10   = x[5];
    r8    = x[4];
    r[6]  = x[3];
    r[4]  = x[2];
    r[2]  = x[1];
    r[0]  = x[0];

    r[7]  = r14;  // r[7] was 0
    r[6] ^= r14;
    r10  ^= r14;
    // r13 is always 0
    r[4] ^= r12;
    r[5]  = r12;  // r[5] was 0
    r[7] ^= r12;
    r8   ^= r12;
    // r11 is always 0
    r[2] ^= r10;
    r[3]  = r10;  // r[3] was 0
    r[5] ^= r10;
    r[6] ^= r10;
    r[1]  = r14;  // r[1] was 0
    r[2] ^= r14;  // Substitute r9 by r14 because they will always be equal
    r[4] ^= r14;
    r[5] ^= r14;
    r[0] ^= r8;
    r[1] ^= r8;
    r[3] ^= r8;
    r[4] ^= r8;
}

// r = 1 / x (mod x^8 + x^4 + x^3 + x + 1)
void gf256_impl::inv(uint32_t r[8], const uint32_t x[8])
{
    uint32_t y[8], z[8];

    sqr(y, x);     // y = x^2
    sqr(y, y);     // y = x^4
    sqr(r, y);     // r = x^8
    mul(z, r, x);  // z = x^9
    sqr(r, r);     // r = x^16
    mul(r, r, z);  // r = x^25
    sqr(r, r);     // r = x^50
    sqr(z, r);     // z = x^100
    sqr(z, z);     // z = x^200
    mul(r, r, z);  // r = x^250
    mul(r, r, y);  // r = x^254
}



// Forward declaration of common sizes
template class gf256<uint32_t>;

}  // namespace core
}  // namespace phantom
