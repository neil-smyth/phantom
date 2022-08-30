/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <limits>
#include <type_traits>
#include "core/bit_manipulation.hpp"
#include "core/const_time.hpp"
#include "core/template_helpers.hpp"
#include "./phantom_memory.hpp"


namespace phantom {
namespace core {

/** 
 * @brief Low-level math routines
 * 
 * Concrete implementation of low-level math functions
 */
class number_impl
{
public:
    static void umul_internal(uint64_t * _RESTRICT_ hi, uint64_t * _RESTRICT_ lo, uint64_t u, uint64_t v);

    static void umul_internal(uint32_t * _RESTRICT_ hi, uint32_t * _RESTRICT_ lo, uint32_t u, uint32_t v);

    static void umul_internal(uint16_t * _RESTRICT_ hi, uint16_t * _RESTRICT_ lo, uint16_t u, uint16_t v);

    static void umul_internal(uint8_t * _RESTRICT_ hi, uint8_t * _RESTRICT_ lo, uint8_t u, uint8_t v);

#if !defined(__x86_64) && !defined(_IA64) && !defined(__aarch64__) && !defined(_WIN64)
    static void umul32(uint32_t * _RESTRICT_ hi, uint32_t * _RESTRICT_ lo, uint32_t u, uint32_t v);
#endif

    static void udiv_qrnnd_internal(uint8_t * const q, uint8_t * const r, uint8_t n1, uint8_t n0, uint8_t d);

    static void udiv_qrnnd_internal(uint16_t * const q, uint16_t * const r, uint16_t n1, uint16_t n0, uint16_t d);

    static void udiv_qrnnd_internal(uint32_t * const q, uint32_t * const r, uint32_t n1, uint32_t n0, uint32_t d);

    static void udiv_qrnnd_internal(uint64_t * const q, uint64_t * const r, uint64_t n1, uint64_t n0, uint64_t d);

    // Compute -1/q mod 2^7 (works for all odd integers represented by 8 bits)
    static uint8_t uninv_internal(uint8_t q);

    // Compute -1/q mod 2^15 (works for all odd integers represented by 16 bits)
    static uint16_t uninv_internal(uint16_t q);

    // Compute -1/q mod 2^31 (works for all odd integers represented by 32 bits)
    static uint32_t uninv_internal(uint32_t q);

    // Compute -1/q mod 2^63 (works for all odd integers represented by 64 bits)
    static uint64_t uninv_internal(uint64_t q);
};


/** 
 * @brief Low-level math interface class.
 * 
 * Templated interface for low-level number arithmetic.
 */
template<typename U>
class number
{
    static_assert(std::is_same<U, uint8_t>::value ||
                  std::is_same<U, uint16_t>::value ||
                  std::is_same<U, uint32_t>::value ||
                  std::is_same<U, uint64_t>::value,
                  "number instantiated with unsupported type");

    using V = half_size_t<U>;
    using D = next_size_t<U>;
    using S = signed_type_t<U>;

public:
    /// Return the minimum of x and y
    static U min(U x, U y)
    {
        return const_time<U>::cmp_lessthan(x, y) * x + const_time<U>::if_gte(x, y, y);
    }

    /// Return the maximum of x and y
    static U max(U x, U y)
    {
        return const_time<U>::if_gte(x, y, x) + const_time<U>::cmp_lessthan(x, y) * y;
    }

    /// Add two double-word numbers to form a double-word result
    static void uadd(U * const s1, U * const s0, U a1, U a0, U b1, U b0)
    {
        // The most significant word must account for the carry bit from the LSW addition
        *s0 = a0 + b0;
        *s1 = a1 + b1 + const_time<U>::cmp_lessthan(*s0, a0);
    }

    /// Subtract two double-word numbers to form a double-word result
    static void usub(U * const s1, U * const s0, U a1, U a0, U b1, U b0)
    {
        // The most significant word must account for the carry bit from the LSW subtraction
        *s1 = a1 - b1 - const_time<U>::cmp_lessthan(a0, b0);
        *s0 = a0 - b0;
    }

    // Division of a single word numerator by a single word denominator
    static U udiv(U n, U d)
    {
        return n / d;
    }

    // Division with remainder of a single word numerator by a single word denominator
    static void udiv_qrnd(U* q, U *r, U n, U d)
    {
        *q = udiv(n, d);
        *r = urem(n, d);
    }

    // Division with remainder of a 2-word numerator by a single word denominator
    static void udiv_qrnnd(U* const q, U* const r, U n1, U n0, U d)
    {
        number_impl::udiv_qrnnd_internal(q, r, n1, n0, d);
    }

    // Division with remainder of a 2-word numerator by a 2-word denominator
    static void udiv_qrrnndd(U* q, U* rh, U* rl, U nh, U nl, U dh, U dl)
    {
        *q = 0;

        if (static_cast<S>(nh) < 0) {
            int cnt;
            for (cnt = 1; static_cast<S>(dh) >= 0; cnt++) {
                dh = (dh << 1) | (dl >> (std::numeric_limits<U>::digits - 1));
                dl = dl << 1;
            }

            while (cnt) {
                *q <<= 1;
                if (nh > dh || (nh == dh && nl >= dl)) {
                    usub(&nh, &nl, nh, nl, dh, dl);
                    *q |= 1;
                }
                dl = (dh << (std::numeric_limits<U>::digits - 1)) | (dl >> 1);
                dh = dh >> 1;
                cnt--;
            }
        }
        else {
            int cnt;
            for (cnt = 0; nh > dh || (nh == dh && nl >= dl); cnt++) {
                dh = (dh << 1) | (dl >> (std::numeric_limits<U>::digits - 1));
                dl = dl << 1;
            }

            while (cnt) {
                dl = (dh << (std::numeric_limits<U>::digits - 1)) | (dl >> 1);
                dh = dh >> 1;
                *q <<= 1;
                if (nh > dh || (nh == dh && nl >= dl)) {
                    usub(&nh, &nl, nh, nl, dh, dl);
                    *q |= 1;
                }
                cnt--;
            }
        }

        *rl = nl;
        *rh = nh;
    }

    // Division with remainder of a 2-word numerator by a single word denominator with a pre-inverted inverse
    static void udiv_qrnnd_preinv(U* const q, U* const r, U n1, U n0, U d, U d_inv)
    {
        U h, l, mask;
        umul(&h, &l, n1, d_inv);
        uadd(&h, &l, h, l, n1 + 1, n0);
        *r   = n0 - h * d;
        mask = -static_cast<U>(*r > l);
        h   += mask;
        *r  += mask & d;
        if (*r >= d) {
            *r -= d;
            h++;
        }
        *q   = h;
    }

    // Division with remainder of a 3-word numerator by a 2-word denominator with a pre-inverted inverse
    static void udiv_qrnnndd_preinv(U* const q, U* const r1, U* const r0,
        U n2, U n1, U n0, U d1, U d0, U d_inv)
    {
        U q0, t1, t0, mask;
        umul(q, &q0, n2, d_inv);
        uadd(q, &q0, *q, q0, n2, n1);

        *r1 = n1 - d1 * (*q);
        usub(r1, r0, *r1, n0, d1, d0);
        umul(&t1, &t0, d0, *q);
        usub(r1, r0, *r1, *r0, t1, t0);
        *q = *q + 1;

        mask = -static_cast<U>(*r1 >= q0);
        *q += mask;
        uadd(r1, r0, *r1, *r0, mask & d1, mask & d0);
        if (*r1 >= d1) {
            if (*r1 > d1 || *r0 >= d0) {
                *q = *q + 1;
                usub(r1, r0, *r1, *r0, d1, d0);
            }
        }
    }

    // Remainder of a single word numerator by a single word denominator
    static U urem(U n, U d)
    {
        return n % d;
    }

    // Remainder of a 2-word numerator by a single word denominator
    static U umod_nnd(U n1, U n0, U d)
    {
        U t;
        size_t i;
        for (i=std::numeric_limits<U>::digits; i--;) {
            t  = n1 >> (std::numeric_limits<U>::digits - 1);
            n1 = (n1 << 1) | (n0 >> (std::numeric_limits<U>::digits - 1));
            n0 <<= 1;

            // If (n1 | t) >= d the numerator has grown too large and must be reduced
            U reduce = (n1 | t) >= d;
            n1 -= reduce * d;
            n0 += reduce;
        }
        return n1;
    }

    // Multiplication of two single word multiplicands to form upper and lower product words
    static void umul(U *hi, U *lo, U u, U v)
    {
        number_impl::umul_internal(hi, lo, u, v);
    }

    // Multiplication of two 2-word multiplicands to form upper and lower product words
    static void umul2_lo(U *hi, U *lo, U uh, U ul, U vh, U vl)
    {
        umul(hi, lo, ul, vl);
        *hi = *hi + ul * vh + uh * vl;
    }

    /// Euclidean algorithm.
    /// Iteratively calculate the gcd using Euclidean division of the operands.
    static U ugcd(U a, U b)
    {
        // Swap a and b if b > a
        if (b > a) {
            return ugcd(b, a);
        }

        U s, quo, t;

        // Iteratively update the variables while b is non-zero
        while (b) {
            quo = number<U>::udiv(a, b);
            t   = b * quo;
            s   = a - t;
            a   = b;
            b   = s;
        }

        return a;
    }

    /// Extended Euclidean algorithm.
    /// Iteratively calculate the gcd and the coefficients of Bezout's identity using a series of
    /// Euclidean divisions such that ax + by = gcd(a,b).
    static U uxgcd(U a, U b, U* x, U* y)
    {
        // Swap a and b if b > a
        if (b > a) {
            return uxgcd(b, a, y, x);
        }

        U old_x, old_y;
        *x    = 0;
        old_x = 1;
        *y    = 1;
        old_y = 0;

        // Iteratively update the variables while b is non-zero
        while (b) {
            U thi, tlo, quo, s;

            quo   = number<U>::udiv(a, b);
            number<U>::umul(&thi, &tlo, b, quo);
            s     = a - tlo;
            a     = b;
            b     = s;

            s     = *x;
            number<U>::umul(&thi, &tlo, quo, *x);
            *x    = old_x - tlo;
            old_x = s;

            s     = *y;
            number<U>::umul(&thi, &tlo, quo, *y);
            *y    = old_y - tlo;
            old_y = s;
        }

        *x = old_x;
        *y = old_y;
        return a;
    }

    /// Calculates the Binary Extended GCD such that u(2a) - vb = 1
    /// NOTE: a must be half of it's intended value, a MUST be even and b MUST be odd
    static int ubinxgcd(U a, U b, U* u, U* v)
    {
        if (a & 1) {
            return -1;
        }
        if (!(b & 1)) {
            return -2;
        }

        U uu    = 1;
        U vv    = 0;
        U alpha = a;
        U beta  = b;

        // The invariant maintained from here on is: 2a = u*2*alpha - v*beta
        while (a > 0) {
            a >>= 1;
            if ((uu & 1) == 0) {    // Remove a common factor of 2 in u and v
                uu >>= 1;
                vv >>= 1;
            }
            else {
                // Set u = (u + beta) >> 1, but that can overflow so care must be taken
                // This uses Dietz (see "Understanding Integer Overflow in C/C++", ICSE 2012)
                // u = ((u ^ beta) >> 1) + (u & beta);
                // This may be patented...
                uu = (uu >> 1) + (beta >> 1) + (uu & beta & 1);
                vv = (vv >> 1) + alpha;
            }
        }
        *u = uu;
        *v = vv;

        return 0;
    }

    /// Modular Multiplicative Inverse.
    /// Calculate xy === 1 (mod m), i.e. the remainder is 1 when xy is divided by m, m = 2^T_bits
    static U umod_mul_inverse(U x, U y)
    {
        using S = typename std::make_signed<U>::type;
        U y0, quo, rem;
        S t2;
        S v1 = 0;
        S v2 = 1;

        // If x > y then swap x and y, and v1 and v2
        if (x > y) {
            return umod_mul_inverse(y, x);
        }

        y0 = y;

        // If x and y both have MSB set then swap and
        // scale the parameters
        if ((y & x) & (static_cast<U>(1) << (std::numeric_limits<U>::digits-1))) {
            quo = y - x;
            y   = x;
            t2  = v2;
            v2  = v1 - v2;
            v1  = t2;
            x   = quo;
        }

        // Whilst the second value has second MSB set
        while (x & (static_cast<U>(1) << (std::numeric_limits<U>::digits-2))) {
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
                number<U>::udiv_qrnd(&quo, &rem, y, x);
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

    // Compute inverse: invx = (B^2 - B*x - 1)/x = (B^2 - 1)/x - B
    // If m = 1/x = B + invx, then m*x = B^2 - 1
    // Therefore, q1*B + q0 = n2/x = n2*B + n2(m-B) = n2*B + n2*(invx)
    static U uinverse(U p)
    {
        U inv, dummy;
        p <<= bit_manipulation::clz(p);
        udiv_qrnnd(&inv, &dummy, ~p, std::numeric_limits<U>::max(), p);
        return inv;
    }

    // Compute invx = floor((B^3 - 1)/(Bx1 + x0)) - B
    static U uinverse_3by2(U ph, U pl)
    {
        D mh, ml, qh, ql;
        U prod, rem, m;
        size_t u_digits_div2 = std::numeric_limits<U>::digits/2;

        // Split the high word into two using the half-limb base b
        // i.e. ph = b * mh + ml
        mh   = ph >> u_digits_div2;
        ml   = ph & U((U(1) << u_digits_div2) - 1);

        // Approximate the high half of the quotient
        qh   = (~ph / mh) & U((U(1) << u_digits_div2) - 1);

        // Get the upper half-limb 3/2 inverse
        //  qh  = floor((b^3 - 1) / (b*mh + ml)) - b
        //      = floor((b^3 - 1) / ph) - b
        //      = floor((b^3 - b*ph - 1) / ph)
        //      = floor((b(b^2 - ph) - 1) / ph)
        //      = floor((b(~ph + 1) - 1) / ph)
        //  rem = b(~ph) + b - 1 - qh * ph
        //      = b(~ph) + b - 1 - qh(b*mh + ml)
        //      = b(~ph - qh*mh) - qh*ml + b - 1
        prod = qh * mh;
        rem  = ((~ph - prod) << u_digits_div2) | U((U(1) << u_digits_div2) - 1);
        prod = qh * ml;

        // Adjustment by at most 2
        if (rem < prod) {
            qh--;
            rem += ph;

            // Check if carry was omitted and adjust
            if (rem >= ph && rem < prod) {
                qh--;
                rem += ph;
            }
        }
        rem -= prod;

        // Obtain the low half of the quotient
        //  ql = floor((b*rem + b - 1) / ph)
        prod = (rem >> u_digits_div2) * qh + rem;
        ql   = (prod >> u_digits_div2) + 1;
        rem  = (rem << u_digits_div2) + U((U(1) << u_digits_div2) - 1) - ql * ph;
        if (rem >= U(prod << u_digits_div2)) {
            ql--;
            rem += ph;
        }
        m = (static_cast<U>(qh) << u_digits_div2) + ql;
        if (rem >= ph) {
            m++;
            rem -= ph;
        }

        // Convert the 2/1 inverse of ph to a 3/2 inverse of B*ph + pl
        if (pl) {
            rem = ~rem + pl;
            if (rem < pl) {
                m--;
                if (rem >= ph) {
                    m--;
                    rem -= ph;
                }
                rem -= ph;
            }
            U pm1, pm0;
            umul(&pm1, &pm0, pl, m);
            rem += pm1;
            if (rem < pm1) {
                m--;
                m -= (rem > ph) | ((rem == ph) & (pm0 > pl));
            }
        }

        return m;
    }

    // Compute -1/q mod 2^(N-1) (works for all odd integers represented by N bits)
    static U uninv_minus1(U q)
    {
        assert(q & 1);
        return number_impl::uninv_internal(q);
    }


private:

    number() {}
    ~number() {}
};



// Forward declaration of common sizes
extern template class number<uint8_t>;
extern template class number<uint16_t>;
extern template class number<uint32_t>;
extern template class number<uint64_t>;

}  // namespace core
}  // namespace phantom
