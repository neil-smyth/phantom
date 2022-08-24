/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <cassert>
#include <limits>
#include <memory>

#include "./phantom.hpp"
#include "core/small_primes.hpp"
#include "crypto/csprng.hpp"
#include "core/reduction_montgomery.hpp"
#include "core/ntt_binary.hpp"
#include "sampling/gaussian_cdf.hpp"


namespace phantom {
namespace ntru {

#if defined(__SIZEOF_INT128__)
using uint128_t = unsigned __int128;
#endif

/**
 * @brief Arithmetic specific to NTRU
 * 
 * @tparam U 
 */
template<typename U>
class ntru_number
{
public:
    using V = core::next_size_t<U>;

    static_assert(std::is_same<U, uint8_t>::value  ||
                  std::is_same<U, uint16_t>::value ||
                  std::is_same<U, uint32_t>::value ||
                  std::is_same<U, uint64_t>::value,
                  "number instantiated with unsupported type");

    /// Reduce a big integer d modulo a small integer p
    static U mod_small_unsigned(const U* d, size_t dlen, U R2,
        const core::reduction<core::reduction_montgomery<U>, U>& mont)
    {
        // Reduce a big integer d modulo a small integer p.
        // Rules:
        //  d is unsigned
        //  p is prime
        //  2^30 < p < 2^31
        //  p0i = -(1/p) mod 2^31
        //  R2 = 2^62 mod p

        // Algorithm: we inject words one by one, starting with the high
        // word. Each step is:
        //  - multiply x by 2^31
        //  - add new word

        U x = 0;
        U q = mont.get_q();
        size_t u = dlen;
        while (u-- > 0) {
            U w;
            x  = mont.mul(x, R2);
            w  = d[u] - q;
            w += q & -(w >> (std::numeric_limits<U>::digits - 1));
            x  = mont.add(x, w);
        }
        return x;
    }

    /// Similar to mod_small_unsigned(), except that d may be signed
    static U mod_small_signed(const U* d, size_t dlen, U R2,
        const core::reduction<core::reduction_montgomery<U>, U>& mont, U Rx)
    {
        // Similar to mod_small_unsigned(), except that d
        // may be signed. Extra parameter is Rx = 2^(31*dlen) mod p.
        U z;

        if (0 == dlen) {
            return 0;
        }
        z = mod_small_unsigned(d, dlen, R2, mont);
        z = mont.sub(z, Rx & -(d[dlen - 1] >> (std::numeric_limits<U>::digits - 2)));
        return z;
    }

    /// Multiply m by x, returning any carry bits
    static U mul_small(U* m, size_t len, U x)
    {
        U cc = 0;
        for (size_t i = 0; i < len; i++) {
            V z;
            z    = static_cast<V>(m[i]) * static_cast<V>(x) + cc;
            m[i] = static_cast<U>(z) & ((U(1) << (std::numeric_limits<U>::digits - 1)) - 1);
            cc   = static_cast<U>(z >> (std::numeric_limits<U>::digits - 1));
        }
        return cc;
    }

    /// Add y*s to x. x and y initially have length 'len' words; the new x
    /// has length 'len+1' words. 's' must fit on (type size - 1) bits
    static void add_mul_small(U* x, const U* y, size_t len, const U s)
    {
        U cc = 0;
        for (size_t u = 0; u < len; u++) {
            V z  = static_cast<V>(y[u]) * static_cast<V>(s) +
                    static_cast<V>(x[u]) + static_cast<V>(cc);
            x[u] = static_cast<U>(z) & ((U(1) << (std::numeric_limits<U>::digits - 1)) - 1);
            cc   = static_cast<U>(z >> (std::numeric_limits<U>::digits - 1));
        }
        x[len] = cc;
    }

    /// Add b to a, returning result in a
    static U add(U* a, const U* b, size_t len)
    {
        U cc = 0;
        for (size_t u = 0; u < len; u++) {
            U w;
            w    = a[u] + b[u] + cc;
            a[u] = w & ((U(1) << (std::numeric_limits<U>::digits - 1)) - 1);
            cc   = w >> (std::numeric_limits<U>::digits - 1);
        }
        return cc;
    }

    /// Subtract b from a, returning result in a
    static U sub(U* a, const U* b, size_t len)
    {
        U cc = 0;
        for (size_t u = 0; u < len; u++) {
            U w;
            w    = a[u] - b[u] - cc;
            a[u] = w & ((U(1) << (std::numeric_limits<U>::digits - 1)) - 1);
            cc   = w >> (std::numeric_limits<U>::digits - 1);
        }
        return cc;
    }

    /// Subtract y from x, modulo p
    static void sub_mod(U* x, const U* y, const U* p, size_t len)
    {
        U s = sub(x, y, len);
#if const_time == const_time_enabled
        U cc = 0;
        for (size_t u = 0; u < len; u++) {
            U w;
            w    = x[u] + core::const_time_enabled<U>::if_condition_is_true(s, p[u]) + cc;
            x[u] = w & ((U(1) << (std::numeric_limits<U>::digits - 1)) - 1);
            cc   = w >> (std::numeric_limits<U>::digits - 1);
        }
#else
        if (s) {
            add(x, p, len);
        }
#endif

        /*if (sub(x, y, len)) {
            add(x, p, len);
        }*/
    }

    /// Right-shift an unsigned integer by one bit
    static U rshift1(U* d, size_t len)
    {
        U cc = 0;
        size_t k = len;
        while (k-- > 0) {
            U w;
            w = d[k];
            d[k] = (w >> 1) | (cc << (std::numeric_limits<U>::digits - 2));
            cc = w & 1;
        }
        return cc;
    }

    /// Halve integer x modulo integer p, the modulus p MUST be odd
    static void rshift1_mod(U* x, const U* p, size_t len)
    {
        // The modulus p MUST be odd
        assert(p[0] & 1);

        // If the LSB of x is asserted set a condition flag
        U cond = x[0] & 1;

        // If the LSB of x is asserted then add p before the right shift
        U hi = 0;
        for (size_t u = 0; u < len; u++) {
            U w;
            w    = x[u] + const_time<U>::if_condition_is_true(cond, p[u]) + hi;
            x[u] = w & ((U(1) << (std::numeric_limits<U>::digits - 1)) - 1);
            hi   = w >> (std::numeric_limits<U>::digits - 1);
        }

        // Right shift the multiple-precision integer by 1 bit
        rshift1(x, len);

        // Set the MSB-1 bit of the mostsignificant word if the addition
        // carry bit is set
        x[len - 1] |= hi << (std::numeric_limits<U>::digits - 2);
    }

    /// Compare a with b. Both integers are unsigned and have the same
    /// encoded length
    static int ucmp(const U* a, const U* b, size_t len)
    {
        while (len-- > 0) {
            U wa = a[len];
            U wb = b[len];
            if (wa < wb) {
                return -1;
            }
            if (wa > wb) {
                return 1;
            }
        }
        return 0;
    }

    /// Normalize an array of integers around 0
    static void norm_zero(U* x, const U* p, size_t len)
    {
        // Normalize a modular integer around 0: if x > p/2, then x is replaced
        // with x - p (signed encoding with two's compliment); otherwise, x is
        // untouched.
        U cc = 0;
        size_t u = len;
        while (u-- > 0) {
            U w;
            w = (p[u] >> 1) | (cc << (std::numeric_limits<U>::digits - 2));
            cc = p[u] & 1;
            if (x[u] < w) {
                return;
            }
            if (x[u] > w) {
                sub(x, p, len);
                return;
            }
        }
    }
};

}  // namespace ntru
}  // namespace phantom
