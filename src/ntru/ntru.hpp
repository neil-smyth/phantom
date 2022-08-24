/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <memory>
#include "./phantom.hpp"
#include "crypto/csprng.hpp"
#include "core/reduction_montgomery.hpp"
#include "core/ntt_binary.hpp"
#include "sampling/gaussian_cdf.hpp"
#include "core/small_primes.hpp"


namespace phantom {
namespace ntru {

/// @class ntru N-th degree Truncated Polynomial Ring, smallest vector problem
class ntru
{
public:
    using mont_red  = core::montgomery<uint32_t>;
    using ntru_mont = core::reduction_montgomery<uint32_t>;
    using ntru_red  = core::reduction<ntru_mont, uint32_t>;
    using ntru_ntt  = core::ntt_binary<ntru_mont, uint32_t>;

    ntru(size_t logn, uint32_t q, const ntru_red* reduction, ntru_ntt* ntt);
    ~ntru();

    /// Attempt to solve the NTRU equation for given private key polynomial rings f and g
    bool solve(const int32_t* f, const int32_t* g, int32_t* F, int32_t* G);

    /// Generate the public key from a given private key f and g
    bool gen_public(int32_t *h, uint32_t* h_ntt, const int32_t *f, const int32_t *g);

private:
    static size_t temp_size(size_t logn);

    static uint32_t calc_gen_from_g1024(const ntru_red& mont, uint32_t g, size_t logn);

    static uint32_t fast_div31(uint32_t x);

    bool solve_deepest(const int32_t *f, const int32_t *g);

    bool solve_intermediate(const int32_t *f, const int32_t *g, size_t depth);

    static void crt_extract(ntru_ntt* transform, const ntru_red& mont, size_t n, size_t logn,
        bool ntt_flag, uint32_t R2, size_t slen, size_t tlen,
        uint32_t* t1, uint32_t* src, uint32_t* dst);
    static void crt_mod_extract(ntru_ntt* transform, const ntru_red& mont, size_t n, size_t logn,
        uint32_t R2, uint32_t Rx, size_t slen, size_t tlen,
        uint32_t* t1, uint32_t* src, uint32_t* dst);

    void gen_rns_fg(uint32_t *t, const int32_t *f, const int32_t *g,
        size_t logn, size_t depth, bool ntt_flag);

    static void gen_rns_fg_step(uint32_t *data, size_t logn, size_t depth, bool in_ntt, int out_ntt);

    static uint32_t poly_max_bitlength(const uint32_t *f, size_t flen, size_t fstride, size_t logn);

    // Convert a polynomial to floating-point values; the maximum bit length
    // of all coefficients is provided as 'maxbl' parameter. Returned values are
    // scaled down by 'scale' bits: if the integer value is z, this function
    // computes an approximation of z*2^(-scale).
    static void poly_big_to_fp(double *d, const uint32_t *f, size_t flen, size_t fstride,
        size_t logn, uint32_t maxbl, uint32_t scale);

    // Convert a polynomial to small integers. Source values are supposed
    // to be one-word integers, signed over 31 bits. Returned value is 0
    // if any of the coefficients exceeds 2047 (in absolute value), or 1
    // on success.
    static bool poly_big_to_small(int32_t *d, const uint32_t *s, size_t logn);

    static void poly_sub_scaled(uint32_t *_RESTRICT_ F, size_t Flen, size_t Fstride,
        const uint32_t *_RESTRICT_ f, size_t flen, size_t fstride,
        const int32_t *_RESTRICT_ k, uint32_t sc, size_t logn);

    static void poly_sub_scaled_ntt(uint32_t *_RESTRICT_ F, size_t Flen, size_t Fstride,
        const uint32_t *_RESTRICT_ f, size_t flen, size_t fstride,
        const int32_t *_RESTRICT_ k, uint32_t sc, size_t logn,
        uint32_t *_RESTRICT_ tmp);

    /// Compute a GCD between two positive big integers x and y. The two
    /// integers must be odd. Returned value is 1 if the GCD is 1, 0
    /// otherwise. When 1 is returned, arrays u and v are filled with values
    /// such that:
    ///   0 <= u <= y
    ///   0 <= v <= x
    ///   x*u - y*v = 1
    /// x[] and y[] are unmodified. Both input values must have the same
    /// encoded length. Temporary array must be large enough to accommodate 4
    /// extra values of that length. Arrays u, v and tmp may not overlap with
    /// each other, or with either x or y.
    static bool bezout(uint32_t* u, uint32_t* v,
        const uint32_t* x, const uint32_t* y,
        size_t len, uint32_t* tmp);

    /// Rebuild integers from their RNS representation. There are 'num'
    /// integers, and each consists in 'xlen' words. 'xx' points at that
    /// first word of the first integer; subsequent integers are accessed
    /// by adding 'xstride' repeatedly.
    ///
    /// The words of an integer are the RNS representation of that integer,
    /// using the provided 'primes' are moduli. This function replaces
    /// each integer with its multi-word value (little-endian order).
    ///
    /// If "normalize_signed" is non-zero, then the returned value is
    /// normalized to the -m/2..m/2 interval (where m is the product of all
    /// small prime moduli); two's complement is used for negative values.
    static void rebuild_CRT(uint32_t* xx, size_t xlen, size_t xstride,
        size_t num, const core::small_prime *primes, bool normalize_signed,
        uint32_t* tmp);

    /// Compute exact length of an integer (i.e. reduce it to remove high words of value 0)
    static size_t exact_length(const uint32_t* x, size_t xlen);

    /// Replace a with (a*xa+b*xb)/(2^31) and b with (a*ya+b*yb)/(2^31)
    static int co_reduce(uint32_t* a, uint32_t* b, size_t len,
        int32_t xa, int32_t xb, int32_t ya, int32_t yb);

    /// Replace a with (a*xa+b*xb)/(2^31) mod m, and b with
    /// (a*ya+b*yb)/(2^31) mod m. Modulus m must be odd; m0i = -1/m[0] mod 2^31
    static void co_reduce_mod(uint32_t* a, uint32_t* b, const uint32_t* m, size_t len,
        uint32_t m0i, int32_t xa, int32_t xb, int32_t ya, int32_t yb);

    /// Replace a with (a+k*b)/(2^31). If the result it negative, then it is
    /// negated and 1 is returned; otherwise, 0 is returned
    static bool reduce(uint32_t* a, const uint32_t* b, size_t len, int32_t k);

    /// Replace a with (a+k*b)/(2^31) mod m, modulus m must be odd; m0i = -1/m[0] mod 2^31
    static void reduce_mod(uint32_t* a, const uint32_t* b, const uint32_t *m,
        size_t len, uint32_t m0i, int32_t k);

    /// Get the bit length of a signed big integer: this is the minimum number
    /// of bits required to hold the value, _without_ the signed bit (thus, -1
    /// has bit length 0)
    static uint32_t signed_bit_length(const uint32_t* x, size_t xlen);

    /// Get the top 63 bits of a signed big integer, starting at the provided
    /// index (in bits). The integer absolute value MUST fit in sc+63 bits
    static int64_t get_top(const uint32_t* x, size_t xlen, uint32_t sc);

    /// Add k*y*2^sc to x
    static void add_scaled_mul_small(uint32_t* x, size_t xlen,
        const uint32_t* y, size_t ylen, int32_t k,
        uint32_t sch, uint32_t scl);

    /// Subtract y*2^sc from x
    static void sub_scaled(uint32_t* x, size_t xlen,
        const uint32_t* y, size_t ylen, uint32_t sch, uint32_t scl);

    // Base-2 logarithm of the degree
    const size_t m_logn;

    // The selected modulus
    const uint32_t m_q;

    const ntru_red* m_reduction;
    ntru_ntt* m_ntt;

    // Temporary storage for key generation. 'tmp_len' is expressed
    // in 32-bit words
    phantom_vector<uint32_t> m_tmp_vec;
    uint32_t* m_tmp;
    size_t m_tmp_len;
};

}  // namespace ntru
}  // namespace phantom
