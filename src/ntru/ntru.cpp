/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "ntru/ntru.hpp"

#include <algorithm>

#include "sampling/uniform_sampler.hpp"
#include "core/small_primes.hpp"
#include "logging/logger.hpp"
#include "core/poly.hpp"
#include "fft/fft_factory.hpp"
#include "fft/fft_poly.hpp"
#include "ntru/ntru_number.hpp"


// NOTE: This code is adapted from thr Falcon reference implementation: https://falcon-sign.info/

namespace phantom {
namespace ntru {


ntru::ntru(size_t logn, uint32_t q, const ntru_red* reduction, ntru_ntt* ntt) :
    m_logn(logn),
    m_q(q),
    m_reduction(reduction),
    m_ntt(ntt)
{
    m_tmp_vec = phantom_vector<uint32_t>(temp_size(m_logn));
    m_tmp = m_tmp_vec.data();
}

ntru::~ntru()
{
}

// Compute size of temporary array for key generation.
// Returned size is expressed in bytes.
size_t ntru::temp_size(size_t logn)
{
    size_t gmax = 0;

    // Compute memory requirements for make_fg() at each depth.
    for (size_t depth = 0; depth < logn; depth++) {
        size_t cur;

        size_t n    = static_cast<size_t>(1) << (logn - depth);
        size_t slen = core::max_bl_small2[depth];
        size_t tlen = core::max_bl_small2[depth + 1];
        cur  = (n * tlen + 2 * n * slen + 3 * n) * sizeof(uint32_t);
        gmax = cur > gmax ? cur : gmax;
        cur  = (n * tlen + 2 * n * slen + slen) * sizeof(uint32_t);
        gmax = cur > gmax ? cur : gmax;
    }

    // Compute memory requirements for each depth.
    for (size_t depth = 0; depth <= logn; depth++) {
        size_t cur;
        size_t max  = 0;
        size_t slen = core::max_bl_small2[depth];

        if (depth == logn) {
            cur = 8 * slen * sizeof(uint32_t);
            max = cur > max ? cur : max;
        }
        else {
            size_t n    = static_cast<size_t>(1) << (logn - depth);
            size_t hn   = n >> 1;
            size_t llen = core::max_bl_large2[depth];

            cur = (2 * n * llen + 2 * n * slen + 4 * n) * sizeof(uint32_t);
            max = cur > max ? cur : max;
            cur = (2 * n * llen + 2 * n * slen + llen) * sizeof(uint32_t);
            max = cur > max ? cur : max;
            size_t tmp1 = align_on_type<uint32_t>(
                align_on_type<double>((2 * n * llen + 2 * n * slen) * sizeof(uint32_t))
                + (2 * n + hn) * sizeof(double))
                + n * sizeof(uint32_t);
            size_t tmp2 = align_on_type<double>((2 * n * llen + 2 * n * slen) * sizeof(uint32_t))
                + (3 * n + hn) * sizeof(double);
            cur = tmp1 > tmp2 ? tmp1 : tmp2;
            cur = align_on_type<double>(cur) + n * sizeof(double);
            max = cur > max ? cur : max;
            cur = align_on_type<uint32_t>(
                align_on_type<double>((2 * n * llen + 2 * n * slen) * sizeof(uint32_t))
                + (2 * n + hn) * sizeof(double))
                + (5 * n + n * slen) * sizeof(uint32_t);
            max = cur > max ? cur : max;
        }

        gmax = max > gmax ? max : gmax;
    }

    return gmax;
}

bool ntru::solve(const int32_t* f, const int32_t* g, int32_t* F, int32_t* G)
{
    if (!solve_deepest(f, g)) {
        return false;
    }

    size_t depth = m_logn;
    while (depth-- > 0) {
        if (!solve_intermediate(f, g, depth)) {
            return false;
        }
    }

    // Final F and G are in m_tmp, one word per coefficient (signed value
    // over 31 bits)
    size_t n = 1 << m_logn;
    if (!poly_big_to_small(F, m_tmp, m_logn) || !poly_big_to_small(G, m_tmp + n, m_logn)) {
        return false;
    }

    // Verify that the NTRU equation is fulfilled. Since all elements
    // have short lengths, verifying modulo a small prime p works, and
    // allows using the NTT.
    uint32_t* ft = m_tmp;
    uint32_t* gt = ft + n;
    uint32_t* Ft = gt + n;
    uint32_t* Gt = Ft + n;

    const core::small_prime *primes = core::small_primes_u31;
    uint32_t p   = primes[0].p;
    uint32_t p0i = core::number<uint32_t>::uninv_minus1(p);
    uint32_t R   = core::montgomery<uint32_t>::gen_R(p, 31);
    uint32_t R2  = core::montgomery<uint32_t>::gen_R2(p, p0i, 31);
    core::montgomery<uint32_t> red(p, p0i, 31, R, R2);
    ntru_red mont(red);
    uint32_t gen = calc_gen_from_g1024(mont, primes[0].g, m_logn);
    ntru_ntt transform(mont, gen, n);

    for (size_t u = 0; u < n; u++) {
        ft[u] = static_cast<uint32_t>(f[u]) + (p & -(static_cast<uint32_t>(f[u]) >> 31));
        gt[u] = static_cast<uint32_t>(g[u]) + (p & -(static_cast<uint32_t>(g[u]) >> 31));
        Ft[u] = static_cast<uint32_t>(F[u]) + (p & -(static_cast<uint32_t>(F[u]) >> 31));
        Gt[u] = static_cast<uint32_t>(G[u]) + (p & -(static_cast<uint32_t>(G[u]) >> 31));
    }

    transform.fwd(ft, m_logn);
    transform.fwd(gt, m_logn);
    transform.fwd(Ft, m_logn);
    transform.fwd(Gt, m_logn);
    uint32_t r = mont.mul(m_q, 1);
    for (size_t u = 0; u < n; u++) {
        uint32_t z = mont.sub(mont.mul(ft[u], Gt[u]), mont.mul(gt[u], Ft[u]));
        if (z != r) {
            return false;
        }
    }

    return true;
}

bool ntru::gen_public(int32_t *h, uint32_t* h_ntt, const int32_t *f, const int32_t *g)
{
    const size_t n = 1 << m_logn;
    alignas(32) uint32_t t[n];
    uint32_t* uh = reinterpret_cast<uint32_t*>(h);

    // Obtain NTT(f) and NTT(g)
    uint32_t temp;
    for (size_t i = 0; i < n; i++) {
        temp  = f[i] + (static_cast<uint32_t>(f[i] >> 31) & m_q);
        uh[i] = m_reduction->convert_to(temp);
        temp  = g[i] + (static_cast<uint32_t>(g[i] >> 31) & m_q);
        t[i]  = m_reduction->convert_to(temp);
    }
    m_ntt->fwd(uh, m_logn);
    m_ntt->fwd(t, m_logn);

    // Attempt to invert NTT(f)
    if (!m_ntt->inverse(uh)) {
        return false;
    }

    // h = g/f and f is invertible, so calculate public key
    m_ntt->mul(uh, uh, t);
    for (size_t i = 0; i < n; i++) {
        h_ntt[i] = uh[i];
    }
    m_ntt->inv(uh, m_logn);
    m_reduction->convert_from(uh, uh, n);

    return true;
}

bool ntru::solve_deepest(const int32_t *f, const int32_t *g)
{
    const core::small_prime *primes = core::small_primes_u31;
    const size_t len = core::max_bl_small2[m_logn];

    uint32_t* Fp  = m_tmp;
    uint32_t* Gp  = Fp + len;
    uint32_t* fp  = Gp + len;
    uint32_t* gp  = fp + len;
    uint32_t* tmp = gp + len;

    // Generate f, g and resultants in residue number system format
    gen_rns_fg(fp, f, g, m_logn, m_logn, false);

    // Use the CRT to rebuild the resultants as big integers
    rebuild_CRT(fp, len, len, 2, primes, false, tmp);

    // Apply the binary GCD, where if the GCD is 1 then Gp and Fp are the
    // bezout coefficients
    if (!bezout(Gp, Fp, fp, gp, len, tmp)) {
        return false;
    }

    // Multiply the Bezout coefficients by q - the result must fit in the len
    // words of Fp, therefore the carry bits must be 0
    if (0 != ntru_number<uint32_t>::mul_small(Fp, len, m_q) ||
        0 != ntru_number<uint32_t>::mul_small(Gp, len, m_q)) {
        return false;
    }

    return true;
}

// Get the maximum bitlength of coordinates for a polynomial
uint32_t ntru::poly_max_bitlength(const uint32_t *f, size_t flen, size_t fstride, size_t logn)
{
    size_t   n     = static_cast<size_t>(1) << logn;
    uint32_t maxbl = 0;
    for (size_t u = 0; u < n; u++, f += fstride) {
        uint32_t bl = signed_bit_length(f, flen);
        if (bl > maxbl) {
            maxbl = bl;
        }
    }
    return maxbl;
}

void ntru::poly_big_to_fp(double *d, const uint32_t *f, size_t flen, size_t fstride,
    size_t logn, uint32_t maxbl, uint32_t scale)
{
    size_t   n   = static_cast<size_t>(1) << logn;
    uint32_t off = maxbl < 63 ? 0 : maxbl - 63;
    for (size_t u = 0; u < n; u++, f += fstride) {
        d[u] = ldexp(get_top(f, flen, off), static_cast<int>(off - scale));
    }
}

bool ntru::poly_big_to_small(int32_t *d, const uint32_t *s, size_t logn)
{
    size_t n = static_cast<size_t>(1) << logn;
    for (size_t u = 0; u < n; u++) {
        uint32_t w = s[u] | ((s[u] & 0x40000000) << 1);
        int32_t  z = static_cast<int32_t>(w);

        if (z < -8191 || z > 8191) {
            return false;
        }
        d[u] = z;
    }
    return true;
}

void ntru::poly_sub_scaled(uint32_t *_RESTRICT_ F, size_t Flen, size_t Fstride,
    const uint32_t *_RESTRICT_ f, size_t flen, size_t fstride,
    const int32_t *_RESTRICT_ k, uint32_t sc, size_t logn)
{
    // Subtract k*f from F, where F, f and k are polynomials modulo X^N+1.
    // Coefficients of polynomial k are small integers (signed values in the
    // -2^31..2^31 range) scaled by 2^sc.
    //
    // This function implements the basic quadratic multiplication algorithm,
    // which is efficient in space (no extra buffer needed) but slow at
    // high degree.

    size_t n   = 1 << logn;
    size_t hn  = n >> 1;
    uint32_t sch = core::bit_manipulation::fast_div31(sc);   // sc / 31
    uint32_t scl = sc - (31 * sch);  // sc % 31

    for (size_t u = 0; u < n; u++) {
        int32_t kf = -k[u];
        uint32_t* x = F + u * Fstride;
        const uint32_t* y = f;
        for (size_t v = 0; v < n; v++) {
            add_scaled_mul_small(x, Flen, y, flen, kf, sch, scl);
            if (u + v == n - 1) {
                x = F;
                kf = -kf;
            }
            else {
                x += Fstride;
            }
            y += fstride;
        }
    }
}

void ntru::poly_sub_scaled_ntt(uint32_t *_RESTRICT_ F, size_t Flen, size_t Fstride,
    const uint32_t *_RESTRICT_ f, size_t flen, size_t fstride,
    const int32_t *_RESTRICT_ k, uint32_t sc, size_t logn,
    uint32_t *_RESTRICT_ tmp)
{
    // Subtract k*f from F. Coefficients of polynomial k are small integers
    // (signed values in the -2^31..2^31 range) scaled by 2^sc. This function
    // assumes that the degree is large, and integers relatively small.

    const core::small_prime *primes = core::small_primes_u31;
    size_t    n    = 1 << logn;
    size_t    tlen = flen + 1;
    uint32_t* fk   = tmp;
    uint32_t* t1   = fk + n * tlen;

    // Compute k*f in fk[], in RNS notation.
    for (size_t u = 0; u < tlen; u++) {
        uint32_t p   = primes[u].p;
        uint32_t p0i = core::number<uint32_t>::uninv_minus1(p);
        uint32_t R   = core::montgomery<uint32_t>::gen_R(p, 31);
        uint32_t R2  = core::montgomery<uint32_t>::gen_R2(p, p0i, 31);
        core::montgomery<uint32_t> red(p, p0i, 31, R, R2);
        ntru_red mont(red);
        uint32_t g   = calc_gen_from_g1024(mont, primes[u].g, logn);
        ntru_ntt transform(mont, g, n);
        uint32_t Rx  = core::montgomery<uint32_t>::gen_Rx(flen, p, p0i, R, R2, 31);

        for (size_t v = 0; v < n; v++) {
            t1[v] = static_cast<uint32_t>(k[v]) + (p & -(static_cast<uint32_t>(k[v]) >> 31));
        }

        transform.fwd(t1, logn);
        uint32_t* x = fk + u;
        const uint32_t* y = f;
        for (size_t v = 0; v < n; v++) {
            *x = ntru_number<uint32_t>::mod_small_signed(y, flen, R2, mont, Rx);
            y += fstride;
            x += tlen;
        }

        transform.fwd(fk + u, logn, tlen);
        x = fk + u;
        for (size_t v = 0; v < n; v++) {
            *x = mont.mul(mont.mul(t1[v], *x), R2);
            x += tlen;
        }

        transform.inv(fk + u, logn, tlen);
    }

    // Rebuild k*f.
    rebuild_CRT(fk, tlen, tlen, n, primes, true, t1);

    // Subtract k*f, scaled, from F.
    uint32_t sch = core::bit_manipulation::fast_div31(sc);   // sc / 31ntru_number
    uint32_t scl = sc - (31 * sch);  // sc % 31
    uint32_t* x = F;
    const uint32_t* y = fk;
    for (size_t u = 0; u < n; u++) {
        sub_scaled(x, Flen, y, tlen, sch, scl);
        x += Fstride;
        y += tlen;
    }
}

bool ntru::bezout(uint32_t * u, uint32_t * v,
    const uint32_t * x, const uint32_t * y,
    size_t len, uint32_t * tmp)
{
    // Algorithm is an extended binary GCD. We maintain 6 values
    // a, b, u0, u1, v0 and v1 with the following invariants:
    //
    //     a = x*u0 - y*v0
    //     b = x*u1 - y*v1
    //     0 <= u0 < y
    //     0 <= v0 < x
    //     0 <= u1 <= y
    //     0 <= v1 <= x
    //
    // Initial values are:
    //
    //     a = x   u0 = 1   v0 = 0
    //     b = y   u1 = y   v1 = x-1
    //
    // Each iteration reduces either a or b, and maintain the invariants. The
    // algorithm stops when a = b, at which point their common value is GCD(a,b)
    // and (u0,v0) (or (u1,v1)) contains the values (u,v) we want to return.
    //
    // We must handle the cases of x = 1 or y = 1, which make the solution trivial.
    // If x > 1 and y > 1, and GCD(x,y) = 1, then there will be a solution (u,v)
    // such that 0 < u < y and 0 < v < x (it can be shown that u = 1/x mod y and
    // v = -1/y mod x).

    uint32_t* u0 = u;
    uint32_t* v0 = v;
    uint32_t* u1 = tmp;
    uint32_t* v1 = u1 + len;
    uint32_t* a  = v1 + len;
    uint32_t* b  = a + len;

    // Compute actual lengths of x and y.
    size_t xlen = exact_length(x, len);
    size_t ylen = exact_length(y, len);

    // Filter out bad values:
    //   x and y must not be zero.
    //   x and y must be odd.
    if (0 == xlen || 0 == ylen || 0 == (x[0] & y[0] & 1)) {
        return false;
    }

    // Initialize a, b, u0, u1, v0 and v1
    //  a = x   u0 = 1   v0 = 0
    //  b = y   u1 = y   v1 = x-1
    // Note that x is odd, so computing x-1 is trivial
    std::copy(x, x + xlen, a);
    std::copy(y, y + ylen, b);
    size_t alen = xlen;
    size_t blen = ylen;
    u0[0] = 1;
    memset(u0 + 1, 0, (ylen - 1) * sizeof *u0);
    memset(v0, 0, xlen * sizeof *v0);
    std::copy(y, y + ylen, u1);
    std::copy(x, x + xlen, v1);
    v1[0] ^= 1;

    // We also zero out the upper unused words of the returned array
    // u and v (caller expects it).
    memset(u + ylen, 0, (len - ylen) * sizeof *u);
    memset(v + xlen, 0, (len - xlen) * sizeof *v);

    // We zero out the upper unused words of a and b as well, so that
    // we may subtract one from the other with a common length.
    size_t mlen = alen < blen ? blen : alen;
    memset(a + alen, 0, (mlen - alen) * sizeof *a);
    memset(b + blen, 0, (mlen - blen) * sizeof *b);

    // If x = 1 then the current values in u and v are just fine
    // and we can return them (because u0 and u are the same array,
    // and similarly v0 and v).
    // If y = 1, then the values in u1 and v1 must be returned.
    if (1 == xlen && 1 == x[0]) {
        return true;
    }
    if (1 == ylen && 1 == y[0]) {
        std::copy(u1, u1 + ylen, u);
        std::copy(v1, v1 + xlen, v);
        return true;
    }

    uint32_t x0i = core::number<uint32_t>::uninv_minus1(x[0]);
    uint32_t y0i = core::number<uint32_t>::uninv_minus1(y[0]);

    // We are now all set for the main algorithm.
    for (;;) {
        int r;

        // If either word is large enough, we use the
        // accelerated approximation.
        if (alen >= 3 || blen >= 3) {
            int32_t r;

            size_t len = alen < blen ? blen : alen;

            // Get the top and low bits of each value.
            uint64_t a_hi = (static_cast<uint64_t>(a[len - 1]) << 31) | a[len - 2];
            uint64_t b_hi = (static_cast<uint64_t>(b[len - 1]) << 31) | b[len - 2];
            uint32_t a_lo = a[0];
            uint32_t b_lo = b[0];
            uint32_t uxa  = 1;
            uint32_t uxb  = 0;
            uint32_t uya  = 0;
            uint32_t uyb  = 1;
            for (size_t i = 0; i < 31; i ++) {
                uint32_t m = UINT32_C(1) << i;

                if (0 == (a_lo & m)) {
                    a_hi >>= 1;
                    b_lo <<= 1;
                    uya  <<= 1;
                    uyb  <<= 1;
                }
                else if (0 == (b_lo & m)) {
                    b_hi >>= 1;
                    a_lo <<= 1;
                    uxa  <<= 1;
                    uxb  <<= 1;
                }
                else if (a_hi > b_hi) {
                    a_hi  -= b_hi;
                    a_lo  -= b_lo;
                    uxa   -= uya;
                    uxb   -= uyb;
                    a_hi >>= 1;
                    b_lo <<= 1;
                    uya  <<= 1;
                    uyb  <<= 1;
                }
                else {
                    b_hi  -= a_hi;
                    b_lo  -= a_lo;
                    uya   -= uxa;
                    uyb   -= uxb;
                    b_hi >>= 1;
                    a_lo <<= 1;
                    uxa  <<= 1;
                    uxb  <<= 1;
                }
            }

            // It may happen that one of the factors is equal to 2^31.
            // In that case, we must use a specialized function, because that
            // value will not fit in an int32_t.
            if (uxa == 0x80000000) {
                if (uxb != 0 || uyb != 1) {
                    return false;
                }
                int32_t ya = static_cast<int32_t>(uya);
                if (reduce(b, a, len, ya)) {
                    ya = -ya;
                }
                reduce_mod(u1, u0, y, ylen, y0i, ya);
                reduce_mod(v1, v0, x, xlen, x0i, ya);
            }
            else if (uyb == 0x80000000) {
                if (uya != 0 || uxa != 1) {
                    return false;
                }
                int32_t xb = static_cast<int32_t>(uxb);
                if (reduce(a, b, len, xb)) {
                    xb = -xb;
                }
                reduce_mod(u0, u1, y, ylen, y0i, xb);
                reduce_mod(v0, v1, x, xlen, x0i, xb);
            }
            else {
                int32_t xa = static_cast<int32_t>(uxa);
                int32_t xb = static_cast<int32_t>(uxb);
                int32_t ya = static_cast<int32_t>(uya);
                int32_t yb = static_cast<int32_t>(uyb);

                r = co_reduce(a, b, len, xa, xb, ya, yb);
                if ((r & 1) != 0) {
                    xa = -xa;
                    xb = -xb;
                }
                if ((r & 2) != 0) {
                    ya = -ya;
                    yb = -yb;
                }
                co_reduce_mod(u0, u1, y, ylen, y0i, xa, xb, ya, yb);
                co_reduce_mod(v0, v1, x, xlen, x0i, xa, xb, ya, yb);
            }
            alen = exact_length(a, alen);
            blen = exact_length(b, blen);

            continue;
        }

        // If a is even, divide it by 2 and adjust u0 and v0.
        if ((a[0] & 1) == 0) {
            ntru_number<uint32_t>::rshift1(a, alen);
            alen = exact_length(a, alen);
            ntru_number<uint32_t>::rshift1_mod(u0, y, ylen);
            ntru_number<uint32_t>::rshift1_mod(v0, x, xlen);
            continue;
        }

        // If b is even, divide it by 2 and adjust u1 and v1.
        if ((b[0] & 1) == 0) {
            ntru_number<uint32_t>::rshift1(b, blen);
            blen = exact_length(b, blen);
            ntru_number<uint32_t>::rshift1_mod(u1, y, ylen);
            ntru_number<uint32_t>::rshift1_mod(v1, x, xlen);
            continue;
        }

        // Compare a to b. If equal, then the algorithm terminates.
        if (alen < blen) {
            r = -1;
        }
        else if (alen > blen) {
            r = 1;
        }
        else {
            r = ntru_number<uint32_t>::ucmp(a, b, alen);
            if (r == 0) {
                // If a == b, then the algorithm terminate as they both contain
                // the GCD of x and y. This is a success only if that GCD is 1.
                // Arrays u and v are already filled with the proper results.
                return alen == 1 && a[0] == 1;
            }
        }

        // If a > b, then set a <- a-b, and adjust u0 and v0 accordingly.
        // We will be able to maintain 0 < u0 < y and 0 < v0 < x.
        //
        // If a < b, then set b <- b-a, and adjust u1 and v1 accordingly.
        // We will be able to maintain 0 < u1 < y and 0 < v1 < x.
        if (r > 0) {
            ntru_number<uint32_t>::sub(a, b, alen);
            alen = exact_length(a, alen);
            ntru_number<uint32_t>::sub_mod(u0, u1, y, ylen);
            ntru_number<uint32_t>::sub_mod(v0, v1, x, xlen);
        }
        else {
            ntru_number<uint32_t>::sub(b, a, blen);
            blen = exact_length(b, blen);
            ntru_number<uint32_t>::sub_mod(u1, u0, y, ylen);
            ntru_number<uint32_t>::sub_mod(v1, v0, x, xlen);
        }
    }
}

void ntru::rebuild_CRT(uint32_t* xx, size_t xlen, size_t xstride,
    size_t num, const core::small_prime *primes, bool normalize_signed,
    uint32_t* tmp)
{
    tmp[0] = primes[0].p;
    for (size_t u = 1; u < xlen; u++) {
        // At the entry of each loop iteration:
        //  - the first u words of each array have been reassembled
        //  - the first u words of tmp[] contains the product of the prime
        //    moduli processed so far.
        //
        // We call 'q' the product of all previous primes.
        uint32_t p    = primes[u].p;
        uint32_t s    = primes[u].s;
        uint32_t invp = core::number<uint32_t>::uninv_minus1(p);
        uint32_t R    = core::montgomery<uint32_t>::gen_R(p, 31);
        uint32_t R2   = core::montgomery<uint32_t>::gen_R2(p, invp, 31);
        core::montgomery<uint32_t> red(p, invp, 31, R, R2);
        core::reduction<core::reduction_montgomery<uint32_t>, uint32_t> mont(red);

        uint32_t *x = xx;
        for (size_t v = 0; v < num; v++, x += xstride) {
            // xp : the integer x modulo the prime p for this iteration
            // xq : (x mod q) mod p
            uint32_t xp = x[u];
            uint32_t xq = ntru_number<uint32_t>::mod_small_unsigned(x, u, R2, mont);

            // (x mod q) + q * (s * (xp - xq) mod p)
            uint32_t xr = mont.mul(s, mont.sub(xp, xq));
            ntru_number<uint32_t>::add_mul_small(x, tmp, u, xr);
        }

        // Update product of primes in tmp[].
        tmp[u] = ntru_number<uint32_t>::mul_small(tmp, u, p);
    }

    // Normalize the reconstructed values around 0.
    if (normalize_signed) {
        uint32_t* x = xx;
        for (size_t u = 0; u < num; u++, x += xstride) {
            ntru_number<uint32_t>::norm_zero(x, tmp, xlen);
        }
    }
}

size_t ntru::exact_length(const uint32_t *x, size_t xlen)
{
    while (xlen > 0) {
        if (x[xlen - 1] != 0) {
            return xlen;
        }
        xlen--;
    }
    return xlen;
}

int32_t ntru::co_reduce(uint32_t *a, uint32_t *b, size_t len,
    int32_t xa, int32_t xb, int32_t ya, int32_t yb)
{
    // Replace a with (a*xa+b*xb)/(2^31) and b with (a*ya+b*yb)/(2^31).
    // The low bits are dropped (the caller should compute the coefficients
    // such that these dropped bits are all zeros). If either or both
    // yields a negative value, then the value is negated.
    //
    // Returned value is:
    //  0  both values were positive
    //  1  new a had to be negated
    //  2  new b had to be negated
    //  3  both new a and new b had to be negated
    //
    // Coefficients xa, xb, ya and yb may use the full signed 32-bit range.

    int32_t cca = 0;
    int32_t ccb = 0;
    for (size_t u = 0; u < len; u++) {
        int32_t wa = static_cast<int32_t>(a[u]);
        int32_t wb = static_cast<int32_t>(b[u]);
        int64_t za = static_cast<int64_t>(wa) * xa + static_cast<int64_t>(wb) * xb + cca;
        int64_t zb = static_cast<int64_t>(wa) * ya + static_cast<int64_t>(wb) * yb + ccb;
        if (u > 0) {
            a[u - 1] = static_cast<uint32_t>(za) & 0x7FFFFFFF;
            b[u - 1] = static_cast<uint32_t>(zb) & 0x7FFFFFFF;
        }
        uint32_t tta = static_cast<uint32_t>(static_cast<uint64_t>(za) >> 31);
        uint32_t ttb = static_cast<uint32_t>(static_cast<uint64_t>(zb) >> 31);
        cca = *reinterpret_cast<int32_t*>(&tta);
        ccb = *reinterpret_cast<int32_t*>(&ttb);
    }
    a[len - 1] = static_cast<uint32_t>(cca);
    b[len - 1] = static_cast<uint32_t>(ccb);
    int32_t r = 0;
    if (cca < 0) {
        uint32_t c = 1;
        for (size_t u = 0; u < len; u++) {
            uint32_t w = c + ~a[u];
            a[u] = w & 0x7FFFFFFF;
            c = (~w) >> 31;
        }
        r |= 1;
    }
    if (ccb < 0) {
        uint32_t c = 1;
        for (size_t u = 0; u < len; u++) {
            uint32_t w = c + ~b[u];
            b[u] = w & 0x7FFFFFFF;
            c = (~w) >> 31;
        }
        r |= 2;
    }

    return r;
}

void ntru::co_reduce_mod(uint32_t *a, uint32_t *b, const uint32_t *m, size_t len,
    uint32_t m0i, int32_t xa, int32_t xb, int32_t ya, int32_t yb)
{
    // These are actually four combined Montgomery multiplications.
    uint32_t fx = ((a[0] * static_cast<uint32_t>(xa) + b[0] * static_cast<uint32_t>(xb)) * m0i) & 0x7FFFFFFF;
    uint32_t fy = ((a[0] * static_cast<uint32_t>(ya) + b[0] * static_cast<uint32_t>(yb)) * m0i) & 0x7FFFFFFF;
    int64_t cca = 0;
    int64_t ccb = 0;
    for (size_t u = 0; u < len; u++) {
        uint32_t wa = a[u];
        uint32_t wb = b[u];
        int64_t za, zb;
        za = static_cast<int64_t>(wa) * static_cast<int64_t>(xa) +
             static_cast<int64_t>(wb) * static_cast<int64_t>(xb);
        zb = static_cast<int64_t>(wa) * static_cast<int64_t>(ya) +
             static_cast<int64_t>(wb) * static_cast<int64_t>(yb);
        za += cca;
        zb += ccb;
        za += static_cast<uint64_t>(m[u]) * static_cast<uint64_t>(fx);
        zb += static_cast<uint64_t>(m[u]) * static_cast<uint64_t>(fy);
        if (u > 0) {
            a[u - 1] = static_cast<uint32_t>(za) & 0x7FFFFFFF;
            b[u - 1] = static_cast<uint32_t>(zb) & 0x7FFFFFFF;
        }

        // Here we need to right shift 64-bit signed variable swith sign extension,
        // but the C++ standard defines sign extension of a signed right shift
        // as implementation dependant. So we need to detect this.
        //
        // We could to a pre-build test with CMake to set a compiler definition if sign
        // extension is supported, but that will be a last resort due to complexity.
        //
        // In C++17 I think we can do the following to easilyachieve this at compil-time:
        //     'if constexpr((int64_t(-1) >> 1) < 0)'
        //
        // But we're targeting C++11, so we rely on the compiler to optimise away a
        // conditional check
        if ((int64_t(-1) >> 1) < 0) {
            cca = za >> 31;
            ccb = zb >> 31;
        }
        else {
            uint64_t tta, ttb;
            tta = static_cast<uint64_t>(za) >> 31;
            ttb = static_cast<uint64_t>(zb) >> 31;
            tta = (tta ^ UINT64_C(0x100000000)) - UINT64_C(0x100000000);
            ttb = (ttb ^ UINT64_C(0x100000000)) - UINT64_C(0x100000000);
            cca = *reinterpret_cast<int64_t *>(&tta);
            ccb = *reinterpret_cast<int64_t *>(&ttb);
        }
    }
    a[len - 1] = static_cast<uint32_t>(cca) & 0x7FFFFFFF;
    b[len - 1] = static_cast<uint32_t>(ccb) & 0x7FFFFFFF;

    // For each value a and b:
    //  - if negative, add modulus
    //  - if positive and not lower than modulus, subtract modulus
    if (cca < 0) {
        ntru_number<uint32_t>::add(a, m, len);
    }
    else {
        if (ntru_number<uint32_t>::ucmp(a, m, len) >= 0) {
            ntru_number<uint32_t>::sub(a, m, len);
        }
    }
    if (ccb < 0) {
        ntru_number<uint32_t>::add(b, m, len);
    }
    else {
        if (ntru_number<uint32_t>::ucmp(b, m, len) >= 0) {
            ntru_number<uint32_t>::sub(b, m, len);
        }
    }
}

bool ntru::reduce(uint32_t *a, const uint32_t *b, size_t len, int32_t k)
{
    int32_t cc = 0;
    for (size_t u = 0; u < len; u++) {
        int32_t wa = static_cast<int32_t>(a[u]);
        int32_t wb = static_cast<int32_t>(b[u]);
        int64_t z  = static_cast<int64_t>(wb) * k + static_cast<int64_t>(wa) + cc;
        if (u > 0) {
            a[u - 1] = static_cast<uint32_t>(z) & 0x7FFFFFFF;
        }
        uint32_t tt = static_cast<uint32_t>(static_cast<uint64_t>(z) >> 31);
        cc = static_cast<int32_t>(tt);
    }
    a[len - 1] = static_cast<uint32_t>(cc);
    if (cc < 0) {
        uint32_t c = 1;
        for (size_t u = 0; u < len; u++) {
            uint32_t w = c + ~a[u];
            a[u] = w & 0x7FFFFFFF;
            c = (~w) >> 31;
        }
        return true;
    }
    else {
        return false;
    }
}

void ntru::reduce_mod(uint32_t *a, const uint32_t *b, const uint32_t *m,
    size_t len, uint32_t m0i, int32_t k)
{
    uint32_t f  = ((a[0] + b[0] * static_cast<uint32_t>(k)) * m0i) & 0x7FFFFFFF;
    int32_t  cc = 0;
    for (size_t u = 0; u < len; u++) {
        uint32_t wa = a[u];
        uint32_t wb = b[u];
        int64_t z;
        z  = static_cast<int64_t>(wa) + static_cast<int64_t>(wb) * static_cast<int64_t>(k);
        z += cc;
        z += static_cast<uint64_t>(m[u]) * static_cast<uint64_t>(f);
        if (u > 0) {
            a[u - 1] = static_cast<uint32_t>(z) & 0x7FFFFFFF;
        }
        uint32_t tt = static_cast<uint32_t>(static_cast<uint64_t>(z) >> 31);
        cc = *reinterpret_cast<int32_t *>(&tt);
    }
    a[len - 1] = (uint32_t)cc & 0x7FFFFFFF;

    // If negative, add modulus
    // If positive and not lower than modulus, subtract modulus
    if (cc < 0) {
        ntru_number<uint32_t>::add(a, m, len);
    }
    else {
        if (ntru_number<uint32_t>::ucmp(a, m, len) >= 0) {
            ntru_number<uint32_t>::sub(a, m, len);
        }
    }
}

uint32_t ntru::signed_bit_length(const uint32_t *x, size_t xlen)
{
    if (0 == xlen) {
        return 0;
    }
    uint32_t sign = (-(x[xlen - 1] >> 30)) >> 1;
    while (xlen > 0) {
        if (x[xlen - 1] != sign) {
            break;
        }
        xlen--;
    }
    if (0 == xlen) {
        return 0;
    }
    return static_cast<uint32_t>(xlen - 1) * 31 + core::bit_manipulation::bitlength(x[xlen - 1] ^ sign);
}

int64_t ntru::get_top(const uint32_t *x, size_t xlen, uint32_t sc)
{
    if (0 == xlen) {
        return 0;
    }

    // The "sign word" is -1 for negative values, 0 for positive values.
    uint32_t sign = -(x[xlen - 1] >> 30);

    uint32_t k    = sc / 31;
    uint32_t off  = sc - (31 * k);

    uint32_t w0, w1, w2;

    // To obtain 63 bits, we always need exactly three words.
    if ((k + 2) < xlen) {
        w0 = x[k + 0];
        w1 = x[k + 1];
        w2 = x[k + 2] | (sign << 31);
    }
    else if ((k + 1) < xlen) {
        w0 = x[k + 0];
        w1 = x[k + 1];
        w2 = sign;
    }
    else if (k < xlen) {
        w0 = x[k + 0];
        w1 = sign;
        w2 = sign;
    }
    else {
        w0 = sign;
        w1 = sign;
        w2 = sign;
    }
    uint64_t z = (static_cast<uint64_t>(w0) >> (     off)) |    // NOLINT
                 (static_cast<uint64_t>(w1) << (31 - off)) |
                 (static_cast<uint64_t>(w2) << (62 - off));

    // Properties of the exact-width types (no padding, no trap
    // representation, two's complement representation) means that
    // we can use a cast on the in-memory representation to
    // convert from unsigned to signed values, without incurring
    // any undefined behaviour.
    return *reinterpret_cast<int64_t *>(&z);
}

void ntru::add_scaled_mul_small(uint32_t* x, size_t xlen,
    const uint32_t* y, size_t ylen, int32_t k,
    uint32_t sch, uint32_t scl)
{
    // Add k*y*2^sc to x. The result is assumed to fit in the array of
    // size xlen (truncation is applied if necessary).
    // Scale factor 'sc' is provided as sch and scl, such that:
    //   sch = sc / 31
    //   scl = sc % 31
    // xlen MUST NOT be lower than ylen.
    //
    // x[] and y[] are both signed integers, using two's complement for
    // negative values.

    if (0 == ylen) {
        return;
    }

    uint32_t ysign = -(y[ylen - 1] >> 30) >> 1;
    uint32_t tw = 0;
    int32_t  cc = 0;
    for (size_t u = sch; u < xlen; u++) {
        // Get the next word of y (scaled).
        size_t   v   = u - sch;
        uint32_t wy  = v < ylen ? y[v] : ysign;
        uint32_t wys = ((wy << scl) & 0x7FFFFFFF) | tw;
        tw  = wy >> (31 - scl);

        // The expression below does not overflow.
        uint64_t z = static_cast<int64_t>(wys) * static_cast<int64_t>(k) + static_cast<int64_t>(x[u]) + cc;
        x[u] = static_cast<uint32_t>(z) & 0x7FFFFFFF;

        // Right-shifting the signed value z would yield
        // implementation-defined results (arithmetic shift is
        // not guaranteed). However, we can cast to unsigned,
        // and get the next carry as an unsigned word. We can
        // then convert it back to signed by using the guaranteed
        // fact that 'int32_t' uses two's complement with no
        // trap representation or padding bit, and with a layout
        // compatible with that of 'uint32_t'.
        uint32_t ccu = static_cast<uint32_t>(z >> 31);
        cc = static_cast<int32_t>(ccu);
    }
}

void ntru::sub_scaled(uint32_t* x, size_t xlen,
    const uint32_t* y, size_t ylen, uint32_t sch, uint32_t scl)
{
    // Subtract y*2^sc from x. The result is assumed to fit in the array of
    // size xlen (truncation is applied if necessary).
    // Scale factor 'sc' is provided as sch and scl, such that:
    //   sch = sc / 31
    //   scl = sc % 31
    // xlen MUST NOT be lower than ylen.
    //
    // x[] and y[] are both signed integers, using two's complement for
    // negative values.

    if (0 == ylen) {
        return;
    }

    uint32_t ysign = -(y[ylen - 1] >> 30) >> 1;
    uint32_t tw = 0;
    uint32_t cc = 0;
    for (size_t u = sch; u < xlen; u++) {
        // Get the next word of y (scaled).
        size_t v = u - sch;
        uint32_t wy = v < ylen ? y[v] : ysign;
        uint32_t wys = ((wy << scl) & 0x7FFFFFFF) | tw;
        tw = wy >> (31 - scl);

        uint32_t w = x[u] - wys - cc;
        x[u] = w & 0x7FFFFFFF;
        cc = w >> 31;
    }
}


static inline uint32_t modp_set(int32_t x, uint32_t p)
{
    uint32_t w;
    w  = static_cast<uint32_t>(x);
    w += p & -(w >> 31);
    return w;
}

static inline int32_t modp_norm(uint32_t x, uint32_t p)
{
    return static_cast<int32_t>(x - (p & (((x - ((p + 1) >> 1)) >> 31) - 1)));
}

static inline int64_t const_time_rint(double x)
{
    // We do not want to use llrint() since it might be not
    // constant-time.
    //
    // Suppose that x >= 0. If x >= 2^52, then it is already an
    // integer. Otherwise, if x < 2^52, then computing x+2^52 will
    // yield a value that will be rounded to the nearest integer
    // with exactly the right rules (round-to-nearest-even).
    //
    // In order to have constant-time processing, we must do the
    // computation for both x >= 0 and x < 0 cases, and use a
    // cast to an integer to access the sign and select the proper
    // value. Such casts also allow us to find out if |x| < 2^52.

    int64_t sx = static_cast<int64_t>(x - 1.0);
    int64_t tx = static_cast<int64_t>(x);
    int64_t rp = static_cast<int64_t>(x + 4503599627370496.0) - 4503599627370496;
    int64_t rn = static_cast<int64_t>(x - 4503599627370496.0) + 4503599627370496;

    // If tx >= 2^52 or tx < -2^52, then result is tx.
    // Otherwise, if sx >= 0, then result is rp.
    // Otherwise, result is rn. We use the fact that when x is
    // close to 0 (|x| <= 0.25) then both rp and rn are correct;
    // and if x is not close to 0, then trunc(x-1.0) yields the
    // appropriate sign.

    // Clamp rn to zero if sx >= 0
    // Clamp rp to zero if sx < 0
    int64_t m = static_cast<uint64_t>(sx) >> 63;
    rn &= m;
    rp &= ~m;

    // Get the 12 upper bits of tx; if they are not all zeros or
    // all ones, then tx >= 2^52 or tx < -2^52, and we clamp both
    // rp and rn to zero. Otherwise, we clamp tx to zero.
    uint32_t ub = static_cast<uint32_t>(static_cast<uint64_t>(tx) >> 52);
    m = -static_cast<int64_t>((((ub + 1) & 0xFFF) - 2) >> 31);
    rp &= m;
    rn &= m;
    tx &= ~m;

    // Only one of tx, rn or rp (at most) can be non-zero
    return tx | rn | rp;
}

bool ntru::solve_intermediate(const int32_t *f, const int32_t *g, size_t depth)
{
    // Set a pointer to the array of precomputed small prime numbers
    const core::small_prime *primes = core::small_primes_u31;

    // In this function, 'logn' is the log2 of the degree for this step.
    // If N = 2^logn, then:
    //  - the F and G values in m_tmp (from the deeper levels) have degree N/2
    //  - this method returns F and G of degree N
    size_t logn_top = m_logn;
    size_t logn = logn_top - depth;

    // In the ternary case _and_ top-level, n is a multiple of 3,
    // and hn = n/3. Otherwise, n is a power of 2, and hn = n/2.
    size_t n    = static_cast<size_t>(1) << logn;
    size_t hn   = n >> 1;

    // slen = size for our input f and g, and the reduced output F and G (degree N)
    size_t slen = core::max_bl_small2[depth];

    // dlen = size of the F and G obtained from the deeper level (degree N/2)
    size_t dlen = core::max_bl_small2[depth + 1];

    // llen = size for intermediary F and G before reduction (degree N)
    size_t llen = core::max_bl_large2[depth];

    // We build our non-reduced F and G as two independent halves each,
    // of degree N/2 (F = F0 + X*F1, G = G0 + X*G1)

    // Fd and Gd are the F and G from the deeper level
    uint32_t* Fd   = m_tmp;
    uint32_t* Gd   = Fd + dlen * hn;

    // Compute the input f and g for this level in RNS + NTT representation
    uint32_t* ft   = Gd + dlen * hn;
    gen_rns_fg(ft, f, g, logn_top, depth, true);

    // Move the newly computed f and g to make room for the candidate
    // F and G (unreduced)
    uint32_t* Ft   = m_tmp;
    uint32_t* Gt   = Ft + n * llen;
    uint32_t* t1   = Gt + n * llen;
    memmove(t1, ft, 2 * n * slen * sizeof *ft);
    ft   = t1;
    uint32_t* gt   = ft + slen * n;
    t1   = gt + slen * n;

    // Move Fd and Gd immediately after f and g
    memmove(t1, Fd, 2 * hn * dlen * sizeof *Fd);
    Fd   = t1;
    Gd   = Fd + hn * dlen;

    // Reduce Fd and Gd modulo 'llen' small primes, and store the values
    // in Ft and Gt (n/2 values in each)
    for (size_t u = 0; u < llen; u++) {
        uint32_t p   = primes[u].p;
        uint32_t p0i = core::number<uint32_t>::uninv_minus1(p);
        uint32_t R   = mont_red::gen_R(p, 31);
        uint32_t R2  = mont_red::gen_R2(p, p0i, 31);
        uint32_t Rx  = mont_red::gen_Rx(dlen, p, p0i, R, R2, 31);
        mont_red red(p, p0i, 31, R, R2);
        ntru_red mont(red);

        uint32_t* xs = Fd;
        uint32_t* ys = Gd;
        uint32_t* xd = Ft + u;
        uint32_t* yd = Gt + u;
        for (size_t v = 0; v < hn; v++) {
            *xd = ntru_number<uint32_t>::mod_small_signed(xs, dlen, R2, mont, Rx);
            *yd = ntru_number<uint32_t>::mod_small_signed(ys, dlen, R2, mont, Rx);

            xs += dlen;
            ys += dlen;
            xd += llen;
            yd += llen;
        }
    }

    // Compute F and G modulo sufficiently many small primes
    //
    // General case:
    //
    //   we divide degree by d = 2
    //   f'(x^d) = N(f)(x^d) = f * adj(f)
    //   g'(x^d) = N(g)(x^d) = g * adj(g)
    //   f'*G' - g'*F' = q
    //   F = F'(x^d) * adj(g)
    //   G = G'(x^d) * adj(f)
    //
    for (size_t u = 0; u < llen; u++) {

        // All computations are done modulo p
        uint32_t p   = primes[u].p;
        uint32_t p0i = core::number<uint32_t>::uninv_minus1(p);
        uint32_t R   = mont_red::gen_R(p, 31);
        uint32_t R2  = mont_red::gen_R2(p, p0i, 31);
        mont_red red(p, p0i, 31, R, R2);
        ntru_red mont(red);
        uint32_t gen = calc_gen_from_g1024(mont, primes[u].g, logn);
        ntru_ntt transform(mont, gen, n);

        // If we have processed slen words, then f and g have been de-NTTized,
        // and are now in RNS representation only - so they are rebuilt.
        if (u == slen) {
            rebuild_CRT(ft, slen, slen, n, primes, true, t1);
            rebuild_CRT(gt, slen, slen, n, primes, true, t1);
        }

        // Temporary pointers are created after leaving 2*n space for x and y
        uint32_t* fx = t1 + 2 * n;
        uint32_t* gx = fx + n;

        // If we haven't processed slen words yet, then ft and gt are de-NTTized
        // after being copied to fx and gx respectively
        // Otherwise, ft and gt are reduced modulo a small prime
        if (u < slen) {
            uint32_t* x = ft + u;
            uint32_t* y = gt + u;
            for (size_t v = 0; v < n; v++) {
                fx[v] = *x;
                gx[v] = *y;
                x += slen;
                y += slen;
            }
            transform.inv(ft + u, logn, slen);
            transform.inv(gt + u, logn, slen);
        }
        else {
            // Rx = 2^slen mod p
            uint32_t Rx = mont_red::gen_Rx(slen, p, p0i, R, R2, 31);

            uint32_t* x = ft;
            uint32_t* y = gt;
            for (size_t v = 0; v < n; v++) {
                fx[v] = ntru_number<uint32_t>::mod_small_signed(x, slen, R2, mont, Rx);
                gx[v] = ntru_number<uint32_t>::mod_small_signed(y, slen, R2, mont, Rx);
                x += slen;
                y += slen;
            }
            transform.fwd(fx, logn);
            transform.fwd(gx, logn);
        }

        // Compute F' and G' modulo p and in NTT representation (they have degree n/2).
        // These values were computed previously, and are stored in Ft and Gt.
        uint32_t* Fp = gx + n;
        uint32_t* Gp = Fp + hn;
        uint32_t* x = Ft + u;
        uint32_t* y = Gt + u;
        for (size_t v = 0; v < hn; v++) {
            Fp[v] = *x;
            Gp[v] = *y;
            x += llen;
            y += llen;
        }
        transform.fwd(Fp, logn - 1, 1);
        transform.fwd(Gp, logn - 1, 1);

        // Compute F and G for the current small prime.
        x = Ft + u;
        y = Gt + u;
        for (size_t v = 0; v < hn; v++) {
            uint32_t ftA = fx[(v << 1) + 0];
            uint32_t ftB = fx[(v << 1) + 1];
            uint32_t gtA = gx[(v << 1) + 0];
            uint32_t gtB = gx[(v << 1) + 1];
            uint32_t mFp = mont.mul(Fp[v], R2);
            uint32_t mGp = mont.mul(Gp[v], R2);
            x[0]    = mont.mul(gtB, mFp);
            x[llen] = mont.mul(gtA, mFp);
            y[0]    = mont.mul(ftB, mGp);
            y[llen] = mont.mul(ftA, mGp);
            x += (llen << 1);
            y += (llen << 1);
        }
        transform.inv(Ft + u, logn, llen);
        transform.inv(Gt + u, logn, llen);
    }

    // Rebuild F and G with the CRT from many small primes to big numbers
    rebuild_CRT(Ft, llen, llen, n, primes, 1, t1);
    rebuild_CRT(Gt, llen, llen, n, primes, 1, t1);

    // At this point, Ft, Gt, ft and gt are consecutive in RAM (in that order)
    //
    // Apply Babai reduction to bring back F and G to size slen.
    //
    // We use the FFT to compute successive approximations of the reduction
    // coefficient. We first isolate the top bits of the coefficients of f and g,
    // and convert them to floating point; with the FFT, we compute adj(f), adj(g),
    // and 1/(f*adj(f)+g*adj(g)).
    //
    // Then, repeatedly apply the following:
    //
    //   - Get the top bits of the coefficients of F and G into floating point, and
    //     use the FFT to compute:
    //        (F*adj(f)+G*adj(g))/(f*adj(f)+g*adj(g))
    //
    //   - Convert back that value into normal representation, and round it to the
    //     nearest integers, yielding a polynomial k. Proper scaling is applied to
    //     f, g, F and G so that the coefficients fit on 32 bits (signed).
    //
    //   - Subtract k*f from F and k*g from G.
    //
    // This process will reduce the bit lengths of F and G from llen to slen words
    // at most.
    //
    // Memory layout:
    //  - We need to compute and keep adj(f), adj(g), and 1/(f*adj(f)+g*adj(g))
    //    (sizes N, N and N/2 fp numbers, respectively).
    //  - At each iteration we need two extra fp buffers (N fp values), and produce
    //    a k (N 32-bit words). k will be shared with one of the fp buffers.
    //  - To compute k*f and k*g efficiently (with the NTT), we need some extra room,
    //    we reuse the space of the temporary buffers.
    //
    // 'double' arrays are obtained from the temporary array itself. The base is at
    // a properly aligned offset.

    double*  rt3 = align_ptr<double>(m_tmp, t1);
    double*  rt4 = rt3 + n;
    double*  rt5 = rt4 + n;
    double*  rt1 = rt5 + (n >> 1);
    int32_t* k   = reinterpret_cast<int32_t*>(align_ptr<uint32_t>(m_tmp, rt1));
    double*  rt2 = align_ptr<double>(m_tmp, k + n);
    if (rt2 < (rt1 + n)) {
        rt2 = rt1 + n;
    }
    t1  = reinterpret_cast<uint32_t*>(k) + n;

    // Get the maximum bit lengths of f and g. f and g are scaled down by maxbl_fg bits,
    // so that values will be below 1
    uint32_t maxbl_f  = poly_max_bitlength(ft, slen, slen, logn);
    uint32_t maxbl_g  = poly_max_bitlength(gt, slen, slen, logn);
    uint32_t maxbl_fg = maxbl_f < maxbl_g ? maxbl_g : maxbl_f;

    // Pre-compute 1/(f*adj(f)+g*adj(g)) in store in rt5
    poly_big_to_fp(rt3, ft, slen, slen, logn, maxbl_fg, maxbl_fg);
    poly_big_to_fp(rt4, gt, slen, slen, logn, maxbl_fg, maxbl_fg);
    std::shared_ptr<fft<double>> fft_babai = std::shared_ptr<fft<double>>(fft_factory<double>::create(logn));
    fft_babai->fwd(rt3);
    fft_babai->fwd(rt4);
    fft_poly<double>::invnorm2(rt5, rt3, rt4, logn);

    // Store adj(f) and adj(g) in rt3 and rt4
    fft_poly<double>::adjoint(rt3, logn);
    fft_poly<double>::adjoint(rt4, logn);

    // Reduce F and G repeatedly until it can no longer be done
    uint32_t maxbl_FG      = 0xFFFFFFFF;
    uint32_t prev_maxbl_FG = 0xFFFFFFFF;
    size_t FGlen = llen;
    for (;;) {
        // Get current maximum bit length of F and G. Adjust the word length accordingly
        // (keeping extra bits for intermediate computation)
        uint32_t maxbl_F  = poly_max_bitlength(Ft, FGlen, llen, logn);
        uint32_t maxbl_G  = poly_max_bitlength(Gt, FGlen, llen, logn);
        maxbl_FG = (maxbl_F < maxbl_G)? maxbl_G : maxbl_F;
        while ((FGlen * 31) >= (maxbl_FG + 43)) {
            FGlen--;
        }

        // We stop when F and G have been made smaller than f and g, or when the last
        // reduction round did not manage to reduce the maximum bit length
        if (maxbl_FG <= maxbl_fg || maxbl_FG >= prev_maxbl_FG) {
            break;
        }
        prev_maxbl_FG = maxbl_FG;

        // We aim at getting the coefficients of k into 30 bits - the will be scaled
        // down afterwards if required
        uint32_t scale_FG = maxbl_FG < 30 ? 0 : maxbl_FG - 30;
        poly_big_to_fp(rt1, Ft, FGlen, llen, logn, maxbl_FG, scale_FG);
        poly_big_to_fp(rt2, Gt, FGlen, llen, logn, maxbl_FG, scale_FG);

        // Compute the coefficients of k using the precomputed 1/(f*adj(f)+g*adj(g)),
        // adj(f) and adj(g) and the floating-point representation of the coefficients
        // in the FFT domain
        fft_babai->fwd(rt1);
        fft_babai->fwd(rt2);
        fft_poly<double>::mul(rt1, rt3, logn);
        fft_poly<double>::mul(rt2, rt4, logn);
        core::poly<double>::add_inplace(rt2, n, rt1);
        fft_poly<double>::mul_auto_adjoint(rt2, rt5, logn);
        fft_babai->inv(rt2);

        // Get the maximum coefficient of k, then adjust scaling so they all fit on 31 bits
        uint64_t max_kx = 0;
        for (size_t u = 0; u < n; u++) {
            int64_t kx   = const_time_rint(rt2[u]);
            int64_t sign = const_time<int64_t>::if_negative(-kx,  1) |
                           const_time<int64_t>::if_negative(+kx, -1);
            kx *= sign;
            uint64_t cond = const_time<uint64_t>::if_lte(kx, max_kx, UINT64_C(-1));
            max_kx = (~cond & kx) | (cond & max_kx);
        }
        if (max_kx >= (UINT64_C(1) << 62)) {
            return false;
        }
        uint32_t scale_k = core::bit_manipulation::bitlength(static_cast<uint32_t>(max_kx >> 31));

        // We need to scale down k by at least scale_k bits. The final scale will be:
        //
        //     scale_FG + scale_k - maxbl_fg;
        //
        // we also need this value to be non-negative.
        if (scale_k + scale_FG < maxbl_fg) {
            scale_k = maxbl_fg - scale_FG;
            if (scale_k > 62) {
                break;
            }
        }

        // Compute the final scale
        uint32_t final_scale = scale_FG + scale_k - maxbl_fg;

        // Get the coefficients of k as int32_t
        for (size_t u = 0; u < n; u++) {
            int64_t kx   = const_time_rint(rt2[u]);
            int64_t sign = const_time<int64_t>::if_negative(-kx,  1) |
                           const_time<int64_t>::if_negative(+kx, -1);
            kx *= sign;
            int32_t ks = static_cast<int32_t>(kx >> scale_k);
            ks *= sign;
            k[u] = ks;
        }

        // Minimal recursion depth at which we rebuild intermediate values
        // when reconstructing f and g
        #define DEPTH_INT_FG   4

        // If we are at low depth, then we use the NTT to compute k*f and k*g.
        if (depth <= DEPTH_INT_FG) {
            poly_sub_scaled_ntt(Ft, FGlen, llen, ft, slen, slen,
                k, final_scale, logn, t1);
            poly_sub_scaled_ntt(Gt, FGlen, llen, gt, slen, slen,
                k, final_scale, logn, t1);
        }
        else {
            poly_sub_scaled(Ft, FGlen, llen, ft, slen, slen,
                k, final_scale, logn);
            poly_sub_scaled(Gt, FGlen, llen, gt, slen, slen,
                k, final_scale, logn);
        }
    }

    // If we could not reduce F and G so that they fit in slen, then this is a failure
    if (maxbl_FG > (slen * 31)) {
        return false;
    }

    // Compress all output values into slen words
    uint32_t* x = m_tmp;
    uint32_t* y = m_tmp;
    for (size_t u = 0; u < (n << 1); u++) {
        memmove(x, y, slen * sizeof *y);
        x += slen;
        y += llen;
    }

    // Ensure that f and g are sign extended
    if (FGlen < slen) {
        x = m_tmp;
        for (size_t u = 0; u < (n << 1); u++) {
            uint32_t sign = -(x[FGlen - 1] >> 30) >> 1;
            for (size_t v = FGlen; v < slen; v++) {
                x[v] = sign;
            }

            x += slen;
        }
    }

    return true;
}

uint32_t ntru::calc_gen_from_g1024(const ntru_red& mont, uint32_t g, size_t logn)
{
    g = mont.convert_to(g);
    for (size_t k = logn; k < 10; k++) {
        g = mont.mul(g, g);
    }
    g = mont.convert_from(g);
    return g;
}

void ntru::gen_rns_fg(uint32_t *t, const int32_t *f, const int32_t *g,
    size_t logn, size_t depth, bool ntt_flag)
{
    const core::small_prime *primes = core::small_primes_u31;

    size_t    n  = 1 << logn;
    uint32_t *ft = t;
    uint32_t *gt = ft + n;
    uint32_t  p0 = primes[0].p;
    for (size_t u = 0; u < n; u++) {
        ft[u] = static_cast<uint32_t>(f[u]) + (p0 & -(static_cast<uint32_t>(f[u]) >> 31));
        gt[u] = static_cast<uint32_t>(g[u]) + (p0 & -(static_cast<uint32_t>(g[u]) >> 31));
    }

    if (0 == depth && ntt_flag) {
        mont_red red(primes[0].p, 31);
        ntru_red mont(red);
        uint32_t g   = calc_gen_from_g1024(mont, primes[0].g, logn);
        ntru_ntt transform(mont, g, n);

        transform.fwd(ft, logn);
        transform.fwd(gt, logn);

        return;
    }

    for (size_t d = 0; d < depth; d++) {
        gen_rns_fg_step(t, logn - d, d, d != 0, (d + 1) < depth || ntt_flag);
    }
}

void ntru::crt_extract(ntru_ntt* transform, const ntru_red& mont, size_t n, size_t logn,
    bool ntt_flag, uint32_t R2, size_t slen, size_t tlen,
    uint32_t* t1, uint32_t* src, uint32_t* dst)
{
    size_t    hn = n >> 1;
    uint32_t* x;

    x = src;
    for (size_t v = 0; v < n; v++) {
        t1[v] = *x;
        x += slen;
    }

    if (ntt_flag) {
        transform->fwd(t1, logn);
    }

    x = dst;
    for (size_t v = 0; v < hn; v++) {
        uint32_t w0 = t1[(v << 1) + 0];
        uint32_t w1 = t1[(v << 1) + 1];
        *x = mont.mul(mont.mul(w0, w1), R2);
        x += tlen;
    }
}

void ntru::crt_mod_extract(ntru_ntt* transform, const ntru_red& mont, size_t n, size_t logn,
    uint32_t R2, uint32_t Rx, size_t slen, size_t tlen,
    uint32_t* t1, uint32_t* src, uint32_t* dst)
{
    size_t hn = n >> 1;

    uint32_t* x = src;
    for (size_t v = 0; v < n; v++) {
        t1[v] = ntru_number<uint32_t>::mod_small_signed(x, slen, R2, mont, Rx);
        x += slen;
    }

    transform->fwd(t1, logn);

    x = dst;
    for (size_t v = 0; v < hn; v++) {
        uint32_t w0 = t1[(v << 1) + 0];
        uint32_t w1 = t1[(v << 1) + 1];
        *x = mont.mul(mont.mul(w0, w1), R2);
        x += tlen;
    }
}

void ntru::gen_rns_fg_step(uint32_t *data, size_t logn, size_t depth, bool in_ntt, int out_ntt)
{
    const core::small_prime *primes = core::small_primes_u31;

    size_t    n    = static_cast<size_t>(1) << logn;
    size_t    hn   = n >> 1;
    size_t    slen = core::max_bl_small2[depth];
    size_t    tlen = core::max_bl_small2[depth + 1];

    // Prepare room for the result.
    uint32_t* fd   = data;
    uint32_t* gd   = fd + hn * tlen;
    uint32_t* fs   = gd + hn * tlen;
    uint32_t* gs   = fs + n * slen;
    uint32_t* gm   = gs + n * slen;
    uint32_t* igm  = gm + n;
    uint32_t* t1   = igm + n;
    memmove(fs, data, 2 * n * slen * sizeof(uint32_t));

    // First slen words: we use the input values directly, and apply
    // inverse NTT as we go.
    for (size_t u = 0; u < slen; u++) {

        mont_red red(primes[u].p, 31);
        ntru_red mont(red);
        uint32_t g = calc_gen_from_g1024(mont, primes[u].g, logn);
        ntru_ntt transform(mont, g, n);

        // Copy fs and gs (offset by u) with stride slen to temporary array t1, which is NTT'd if necessary,
        // and the product of the odd and even coefficients are computed to form fd and gd respectively
        crt_extract(&transform, mont, n, logn, !in_ntt, red.get_R2(), slen, tlen, t1, fs + u, fd + u);
        crt_extract(&transform, mont, n, logn, !in_ntt, red.get_R2(), slen, tlen, t1, gs + u, gd + u);

        // If necessary de-NTTize fs and gs
        if (in_ntt) {
            transform.inv(fs + u, logn, slen);
            transform.inv(gs + u, logn, slen);
        }

        // If necessary, de-NTTize fd and gd which are halved in length and have stride tlen
        if (!out_ntt) {
            transform.inv(fd + u, logn - 1, tlen);
            transform.inv(gd + u, logn - 1, tlen);
        }
    }

    // Since the fs and gs words have been de-NTTized, we can use the
    // CRT to rebuild the values.
    rebuild_CRT(fs, slen, slen, n, primes, true, gm);
    rebuild_CRT(gs, slen, slen, n, primes, true, gm);

    // Remaining words: use modular reductions to extract the values.
    for (size_t u = slen; u < tlen; u++) {

        uint32_t p   = primes[u].p;
        uint32_t p0i = core::number<uint32_t>::uninv_minus1(p);
        uint32_t R   = mont_red::gen_R(p, 31);
        uint32_t R2  = mont_red::gen_R2(p, p0i, 31);
        mont_red red(p, p0i, 31, R, R2);
        ntru_red mont(red);

        uint32_t g   = calc_gen_from_g1024(mont, primes[u].g, logn);
        ntru_ntt transform(mont, g, n);  // NOLINT
        uint32_t Rx  = mont_red::gen_Rx(slen, p, p0i, R, R2, 31);

        crt_mod_extract(&transform, mont, n, logn, R2, Rx, slen, tlen, t1, fs, fd + u);
        crt_mod_extract(&transform, mont, n, logn, R2, Rx, slen, tlen, t1, gs, gd + u);

        if (!out_ntt) {
            transform.inv(fd + u, logn - 1, tlen);
            transform.inv(gd + u, logn - 1, tlen);
        }
    }
}

}  // namespace ntru
}  // namespace phantom
