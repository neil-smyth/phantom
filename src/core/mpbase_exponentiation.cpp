/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "core/mpbase.hpp"


/// Obtain a specificbit from an array oflimbs
#define GETBIT(p, bi) ((p[(bi - 1) / std::numeric_limits<T>::digits] >> (bi - 1) % std::numeric_limits<T>::digits) & 1)

/// The thresholld at which a single word multiplicative inverse is used for Montgomery reduction
#define REDC_1_TO_REDC_N_THRESHOLD            50

/// The threshold at which gradeschool squaring is optimalforMontgomery reduction
#define REDC_SQR_BASECASE_THRESHOLD           0


namespace phantom {
namespace core {


template<typename T>
using pow_redc_mul = void (*)(T*, T*, T*, size_t);

template<typename T>
using pow_redc_sqr = void (*)(T*, T*, size_t);

template<typename T>
using pow_redc_reduce = void (*)(T*, T*, const T*, size_t, const T*);


template<typename T>
void redc_mul_1(T* r, T* a, T* b, size_t n)
{
    (void) n;
    number<T>::umul(&r[1], &r[0], *a, *b);
}

template<typename T>
void redc_mul_gradeschool(T* r, T* a, T* b, size_t n)
{
    mpbase<T>::mul_gradeschool(r, a, n, b, n);
}

template<typename T>
void redc_mul_n(T* r, T* a, T* b, size_t n)
{
    mpbase<T>::mul_n(r, a, b, n);
}

template<typename T>
void redc_sqr_1(T* r, T* a, size_t n)
{
    (void) n;
    number<T>::umul(&r[1], &r[0], *a, *a);
}

template<typename T>
void redc_sqr_gradeschool(T* r, T* a, size_t n)
{
    mpbase<T>::mul_gradeschool(r, a, n, a, n);
}

template<typename T>
void redc_sqr_n(T* r, T* a, size_t n)
{
    mpbase<T>::sqr(r, a, n);
}

template<typename T>
void redc_reduce(T* r, T* t, const T* m, const T invm)
{
    T p1, r0, u0, dummy;

    u0 = *t;
    number<T>::umul(&p1, &dummy, *m, (u0 * invm) & LIMB_MASK);
    assert(((u0 + dummy) & LIMB_MASK) == 0);
    p1 += (u0 != 0);
    r0 = t[1] + p1;
    if (p1 > r0) {
        r0 -= *m;
    }
    *r = r0;
}

template<typename T>
void redc_reduce_0(T* r, T* t, const T* m, size_t n, const T* invm)
{
    (void) n;
    redc_reduce(r, t, m, invm[0]);
}

template<typename T>
void redc_reduce_1(T* r, T* t, const T* m, size_t n, const T* invm)
{
    mpbase<T>::redc_1_fix(r, t, m, n, invm[0]);
}

template<typename T>
void redc_reduce_n(T* r, T* t, const T* m, size_t n, const T* invm)
{
    mpbase<T>::redc_n(r, t, m, n, invm);
}

template<typename T>
bool powm_innerloop(T* r_limbs, const T* ep, int& ebi, int windowsize, int& this_windowsize,
    int& cnt, T& expbits, size_t n, T* tp, const T* mp, const T* mip, T* pp,
    pow_redc_mul<T> mul, pow_redc_sqr<T> sqr, pow_redc_reduce<T> reduce)
{
    while (ebi != 0) {
        while (GETBIT(ep, ebi) == 0) {
            sqr(tp, r_limbs, n);
            reduce(r_limbs, tp, mp, n, mip);
            ebi--;
            if (ebi == 0)
                return false;
        }

        // The next bit of the exponent is 1.  Now extract the largest block of
        // bits <= windowsize, and such that the least significant bit is 1
        expbits = mpbase<T>::getbits(ep, ebi, windowsize);
        this_windowsize = windowsize;
        if (ebi < windowsize) {
            this_windowsize -= windowsize - ebi;
            ebi = 0;
        }
        else {
            ebi -= windowsize;
        }

        cnt = bit_manipulation::ctz(expbits);
        this_windowsize -= cnt;
        ebi += cnt;
        expbits >>= cnt;

        do {
            sqr(tp, r_limbs, n);
            reduce(r_limbs, tp, mp, n, mip);
            this_windowsize--;
        } while (this_windowsize != 0);

        mul(tp, r_limbs, pp + n * (expbits >> 1), n);
        reduce(r_limbs, tp, mp, n, mip);
    }

    return true;
}

/**
 * Compute the length of an array in a specific base
 * @param ptr Input data array
 * @param n Length of the data arrays
 * @param base2exp 2 to the power of the base to be examined
 * @return Length in chosen base
 */
template<typename T>
size_t sizeinbase_2exp(const T* in, size_t n, size_t base2exp)
{
    assert(n > 0);
    assert(in[n-1] != 0);
    T cnt = bit_manipulation::clz(in[n - 1]);
    size_t totbits = n * std::numeric_limits<T>::digits - cnt;
    return (totbits + base2exp - 1) / base2exp;
}

/**
 * Window size in the selected base
 * @param eb Array length in a specified base
 * @return Length in chosen base
 */
template<typename T>
size_t win_size(size_t eb)
{
    static size_t x[] = {1, 7, 25, 81, 241, 673, 1793, 4609, 11521, 28161, ~static_cast<size_t>(0)};
    assert(eb > 1);
    size_t k;
    for (k = 1; eb > x[k]; k++) {}
    return k;
}

template<typename T>
void mpbase<T>::powm(T* r_limbs, const T* b_limbs, size_t bn, const T* ep, size_t en, const T* mp, size_t n, T* tp)
{
    T i_limbs[2], *mip;
    int cnt;
    int this_windowsize;
    T expbits;
    T* pp, *this_pp;
    size_t i;

    assert(en > 1 || (en == 1 && ep[0] > 1));
    assert(n >= 1 && ((mp[0] & 1) != 0));

    int ebi = sizeinbase_2exp<T>(ep, en, 1);
    int windowsize = win_size<T>(ebi);

    if (BELOW_THRESHOLD(n, REDC_1_TO_REDC_N_THRESHOLD)) {
        mip = i_limbs;
        mip[0] = -binvert_limb(mp[0]);
    }
    else {
        mip = reinterpret_cast<T*>(aligned_malloc(n * sizeof(T)));
        binvert(mip, mp, n, tp);
    }

    pp = reinterpret_cast<T*>(aligned_malloc((n << (windowsize - 1)) * sizeof(T)));

    this_pp = pp;
    redcify(this_pp, b_limbs, bn, mp, n);

    // Store b^2 at r_limbs
    sqr(tp, this_pp, n);
    if (BELOW_THRESHOLD (n, REDC_1_TO_REDC_N_THRESHOLD))
        redc_1_fix(r_limbs, tp, mp, n, mip[0]);
    else
        redc_n(r_limbs, tp, mp, n, mip);

    // Precompute odd powers of b and put them in the temporary area at pp
    for (i = (1 << (windowsize - 1)) - 1; i > 0; i--) {
        if (n == 1) {
            number<T>::umul(&tp[1], &tp[0], *this_pp, *r_limbs);
            ++this_pp;
            redc_reduce(this_pp, tp, mp, mip[0]);
        }
        else {
            mul_n(tp, this_pp, r_limbs, n);
            this_pp += n;
            if (BELOW_THRESHOLD (n, REDC_1_TO_REDC_N_THRESHOLD))
                redc_1_fix(this_pp, tp, mp, n, mip[0]);
            else
                redc_n(this_pp, tp, mp, n, mip);
        }
    }

    expbits = getbits(ep, ebi, windowsize);
    if (ebi < windowsize)
        ebi = 0;
    else
        ebi -= windowsize;

    cnt = bit_manipulation::ctz(expbits);
    ebi += cnt;
    expbits >>= cnt;

    copy(r_limbs, pp + n * (expbits >> 1), n);

    if (n == 1) {
        if (!powm_innerloop(r_limbs, ep, ebi, windowsize, this_windowsize,
            cnt, expbits, n, tp, mp, mip, pp,
            redc_mul_1, redc_sqr_1, redc_reduce_0)) {
            goto done;
        }
    }
    else {
        if (REDC_1_TO_REDC_N_THRESHOLD < MUL_TOOM22_THRESHOLD) {
            if (BELOW_THRESHOLD(n, REDC_1_TO_REDC_N_THRESHOLD)) {
                if (!powm_innerloop(r_limbs, ep, ebi, windowsize, this_windowsize,
                    cnt, expbits, n, tp, mp, mip, pp,
                    redc_mul_n, redc_sqr_n, redc_reduce_1)) {
                    goto done;
                }
            }
            else {
                if (!powm_innerloop(r_limbs, ep, ebi, windowsize, this_windowsize,
                    cnt, expbits, n, tp, mp, mip, pp,
                    redc_mul_n, redc_sqr_n, redc_reduce_n)) {
                    goto done;
                }
            }
        }
        else {
            if (BELOW_THRESHOLD(n, MUL_TOOM22_THRESHOLD)) {
                if (MUL_TOOM22_THRESHOLD < REDC_SQR_BASECASE_THRESHOLD
                    || BELOW_THRESHOLD(n, REDC_SQR_BASECASE_THRESHOLD)) {
                    if (!powm_innerloop(r_limbs, ep, ebi, windowsize, this_windowsize,
                        cnt, expbits, n, tp, mp, mip, pp,
                        redc_mul_gradeschool, redc_sqr_gradeschool, redc_reduce_1)) {
                        goto done;
                    }
                }
                else {
                    if (!powm_innerloop(r_limbs, ep, ebi, windowsize, this_windowsize,
                        cnt, expbits, n, tp, mp, mip, pp,
                        redc_mul_gradeschool, redc_sqr_n, redc_reduce_1)) {
                        goto done;
                    }
                }
            }
            else if (BELOW_THRESHOLD(n, REDC_1_TO_REDC_N_THRESHOLD)) {
                if (!powm_innerloop(r_limbs, ep, ebi, windowsize, this_windowsize,
                    cnt, expbits, n, tp, mp, mip, pp,
                    redc_mul_n, redc_sqr_n, redc_reduce_1)) {
                    goto done;
                }
            }
            else {
                if (!powm_innerloop(r_limbs, ep, ebi, windowsize, this_windowsize,
                    cnt, expbits, n, tp, mp, mip, pp,
                    redc_mul_n, redc_sqr_n, redc_reduce_n)) {
                    goto done;
                }
            }
        }
    }

done:
    copy(tp, r_limbs, n);
    zero(tp + n, n);

    if (BELOW_THRESHOLD(n, REDC_1_TO_REDC_N_THRESHOLD))
        redc_1_fix(r_limbs, tp, mp, n, mip[0]);
    else
        redc_n(r_limbs, tp, mp, n, mip);

    if (cmp(r_limbs, mp, n) >= 0)
        sub_n(r_limbs, r_limbs, mp, n);

    if (mip != i_limbs) {
        aligned_free(mip);
    }
    aligned_free(pp);
}

template<typename T>
void mpbase<T>::pow_low(T* out, const T* base, const T* exp, size_t exp_n, size_t n, T* tmp)
{
    int cnt;
    int ebi;
    int windowsize, this_windowsize;
    T expbits;
    T *pp, *this_pp, *last_pp;
    int32_t i;

    assert(exp_n > 1 || (exp_n == 1 && exp[0] > 1));

    // Calculate the bit length of the exponent
    ebi = sizeinbase_2exp<T>(exp, exp_n, 1);

    // Obtain a window size for the exponentiation
    windowsize = win_size<T>(ebi);
    assert(windowsize < ebi);

    // Temporary storage for n * 2^(windowsize-1) limbs, initialised with the base number
    pp = reinterpret_cast<T*>(aligned_malloc((n << (windowsize - 1)) * sizeof(T)));
    this_pp = pp;
    copy(this_pp, base, n);

    // Store base^2 in tmp
    sqr_low_n(tmp, base, n);

    // Precompute odd powers of base and place them in the temporary area at pp
    for (i = (1 << (windowsize - 1)) - 1; i > 0; i--) {
        last_pp = this_pp;
        this_pp += n;
        mul_low_n(this_pp, last_pp, tmp, n);
    }

    // Extract the number of exponent bits within the window
    expbits = getbits(exp, ebi, windowsize);

    // Normalize the exponent to remove the LSB's
    cnt = bit_manipulation::ctz(expbits);
    ebi -= windowsize;
    ebi += cnt;
    expbits >>= cnt;

    // Initialize out with the base raised to the powerof half the exponent
    copy(out, pp + n * (expbits >> 1), n);

    // Square-and-multiply
    do {
        while (GETBIT(exp, ebi) == 0) {
            sqr_low_n(tmp, out, n);
            copy(out, tmp, n);
            if (--ebi == 0)
                goto done;
        }

        // Multiply as exponent bit is 1 - extract the largest block of
        // bits <= windowsize such that the least significant bit is 1
        expbits = getbits(exp, ebi, windowsize);
        this_windowsize = windowsize;
        if (ebi < windowsize) {
            this_windowsize -= windowsize - ebi;
            ebi = 0;
        }
        else
            ebi -= windowsize;

        // Adjust for trailing zeros
        cnt = bit_manipulation::ctz(expbits);
        this_windowsize -= cnt;
        ebi += cnt;
        expbits >>= cnt;

        // Raise to the power of 4
        while (this_windowsize > 1) {
            sqr_low_n(tmp, out, n);
            sqr_low_n(out, tmp, n);
            this_windowsize -= 2;
        }

        // Until the end of the window we square again
        if (this_windowsize != 0)
            sqr_low_n(tmp, out, n);
        else
            copy(tmp, out, n);

        // Multiply by the relevant precomputed base raised to an odd power
        mul_low_n(out, tmp, pp + n * (expbits >> 1), n);
    } while (ebi != 0);

done:
    aligned_free(pp);
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
