/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "core/mpbase.hpp"


/// The intermediate storage limbs required for inversion of a length n
#define INVERTAPPR_SCRATCH_SIZE(n)      (3 * (n) + 2)

/// The threshold for basecase Hensel binary division
#define BDIV_Q_THRESHOLD                180

/// The threshold for mu_div_qr_internal not returning an error
#define MU_DIV_QR_SKEW_THRESHOLD        100

/// The threshold for divappr_qr_1 being optimal as the denominator is sufficiently small
#define DIVAPPR_Q_THRESHOLD             200

/// The base threshold for multiplicative inverse modular multiplication to be enabled
#define MULMOD_BNM1_THRESHOLD           16

/// The threshold for newton_invertappr being optimal over basecase_invertappr
#define INV_NEWTON_THRESHOLD            200

/// The threshold for Newton iterations when calculating the multiplicative inverse
#define BINV_NEWTON_THRESHOLD           300

/// The threshold at which multiplication requires modular reduction during Newton inversion
#define INV_MULMOD_BNM1_THRESHOLD       (4 * MULMOD_BNM1_THRESHOLD)

/// The threshold for basecase division with quotient and remainder
#define DIV_QR_THRESHOLD                50

/// Threshold for mu_div_qr denominator
#define MU_DEN_DIV_QR_THRESHOLD         200

/// Threshold for mu_div_qr
#define MU_DIV_QR_THRESHOLD             2000

/// Threshold for Hensel binary division basecase
#define BASECASE_BDIV_QR_THRESHOLD      50

/// 16-bit log2(n)
#define LOG2B16(n) \
    (((n) >= 0x0001) + ((n) >= 0x0002) + ((n) >= 0x0004) + ((n) >= 0x0008) + \
     ((n) >= 0x0010) + ((n) >= 0x0020) + ((n) >= 0x0040) + ((n) >= 0x0080) + \
     ((n) >= 0x0100) + ((n) >= 0x0200) + ((n) >= 0x0400) + ((n) >= 0x0800) + \
     ((n) >= 0x1000) + ((n) >= 0x2000) + ((n) >= 0x4000) + ((n) >= 0x8000))

/// Size ofcoputation precision table
#define INV_SIZE_PREC ((sizeof(size_t) > 6 ? 48 : 8*sizeof(size_t)) - LOG2B16(BINV_NEWTON_THRESHOLD))


namespace phantom {
namespace core {


template<typename T>
T mpbase<T>::div_qr_1_preinv(T *q_limbs, const T *n_limbs,
    size_t n, const mod_metadata<T>& mod)
{
    T  rem  = 0;
    T *temp = nullptr;

    // Normalise the numerator (left shift by 'norm' bits)
    if (mod.norm > 0) {
        temp = reinterpret_cast<T*>(aligned_malloc(n * sizeof(T)));
        rem = lshift(temp, n_limbs, n, mod.norm);
        n_limbs = temp;
    }

    // Iteratively divide each word of the numerator, conditionally store the quotient
    // if a valid pointer is supplied
    while (n--) {
        T quo;
        number<T>::udiv_qrnnd_preinv(&quo, &rem, rem, n_limbs[n], mod.m << mod.norm, mod.m_inv);
        if (q_limbs) {
            q_limbs[n] = quo;
        }
    }

    // Free intermediate memory if it was used
    if (mod.norm > 0) {
        aligned_free(temp);
    }

    // Ensure that the remainder is returned as a de-normalised value
    return rem >> mod.norm;
}

/**
 * Division with a quotient and remainder using a 2-limb pre-inverted fixed-point reciprocal of the denominator
 * @param q_limbs Quotient
 * @param r_limbs Remainder
 * @param n_limbs Numerator (NOTE: The numerator is destroyed)
 * @param n Length of the numerator
 * @param mod Struct with a double-precision denominator that is pre-inverted to form a
 * limb-sized fixed-point reciprocal
 */
template<typename T>
void mpbase<T>::div_qr_2_preinv(T *q_limbs, T *r_limbs,
    const T *n_limbs, size_t n, const mod_metadata<T>& mod)
{
    T  r1   = 0;
    T *temp = nullptr;

    // Normalise the numerator by norm bits, otherwise r1 is zero
    if (mod.norm) {
        temp    = reinterpret_cast<T*>(aligned_malloc(n * sizeof(T)));
        r1      = lshift(temp, n_limbs, n, mod.norm);
        n_limbs = temp;
    }

    // r0 is always the most significant numerator word
    T r0 = n_limbs[n - 1];

    // Iteratively perform a 3-by-2 division to obtain the quotient from most significant
    // to least significant word
    size_t i = n - 2;
    do {
        T quo;
        number<T>::udiv_qrnnndd_preinv(&quo, &r1, &r0, r1, r0, n_limbs[i], mod.m, mod.m_low, mod.m_inv);
        if (q_limbs) {
            q_limbs[i] = quo;
        }
    } while (i--);

    // De-normalise the remainder by right shifting by norm bits
    if (mod.norm) {
        r0   = (r0 >> mod.norm) | (r1 << mod.b_norm);
        r1 >>= mod.norm;
        aligned_free(temp);
    }

    // Return the two de-normalised remainder words
    r_limbs[1] = r1;
    r_limbs[0] = r0;
}

/**
 * Division with a quotient and remainder using a single limb denominator
 * @param q_limbs Quotient
 * @param r_limbs Remainder
 * @param n_limbs Numerator (NOTE: The numerator is destroyed)
 * @param n Length of the numerator
 * @param mod Struct with a double-precision denominator that is pre-inverted to form a
 * limb-sized fixed-point reciprocal
 */
template<typename T>
T mpbase<T>::div_qr_1(T *q_limbs, const T *n_limbs, size_t n, T d)
{
    // Detect a power of 2 and right-shift, otherwise perform a division
    if (d > 1 && (d & (d-1)) == 0) {
        T r = n_limbs[0] & (d - 1);
        T shift = bit_manipulation::ctz(d);
        if (q_limbs) {
            rshift(q_limbs, n_limbs, n, shift);
        }
        return r;
    }
    else {
        mod_metadata<T> mod;
        mod.init(d);
        return div_qr_1_preinv(q_limbs, n_limbs, n, mod);
    }
}

/**
 * Division with a quotient and remainder using pre-inverted estimation
 * @param q_limbs Quotient
 * @param n_limbs Numerator
 * @param n Length of the numerator
 * @param d_limbs Denominator
 * @param dn Length of the denominator
 * @param mod Struct with a double-precision denominator that is pre-inverted to form a
 * limb-sized fixed-point reciprocal
 */
template<typename T>
void mpbase<T>::div_qr_general_preinv(T *q_limbs, T *n_limbs,
    size_t n, const T *d_limbs, size_t dn, const mod_metadata<T>& mod)
{
    size_t i;
    T q, inv, d1, d0, n1;
    inv = mod.m_inv;
    d1  = d_limbs[dn-1];
    d0  = d_limbs[dn-2];
    n1  = 0;

    // Normalise the numerator by left shifting by norm bits
    if (mod.norm) {
        n1 = lshift(n_limbs, n_limbs, n, mod.norm);
    }

    // Calculate the quotient in descending order over 'n - dn' iterations
    i = n - dn;
    do {
        T n0 = n_limbs[dn - 1 + i];
        if (n1 == d1 && n0 == d0) {
            // If the numerator and denominator are identical the quotient is set to
            // the maximum limb value and the product of the quotient and denominator is
            // subtracted from the numerator.
            q = ~T(0);
            submul_1(n_limbs + i, d_limbs, dn, q);
            n1 = n_limbs[dn - 1 + i];
        }
        else {
            // Divide 'n1|n0|n_limbs[dn-2+i]' by 'd1|d0' and subtract the product of the quotient
            // and denominator from the numerator
            number<T>::udiv_qrnnndd_preinv(&q, &n1, &n0, n1, n0, n_limbs[dn - 2 + i], d1, d0, inv);
            T c = submul_1(n_limbs + i, d_limbs, dn - 2, q);

            // Subtract the carry from the middle numerator limb and copy to the numerator output
            T c2 = const_time<T>::cmp_lessthan(n0, c);
            n0 -= c;
            n_limbs[dn - 2 + i] = n0;

            // Subtract the carry from the upper numerator limb
            c   = const_time<T>::cmp_lessthan(n1, c2);
            n1 -= c2;

            // If there is a carry it must be propagated through the numerator and accounted for by
            // decrementing the quotient
            if (c) {
                n1 += d1 + add_n(n_limbs + i, n_limbs + i, d_limbs, dn - 1);
                q--;
            }
        }

        // Update the output quotient
        if (q_limbs) {
            q_limbs[i] = q;
        }
    } while (0 != i--);

    // Carry the numerator word to the most significant remainder/numerator word indexed by n1
    n_limbs[dn - 1] = n1;

    // De-normalise the least significant numerator words
    if (mod.norm) {
        rshift(n_limbs, n_limbs, dn, mod.norm);
    }
}

/**
 * Division with a quotient and remainder using pre-inverted estimation, with denominator optimization
 * @param q_limbs Quotient
 * @param n_limbs Numerator
 * @param n Length of the numerator
 * @param d_limbs Denominator
 * @param dn Length of the denominator
 * @param mod Struct with a double-precision denominator that is pre-inverted to form a
 * limb-sized fixed-point reciprocal
 */
template<typename T>
void mpbase<T>::div_qr_preinv(T *q_limbs, T *n_limbs,
    size_t n, const T *d_limbs, size_t dn, const mod_metadata<T>& mod)
{
    if (1 == dn) {
        // Special case with a single precision denominator
        n_limbs[0] = div_qr_1_preinv(q_limbs, n_limbs, n, mod);
    }
    else if (2 == dn) {
        // Special case with a double precision denominator
        div_qr_2_preinv(q_limbs, n_limbs, n_limbs, n, mod);
    }
    else {
        // The general case
        div_qr_general_preinv(q_limbs, n_limbs, n, d_limbs, dn, mod);
    }
}

/**
 * @brief Division with a quotient and remainder (NOTE: The numerator will be overwritten)
 * @param q_limbs Quotient
 * @param n_limbs Numerator
 * @param n Length of the numerator
 * @param d_limbs Denominator
 * @param dn Length of the denominator
 */
template<typename T>
void mpbase<T>::div_qr(T *q_limbs, T *n_limbs, size_t n, const T *d_limbs, size_t dn)
{
    mod_metadata<T> mod;

    if (1 == dn) {
        // Special case for a single limb divisor
        mod.init(d_limbs[0]);
    }
    else if (2 == dn) {
        // Special case for a two limb divisor
        mod.init_2(d_limbs[1], d_limbs[0]);
    }
    else {
        mod.init_3(d_limbs[dn-1], d_limbs[dn-2], d_limbs[dn-3]);
    }

    // Normalise the divisor if it is not a special case and
    // it contains leading zeros in the MSW
    if (dn > 2 && mod.norm > 0) {
        T *temp = reinterpret_cast<T*>(aligned_malloc(dn * sizeof(T)));
        lshift(temp, d_limbs, dn, mod.norm);

        // Perform the division with the precomputed inverse
        div_qr_preinv(q_limbs, n_limbs, n, temp, dn, mod);

        // Free resources associated with divisor normalisation
        aligned_free(temp);
    }
    else {
        // Perform the division with the precomputed inverse
        div_qr_preinv(q_limbs, n_limbs, n, d_limbs, dn, mod);
    }
}

/**
 * @brief Division with the numerator overwritten by the remainder and a 2 limb denominator
 * @param q_limbs Quotient
 * @param q_offset Length of the numerator
 * @param n_limbs Numerator
 * @param n Length of the numerator
 * @param d_limbs Denominator
 * @return 1 if numerator normalised to be smaller than denominator, 0 otherwise
 */
template<typename T>
T mpbase<T>::divrem_2(T* q_limbs, size_t q_offset, T* n_limbs, size_t n, const T* d_limbs)
{
    T most_significant_q_limb;
    size_t i;
    T r1, r0, d1, d0;

    // Rule checking for conditions of use
    assert(n >= 2);
    assert(q_offset >= 0);
    assert(d_limbs[1] & LIMB_HIGHBIT);
    assert(!OVERLAP_P(q_limbs, n-2+q_offset, n_limbs, n) || q_limbs >= n_limbs+2);

    // Calculate the pre-inversion constants
    n_limbs += n - 2;
    d1 = d_limbs[1];
    d0 = d_limbs[0];
    r1 = n_limbs[1];
    r0 = n_limbs[0];

    most_significant_q_limb = 0;
    if (r1 >= d1 && (r1 > d1 || r0 >= d0)) {
        number<T>::usub(&r1, &r0, r1, r0, d1, d0);
        most_significant_q_limb = 1;
    }

    mod_metadata<T> mod;
    mod.init_2(d1, d0);

    // Iteratively compute the quotient limbs
    q_limbs += q_offset;
    for (i = n - 2 - 1; i >= 0; i--) {
        T n0, q;
        n0 = n_limbs[-1];
        number<T>::udiv_qrnnndd_preinv(&q, &r1, &r0, r1, r0, n0, d1, d0, mod.m_inv);
        n_limbs--;
        q_limbs[i] = q;
    }

    // Compensate for the offset
    if (q_offset != 0) {
        q_limbs -= q_offset;
        for (i = q_offset - 1; i >= 0; i--) {
            T q;
            number<T>::udiv_qrnnndd_preinv(&q, &r1, &r0, r1, r0, T(0), d1, d0, mod.m_inv);
            q_limbs[i] = q;
        }
    }

    // Overwrite the least significant 2 limbs of the numerator with the remainder
    n_limbs[1] = r1;
    n_limbs[0] = r0;

    return most_significant_q_limb;
}

/**
 * @brief Division wrapping the div_qr() method to conveniently obtain the remainder
 * @param q_limbs Quotient
 * @param r_limbs Remainder
 * @param n_limbs Numerator
 * @param nn Length of the numerator
 * @param d_limbs Denominator
 * @param dn Length of the denominator
 */
template<typename T>
void mpbase<T>::div_quorem(T *q_limbs, T *r_limbs, const T *n_limbs, size_t nn, const T *d_limbs, size_t dn)
{
    assert(nn >= dn);
    assert(dn > 0);
    assert(d_limbs[dn - 1] != 0);

    if (r_limbs == n_limbs) {
        div_qr(q_limbs, r_limbs, nn, d_limbs, dn);
    }
    else {
        T* tp = reinterpret_cast<T*>(aligned_malloc(nn * sizeof(T)));

        copy(tp, n_limbs, nn);
        div_qr(q_limbs, tp, nn, d_limbs, dn);

        if (r_limbs) {
            copy(r_limbs, tp, dn);
        }

        aligned_free(tp);
    }
}

/**
 * Compute the inverse size of a denominator for a selected quotient length
 * @param qn Quotient length
 * @param dn Denominator length
 * @return Length of the inverse
 */
template<typename T>
size_t mpbase<T>::mu_div_qr_inverse_size(size_t qn, size_t dn)
{
    size_t in;
    size_t b;

    // In all cases in <= dn.
    //  (a) dn < qn:         in = ceil(qn / ceil(qn/dn))
    //  (b) dn/3 < qn <= dn: in = ceil(qn / 2)
    //  (c) qn < dn/3:       in = qn
    if (qn > dn) {
        b = (qn - 1) / dn + 1;  // Number of blocks = ceil(qn/dn)
    }
    else if (3 * qn > dn) {
        b = 2;
    }
    else {
        b = 1;
    }

    in = (qn - 1) / b + 1;         // ceil(qn / ceil(qn/dn))

    return in;
}

/**
 * Compute the scratch size required for mu_div_qr()
 * @param nn Numerator length
 * @param dn Denominator length
 * @return Scratch memory length
 */
template<typename T>
size_t mpbase<T>::mu_div_qr_scratch_size(size_t nn, size_t dn)
{
    size_t itch_local = mulmod_bnm1_next_size(dn + 1);
    size_t in         = mu_div_qr_inverse_size(nn - dn, dn);
    size_t itch_out   = mulmod_bnm1_size(itch_local, dn, in);

    return in + itch_local + itch_out;
}

/**
 * @brief Division using external scratch memory
 * @param q_limbs Quotient
 * @param r_limbs Remainder
 * @param n_limbs Numerator
 * @param nn Length of the numerator
 * @param d_limbs Denominator
 * @param dn Length of the denominator
 * @param scratch Temporary memory for intermediate values
 */
template<typename T>
T mpbase<T>::mu_div_qr(T* q_limbs, T* r_limbs, const T* n_limbs, size_t nn,
    const T* d_limbs, size_t dn, T* scratch)
{
    T cy, qh;

    size_t qn = nn - dn;
    if ((qn + MU_DIV_QR_SKEW_THRESHOLD) < dn) {

        // Compute a preliminary quotient and a partial remainder by dividing the
        // most significant limbs of each operand
        qh = mu_div_qr_internal(q_limbs, r_limbs + nn - (2 * qn + 1),
                n_limbs + nn - (2 * qn + 1), 2 * qn + 1,
                d_limbs + dn - (qn + 1), qn + 1,
                scratch);

        // Multiply the quotient by the divisor limbs
        if (dn - (qn + 1) > qn) {
            mul(scratch, d_limbs, dn - (qn + 1), q_limbs, qn);  // product is dn-1 limbs
        }
        else {
            mul(scratch, q_limbs, qn, d_limbs, dn - (qn + 1));  // product is dn-1 limbs
        }

        // Compensate for the carry from mu_div_qr_internal()
        if (qh) {
            cy = add_n(scratch + qn, scratch + qn, d_limbs, dn - (qn + 1));
        }
        else {
            cy = 0;
        }
        scratch[dn - 1] = cy;

        // Calculate the remainder by subtracting the quotient/denominator product
        // from the numerator
        cy = sub_n(r_limbs, n_limbs, scratch, nn - (2 * qn + 1));
        cy = sub_nc(r_limbs + nn - (2 * qn + 1),
                r_limbs + nn - (2 * qn + 1),
                scratch + nn - (2 * qn + 1),
                qn + 1, cy);
        if (cy) {
            qh -= sub_1(q_limbs, q_limbs, qn, 1);
            add_n(r_limbs, r_limbs, d_limbs, dn);
        }
    }
    else {
        // The quotient is sufficiently larger than the denominator so mu_div_qr_internal()
        // will not produce an error
        qh = mu_div_qr_internal(q_limbs, r_limbs, n_limbs, nn, d_limbs, dn, scratch);
    }

    return qh;
}

/**
 * @brief Division with pre-inversion using external scratch memory
 * @param q_limbs Quotient
 * @param r_limbs Remainder
 * @param n_limbs Numerator
 * @param nn Length of the numerator
 * @param d_limbs Denominator
 * @param dn Length of the denominator
 * @param scratch Temporary memory for intermediate values
 */
template<typename T>
T mpbase<T>::mu_div_qr_internal(T* q_limbs, T* r_limbs, const T* n_limbs, size_t nn,
    const T* d_limbs, size_t dn, T* scratch)
{
    size_t qn, in;
    T cy, qh;
    T *i_limbs, *tp;

    assert(dn > 1);

    qn = nn - dn;

    // Compute the inverse size
    in = mu_div_qr_inverse_size(qn, dn);
    assert(in <= dn);

    // Compute an approximate inverse on (in+1) limbs
    i_limbs = scratch;
    tp = scratch + in + 1;
    if (dn == in) {
        copy(tp + 1, d_limbs, in);
        tp[0] = 1;
        invertappr(i_limbs, tp, in + 1, NULL);
        copy(i_limbs, i_limbs + 1, in);
    }
    else {
        cy = add_1(tp, d_limbs + dn - (in + 1), in + 1, 1);
        if (0 != cy) {
            zero(i_limbs, in);
        }
        else {
            invertappr(i_limbs, tp, in + 1, NULL);
            copy(i_limbs, i_limbs + 1, in);
        }
    }

    // Perform the division using the pre-inverted inverse
    qh = preinv_mu_div_qr(q_limbs, r_limbs, n_limbs, nn, d_limbs, dn, i_limbs, in, scratch + in);

    return qh;
}

/**
 * @brief Approximate division for smaller divisors
 * @param q_limbs Quotient
 * @param n_limbs Numerator
 * @param nn Length of the numerator
 * @param d_limbs Denominator
 * @param dn Length of the denominator
 * @param dinv Denominator inverse
 * @return 1 if numerator is grater than or equal to the denominator
 */
template<typename T>
T mpbase<T>::divappr_qr_1(T* q_limbs, T* n_limbs, size_t nn, const T* d_limbs, size_t dn, T dinv)
{
    T qh;
    size_t qn, i;
    T n1, n0;
    T d1, d0;
    T cy, cy1;
    T q;
    T flag;

    assert(dn > 2);
    assert(nn >= dn);
    assert((d_limbs[dn-1] & LIMB_HIGHBIT) != 0);

    n_limbs += nn;

    qn = nn - dn;
    if (qn + 1 < dn) {
        d_limbs += dn - (qn + 1);
        dn = qn + 1;
    }

    qh = cmp(n_limbs - dn, d_limbs, dn) >= 0;
    if (qh != 0) {
        sub_n(n_limbs - dn, n_limbs - dn, d_limbs, dn);
    }

    q_limbs += qn;

    dn -= 2;          // offset dn by 2 for main division loops,
                        // saving two iterations in submul_1
    d1 = d_limbs[dn + 1];
    d0 = d_limbs[dn + 0];

    n_limbs -= 2;

    n1 = n_limbs[1];

    for (i = qn - (dn + 2); i >= 0; i--) {
        n_limbs--;
        if ((n1 == d1) && n_limbs[1] == d0) {
            q = LIMB_MASK;
            submul_1(n_limbs - dn, d_limbs, dn + 2, q);
            n1 = n_limbs[1];       // update n1, last loop's value will now be invalid
        }
        else {
            number<T>::udiv_qrnnndd_preinv(&q, &n1, &n0, n1, n_limbs[1], n_limbs[0], d1, d0, dinv);

            cy = submul_1(n_limbs - dn, d_limbs, dn, q);

            cy1 = n0 < cy;
            n0 = (n0 - cy) & LIMB_MASK;
            cy = n1 < cy1;
            n1 -= cy1;
            n_limbs[0] = n0;

            if (cy != 0) {
                n1 += d1 + add_n(n_limbs - dn, n_limbs - dn, d_limbs, dn + 1);
                q--;
            }
        }

        *--q_limbs = q;
    }

    flag = ~T(0);

    if (dn >= 0) {
        for (i = dn; i > 0; i--) {
            n_limbs--;
            if (n1 >= (d1 & flag)) {
                q = LIMB_MASK;
                cy = submul_1(n_limbs - dn, d_limbs, dn + 2, q);

                if (n1 != cy) {
                    if (n1 < (cy & flag)) {
                        q--;
                        add_n(n_limbs - dn, n_limbs - dn, d_limbs, dn + 2);
                    }
                    else
                        flag = 0;
                }
                n1 = n_limbs[1];
            }
            else {
                number<T>::udiv_qrnnndd_preinv(&q, &n1, &n0, n1, n_limbs[1], n_limbs[0], d1, d0, dinv);

                cy = submul_1(n_limbs - dn, d_limbs, dn, q);

                cy1 = n0 < cy;
                n0 = (n0 - cy) & LIMB_MASK;
                cy = n1 < cy1;
                n1 -= cy1;
                n_limbs[0] = n0;

                if (cy != 0) {
                    n1 += d1 + add_n(n_limbs - dn, n_limbs - dn, d_limbs, dn + 1);
                    q--;
                }
            }

            *--q_limbs = q;

            // Truncate operands
            dn--;
            d_limbs++;
        }

        n_limbs--;
        if (n1 >= (d1 & flag)) {
            q = LIMB_MASK;
            cy = submul_1(n_limbs, d_limbs, 2, q);

            if (n1 != cy) {
                if (n1 < (cy & flag)) {
                    q--;
                    number<T>::uadd(&n_limbs[1], &n_limbs[0], n_limbs[1], n_limbs[0], d_limbs[1], d_limbs[0]);
                }
                else {
                    flag = 0;
                }
            }
            n1 = n_limbs[1];
        }
        else {
            number<T>::udiv_qrnnndd_preinv(&q, &n1, &n0, n1, n_limbs[1], n_limbs[0], d1, d0, dinv);

            n_limbs[1] = n1;
            n_limbs[0] = n0;
        }

        *--q_limbs = q;
    }

    return qh;
}

/**
 * @brief Approximate division with same length numerator and divisor
 * @param q_limbs Quotient
 * @param n_limbs Numerator
 * @param d_limbs Denominator
 * @param n Length of the denominator
 * @param dinv Denominator inverse
 * @param scratch Intermediate storage
 * @return 1 if numerator is grater than or equal to the denominator
 */
template<typename T>
T mpbase<T>::divappr_qr_2_n(T* q_limbs, T* n_limbs, const T* d_limbs, size_t n, T dinv, T* scratch)
{
    size_t lo, hi;
    T cy, qh, ql;

    lo = n >> 1;          // floor(n/2)
    hi = n - lo;          // ceil(n/2)

    if (BELOW_THRESHOLD(hi, DIV_QR_THRESHOLD)) {
        qh = basecase_div_qr(q_limbs + lo, n_limbs + 2 * lo, 2 * hi, d_limbs + lo, hi, dinv);
    }
    else {
        qh = general_div_qr_n(q_limbs + lo, n_limbs + 2 * lo, d_limbs + lo, hi, dinv, scratch);
    }

    mul(scratch, q_limbs + lo, hi, d_limbs, lo);

    cy = sub_n(n_limbs + lo, n_limbs + lo, scratch, n);
    if (qh != 0)
        cy += sub_n(n_limbs + n, n_limbs + n, d_limbs, lo);

    while (cy != 0) {
        qh -= sub_1(q_limbs + lo, q_limbs + lo, hi, 1);
        cy -= add_n(n_limbs + lo, n_limbs + lo, d_limbs, n);
    }

    if (BELOW_THRESHOLD(lo, DIVAPPR_Q_THRESHOLD)) {
        ql = divappr_qr_1(q_limbs, n_limbs + hi, 2 * lo, d_limbs + hi, lo, dinv);
    }
    else {
        ql = divappr_qr_2_n(q_limbs, n_limbs + hi, d_limbs + hi, lo, dinv, scratch);
    }

    if (ql != 0) {
        for (size_t i = 0; i < lo; i++) {
            q_limbs[i] = LIMB_MASK;
        }
    }

    return qh;
}

/**
 * @brief Approximate division for larger divisors
 * @param q_limbs Quotient
 * @param n_limbs Numerator
 * @param nn Length of the numerator
 * @param d_limbs Denominator
 * @param dn Length of the denominator
 * @param dinv Denominator inverse
 * @return 1 if numerator is grater than or equal to the denominator
 */
template<typename T>
T mpbase<T>::divappr_qr_2(T* q_limbs, T* n_limbs, size_t nn, const T* d_limbs, size_t dn, T dinv)
{
    size_t qn;
    T qh, cy, qsave;
    phantom_vector<T> tpvec;
    T* tp;

    assert(dn >= 6);
    assert(nn > dn);
    assert(d_limbs[dn-1] & LIMB_HIGHBIT);

    qn = nn - dn;
    q_limbs += qn;
    n_limbs += nn;
    d_limbs += dn;

    if (qn >= dn) {
        // Add an extra limb to ensure dn-1 = qn quotient limbs will remain
        qn++;

        // Reduce qn mod dn without division, optimizing small operations
        do {
            qn -= dn;
        } while (qn > dn);

        q_limbs -= qn;      // Quotient points at the low limb of the next quotient block
        n_limbs -= qn;      // Numerator points in the middle of the partial remainder

        tpvec.resize(dn);
        tp = tpvec.data();

        if (qn == 1) {
            T q, n2, n1, n0, d1, d0;

            qh = cmp(n_limbs - dn + 1, d_limbs - dn, dn) >= 0;
            if (qh) {
                sub_n(n_limbs - dn + 1, n_limbs - dn + 1, d_limbs - dn, dn);
            }

            // udiv_qrnnndd_preinv division and adjustment
            n2 = n_limbs[0];
            n1 = n_limbs[-1];
            n0 = n_limbs[-2];
            d1 = d_limbs[-1];
            d0 = d_limbs[-2];

            assert(n2 < d1 || (n2 == d1 && n1 <= d0));

            if ((n2 == d1) && n1 == d0) {
                q = LIMB_MASK;
                cy = submul_1(n_limbs - dn, d_limbs - dn, dn, q);
                assert(cy == n2);
            }
            else {
                number<T>::udiv_qrnnndd_preinv(&q, &n1, &n0, n2, n1, n0, d1, d0, dinv);

                if (dn > 2) {
                    T cy, cy1;
                    cy = submul_1(n_limbs - dn, d_limbs - dn, dn - 2, q);

                    cy1 = n0 < cy;
                    n0 = (n0 - cy) & LIMB_MASK;
                    cy = n1 < cy1;
                    n1 = (n1 - cy1) & LIMB_MASK;
                    n_limbs[-2] = n0;

                    if (cy != 0) {
                        n1 += d1 + add_n(n_limbs - dn, n_limbs - dn, d_limbs - dn, dn - 1);
                        qh -= (q == 0);
                        q = (q - 1) & LIMB_MASK;
                    }
                }
                else {
                    n_limbs[-2] = n0;
                }

                n_limbs[-1] = n1;
            }
            q_limbs[0] = q;
        }
        else {
            if (qn == 2) {
                qh = divrem_2(q_limbs, 0L, n_limbs - 2, 4, d_limbs - 2);
            }
            else if (BELOW_THRESHOLD(qn, DIV_QR_THRESHOLD)) {
                qh = basecase_div_qr(q_limbs, n_limbs - qn, 2 * qn, d_limbs - qn, qn, dinv);
            }
            else {
                qh = general_div_qr_n(q_limbs, n_limbs - qn, d_limbs - qn, qn, dinv, tp);
            }

            if (qn != dn) {
                if (qn > dn - qn) {
                    mul(tp, q_limbs, qn, d_limbs - dn, dn - qn);
                }
                else {
                    mul(tp, d_limbs - dn, dn - qn, q_limbs, qn);
                }

                cy = sub_n(n_limbs - dn, n_limbs - dn, tp, dn);
                if (qh != 0) {
                    cy += sub_n(n_limbs - dn + qn, n_limbs - dn + qn, d_limbs - dn, dn - qn);
                }

                while (cy != 0) {
                    qh -= sub_1(q_limbs, q_limbs, qn, 1);
                    cy -= add_n(n_limbs - dn, n_limbs - dn, d_limbs - dn, dn);
                }
            }
        }
        qn = nn - dn - qn + 1;
        while (qn > dn) {
            q_limbs -= dn;
            n_limbs -= dn;
            general_div_qr_n(q_limbs, n_limbs - dn, d_limbs - dn, dn, dinv, tp);
            qn -= dn;
        }

        // Subtract the extra quotient limb we added and correct
        qn--;
        q_limbs -= qn;
        n_limbs -= dn;
        qsave = q_limbs[qn];
        divappr_qr_2_n(q_limbs, n_limbs - dn, d_limbs - dn, dn, dinv, tp);
        copy(q_limbs, q_limbs + 1, qn);
        q_limbs[qn] = qsave;
    }
    else {
        T* q2p;

        q_limbs -= qn;         // Quotient points at the low limb of the next quotient block
        n_limbs -= qn;         // Numerator points in the middle of the partial remainder

        phantom_vector<T> q2pvec(qn + 1);
        q2p = q2pvec.data();

        if (BELOW_THRESHOLD(qn, DIVAPPR_Q_THRESHOLD)) {
            qh = divappr_qr_1(q2p, n_limbs - qn - 2, 2 * (qn + 1),
                    d_limbs - (qn + 1), qn + 1, dinv);
        }
        else {
            tpvec.resize(qn + 1);
            tp = tpvec.data();
            qh = divappr_qr_2_n(q2p, n_limbs - qn - 2, d_limbs - (qn + 1), qn + 1, dinv, tp);
        }
        copy(q_limbs, q2p + 1, qn);
    }

    return qh;
}

/**
 * @brief Basecase for inversion approximation
 * @param i_limbs Inverted denominator
 * @param d_limbs Denominator
 * @param n Length of the denominator
 * @param scratch Intermediate memoey of length 3 * n + 2
 * @return 1 if numerator is greater than or equal to the denominator
 */
template<typename T>
T mpbase<T>::basecase_invertappr(T* i_limbs, const T* d_limbs, size_t n, T* scratch)
{
    assert(n > 0);
    assert(d_limbs[n-1] & LIMB_HIGHBIT);
    assert(!OVERLAP_P(i_limbs, n, d_limbs, n));
    assert(!OVERLAP_P(i_limbs, n, scratch, INVERTAPPR_SCRATCH_SIZE(n)));
    assert(!OVERLAP_P(d_limbs, n, scratch, INVERTAPPR_SCRATCH_SIZE(n)));

    mod_metadata<T> mod;

    // Compute a base value of r limbs
    if (n == 1) {
        mod.init(d_limbs[0]);
        i_limbs[0] = mod.m_inv;
    }
    else {
        // n > 1 here
        fill(scratch, n, LIMB_MASK);
        ones_complement(scratch + n, d_limbs, n);

        // scratch contains B^2n - {d_limbs,n}*B^n - 1

        if (n == 2) {
            divrem_2(i_limbs, 0, scratch, 4, d_limbs);
        }
        else {
            mod.init_2(d_limbs[n-1], d_limbs[n-2]);

            if (BELOW_THRESHOLD(n, DIVAPPR_Q_THRESHOLD))
                divappr_qr_1(i_limbs, scratch, 2 * n, d_limbs, n, mod.m_inv);
            else
                divappr_qr_2(i_limbs, scratch, 2 * n, d_limbs, n, mod.m_inv);
            sub_1(i_limbs, i_limbs, n, T(1));
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Newton iteration for inversion approximation
 * @param i_limbs Inverted denominator
 * @param d_limbs Denominator
 * @param n Length of the denominator
 * @param scratch Intermediate memoey of length 3 * n + 2
 * @return 1 if numerator is greater than or equal to the denominator
 */
template<typename T>
T mpbase<T>::newton_invertappr(T* i_limbs, const T* d_limbs, size_t n, T* scratch)
{
    T cy;
    size_t sizes[INV_SIZE_PREC];

    assert(n > 2);
    assert(d_limbs[n-1] & LIMB_HIGHBIT);
    assert(!OVERLAP_P(i_limbs, n, d_limbs, n));
    assert(!OVERLAP_P(i_limbs, n, scratch, INVERTAPPR_SCRATCH_SIZE(n)));
    assert(!OVERLAP_P(d_limbs, n, scratch, INVERTAPPR_SCRATCH_SIZE(n)));

    // Compute the computation precisions from highest to lowest, leaving the
    // base case size in 'rn'
    size_t *sizp = sizes;
    size_t rn = n;
    do {
        *sizp = rn;
        rn = ((rn) >> 1) + 1;
        sizp++;
    } while (ABOVE_THRESHOLD(rn, INV_NEWTON_THRESHOLD));

    // We search the inverse of 0.{d_limbs,n}, we compute it as 1.{i_limbs,n}
    d_limbs += n;
    i_limbs += n;

    // Compute a base value of rn limbs
    basecase_invertappr(i_limbs - rn, d_limbs - rn, rn, scratch);

    size_t mn;
    phantom_vector<T> tpvec;
    T* tp = nullptr;
    if (ABOVE_THRESHOLD(n, INV_MULMOD_BNM1_THRESHOLD)) {
        mn = mulmod_bnm1_next_size(n + 1);
        tpvec.resize(mulmod_bnm1_size(mn, n, (n >> 1) + 1));
        tp = tpvec.data();
    }

    // Use Newton's iterations to get the desired precision - maximum scratch
    // needed by this branch <= 3*n + 2
    T *xp = scratch + n + 3;             // n + rn limbs
    while (1) {
        T method;
        n = *--sizp;

        if (BELOW_THRESHOLD (n, INV_MULMOD_BNM1_THRESHOLD) ||
            ((mn = mulmod_bnm1_next_size(n + 1)) > (n + rn))) {
            // Truncated product
            method = 1;
            mul(xp, d_limbs - n, n, i_limbs - rn, rn);
            add_n(xp + rn, xp + rn, d_limbs - n, n - rn + 1);
        }
        else {
            // Using mod B^m-1 product
            method = 0;
            mulmod_bnm1(xp, mn, d_limbs - n, n, i_limbs - rn, rn, tp);

            // We computed {xp,mn} <- {i_limbs,rn} * {d_limbs,n} mod (B^mn-1)
            // We know that 2*|i_limbs*d_limbs + d_limbs*B^rn - B^{rn+n}| < B^mn-1
            // Add d_limbs*B^rn mod (B^mn-1)
            assert(n >= mn - rn);
            xp[mn] = 1 + add_n(xp + rn, xp + rn, d_limbs - n, mn - rn);
            cy = add_n(xp, xp, d_limbs - (n - (mn - rn)), n - (mn - rn));
            add_1(xp + n - (mn - rn), xp + n - (mn - rn), mn + 1 - n + (mn - rn), cy);
            assert(n + rn >=  mn);

            // subtract B^{rn+n}
            sub_1(xp + rn + n - mn, xp + rn + n - mn, 2*mn + 1 - rn - n, 1);
            if (xp[mn]) {
                add_1(xp, xp, mn, xp[mn] - 1);
            }
            else {
                sub_1(xp, xp, mn, 1);
            }
        }

        if (xp[n] < 2) {
            // "positive" residue class
            cy = 1;
            while (xp[n] || cmp(xp, d_limbs - n, n) > 0) {
                xp[n] -= sub_n(xp, xp, d_limbs - n, n);
                cy++;
            }
            sub_1(i_limbs - rn, i_limbs - rn, rn, cy);
            assert(cy <= 4);  // while loop has at most 3 iterations
            sub_n(xp, d_limbs - n, xp, n);
            assert(xp[n] == 0);
        }
        else {
            // "negative" residue class
            ones_complement(xp, xp, n + 1);
            add_1(xp, xp, n + 1, method);
            assert(xp[n] <= 1);
            if (xp[n]) {
                add_1(i_limbs - rn, i_limbs - rn, rn, 1);
                sub_n(xp, xp, d_limbs - n, n);
            }
        }

        mul_n(scratch, xp + n - rn, i_limbs - rn, rn);

        // We need _only_ the carry from the next addition
        cy = add_n(scratch + rn, scratch + rn, xp + n - rn, 2*rn - n);
        cy = add_nc(i_limbs - n, scratch + 3*rn - n, xp + rn, n - rn, cy);
        add_1(i_limbs - rn, i_limbs - rn, rn, cy);
        if (sizp == sizes) {
            // Check carry propagation
            cy = scratch[3*rn - n - 1] > LIMB_MASK - 7;
            break;
        }
        rn = n;
    }

    return cy;
}

/**
 * @brief Newton iteration for inversion approximation
 * @param i_limbs Inverted denominator
 * @param d_limbs Denominator
 * @param n Length of the denominator
 * @param scratch Intermediate memoey of length 3 * n + 2
 * @return 1 if numerator is greater than or equal to the denominator
 */
template<typename T>
T mpbase<T>::invertappr(T* i_limbs, const T* d_limbs, size_t n, T* scratch)
{
    assert(n > 0);
    assert(d_limbs[n-1] & LIMB_HIGHBIT);
    assert(!OVERLAP_P(i_limbs, n, d_limbs, n));
    assert(!OVERLAP_P(i_limbs, n, scratch, INVERTAPPR_SCRATCH_SIZE(n)));
    assert(!OVERLAP_P(d_limbs, n, scratch, INVERTAPPR_SCRATCH_SIZE(n)));

    if (BELOW_THRESHOLD(n, INV_NEWTON_THRESHOLD)) {
        return basecase_invertappr(i_limbs, d_limbs, n, scratch);
    }
    else {
        return newton_invertappr(i_limbs, d_limbs, n, scratch);
    }
}

/**
 * @brief Division with a pre-inverted denominator with partial block iterations
 * @param q_limbs Quotient
 * @param r_limbs Remainder
 * @param n_limbs Numerator
 * @param nn Length of the numerator
 * @param d_limbs Denominator
 * @param dn Length of the denominator
 * @param i_limbs Inverse of denominator
 * @param in Length of the inverse
 * @param scratch Shared intermediate storage of 
 * @return 1 if numerator is greater than or equal to the denominator
 */
template<typename T>
T mpbase<T>::preinv_mu_div_qr(T* q_limbs, T* r_limbs, const T* n_limbs, size_t nn,
    const T* d_limbs, size_t dn, const T* i_limbs, size_t in, T* scratch)
{
    T cy, cx, r;
    size_t tn, wn;
    size_t qn = nn - dn;   // The maximum quotient length

    n_limbs += qn;
    q_limbs += qn;

    assert(nn >= dn);

    // If the numerator is >= to the denominator then initialize the remainder as
    // difference, otherwise copy the last dn words of the numerator
    T qh = cmp(n_limbs, d_limbs, dn) >= 0;
    if (qh != 0) {
        sub_n(r_limbs, n_limbs, d_limbs, dn);
    }
    else {
        copy(r_limbs, n_limbs, dn);
    }

    if (0 == qn) {
        return qh;
    }

    // Iteratively calculate the quotient in blocks
    while (qn > 0) {
        if (qn < in) {
            i_limbs += in - qn;
            in = qn;
        }
        n_limbs -= in;
        q_limbs -= in;

        // Compute the next block of quotient limbs by multiplying the inverse
        // by the upper part of the partial remainder
        mul_n(scratch, r_limbs + dn - in, i_limbs, in);
        cy = add_n(q_limbs, scratch + in, r_limbs + dn - in, in);

        qn -= in;

        // Compute the product of the quotient block and the denominator, to be
        // subtracted from the partial remainder combined with new limbs from the
        // numerator
        if (BELOW_THRESHOLD(in, INV_MULMOD_BNM1_THRESHOLD/2)) {
            mul(scratch, d_limbs, dn, q_limbs, in);       // dn+in limbs, high 'in' cancels
        }
        else {
            tn = mulmod_bnm1_next_size(dn + 1);
            mulmod_bnm1(scratch, tn, d_limbs, dn, q_limbs, in, scratch + tn);
            wn = dn + in - tn;            // number of wrapped limbs
            if (wn > 0) {
                cy = sub_n(scratch, scratch, r_limbs + dn - wn, wn);
                cy = sub_1(scratch + wn, scratch + wn, tn - wn, cy);
                cx = cmp(r_limbs + dn - in, scratch + dn, tn - dn) < 0;
                incr_u(scratch, cx - cy);
            }
        }

        r = r_limbs[dn - in] - scratch[dn];

        // Subtract the product from the partial remainder combined with new
        // limbs from the numerator, generating a new partial remainder
        if (dn != in) {
            cy = sub_n(scratch, n_limbs, scratch, in);  // Get next inverse limbs from numerator
            cy = sub_nc(scratch + in, r_limbs, scratch + in, dn - in, cy);
            copy(r_limbs, scratch, dn);
        }
        else {
            cy = sub_n(r_limbs, n_limbs, scratch, in);  // Get next inverse limbs from numerator
        }

        // Adjust the quotient as needed
        r -= cy;
        while (r != 0) {
            incr_u(q_limbs, 1);
            cy = sub_n(r_limbs, r_limbs, d_limbs, dn);
            r -= cy;
        }
        if (cmp(r_limbs, d_limbs, dn) >= 0) {
            incr_u(q_limbs, 1);
            cy = sub_n(r_limbs, r_limbs, d_limbs, dn);
        }
    }

    return qh;
}

/**
 * @brief Division with a pre-inverted denominator estimate (numerator overwritten with remainder)
 * @param q_limbs Quotient
 * @param n_limbs Numerator (overwritten with remainder))
 * @param nn Length of the numerator
 * @param d_limbs Denominator
 * @param dn Length of the denominator
 * @param dinv (-d)^-1 mod B
 * @return 1 if numerator is grater than or equal to the denominator
 */
template<typename T>
T mpbase<T>::basecase_div_qr(T* q_limbs, T* n_limbs, size_t nn, const T* d_limbs, size_t dn, T dinv)
{
    assert(dn > 2);
    assert(nn >= dn);
    assert((d_limbs[dn-1] & LIMB_HIGHBIT) != 0);

    n_limbs += nn;

    T qh = cmp(n_limbs - dn, d_limbs, dn) >= 0;
    if (qh != 0) {
        sub_n(n_limbs - dn, n_limbs - dn, d_limbs, dn);
    }

    q_limbs += nn - dn;

    dn -= 2;  // offset dn by 2 for main division loops, saving two iterations in submul_1
    T d1 = d_limbs[dn + 1];
    T d0 = d_limbs[dn + 0];

    n_limbs -= 2;

    T n1 = n_limbs[1];

    for (size_t i = nn - (dn + 2); i > 0; i--) {
        T q;
        n_limbs--;
        if ((n1 == d1) && n_limbs[1] == d0) {
            q = LIMB_MASK;
            submul_1(n_limbs - dn, d_limbs, dn + 2, q);
            n1 = n_limbs[1];  // update n1, last loop's value will now be invalid
        }
        else {
            T n0;
            number<T>::udiv_qrnnndd_preinv(&q, &n1, &n0, n1, n_limbs[1], n_limbs[0], d1, d0, dinv);

            T cy  = submul_1(n_limbs - dn, d_limbs, dn, q);
            T cy1 = n0 < cy;

            n0 = (n0 - cy) & LIMB_MASK;
            cy = n1 < cy1;
            n1 = (n1 - cy1) & LIMB_MASK;
            n_limbs[0] = n0;

            if (cy != 0) {
                n1 += d1 + add_n(n_limbs - dn, n_limbs - dn, d_limbs, dn + 1);
                q--;
            }
        }

        *--q_limbs = q;
    }
    n_limbs[1] = n1;

    return qh;
}

/**
 * @brief Hensel binary division, q = -n * d^{-1} mod B^nn, destroys numerator
 * @param q_limbs Quotient
 * @param n_limbs Numerator (overwritten with remainder))
 * @param nn Length of the numerator
 * @param d_limbs Denominator (must be odd)
 * @param dn Length of the denominator
 * @param dinv (-d)^-1 mod B
 */
template<typename T>
void mpbase<T>::basecase_bdiv_q(T* q_limbs, T* n_limbs, size_t nn, const T* d_limbs, size_t dn, T dinv)
{
    assert(dn > 0);
    assert(nn >= dn);
    assert((d_limbs[0] & 1) != 0);
    assert(-(d_limbs[0] * dinv) == 1);
    assert(n_limbs == q_limbs || !OVERLAP_P(n_limbs, nn, q_limbs, nn - dn));

    T q;
    if (nn > dn) {
        T cy = 0, hi;
        for (size_t i = nn - dn - 1, cy = 0; i > 0; i--) {
            q = dinv * n_limbs[0];
            hi = addmul_1(n_limbs, d_limbs, dn, q);

            assert(n_limbs[0] == 0);
            *q_limbs++ = q;
            hi += cy;
            cy = hi < cy;
            hi += n_limbs[dn];
            cy += hi < n_limbs[dn];
            n_limbs[dn] = hi;
            n_limbs++;
        }
        q = dinv * n_limbs[0];
        hi = cy + addmul_1(n_limbs, d_limbs, dn, q);
        assert(n_limbs[0] == 0);
        *q_limbs++ = q;
        n_limbs[dn] += hi;
        n_limbs++;
    }

    for (size_t i = dn; i > 1; i--) {
        T q = dinv * n_limbs[0];
        addmul_1(n_limbs, d_limbs, i, q);
        assert(n_limbs[0] == 0);
        *q_limbs++ = q;
        n_limbs++;
    }

    *q_limbs = dinv * n_limbs[0];
}

/**
 * @brief Hensel binary division, q = -n * d^{-1} mod B^nn, destroys numerator
 * @param q_limbs Quotient, qn = un - dn
 * @param n_limbs Numerator
 * @param nn Length of the numerator
 * @param d_limbs Denominator (must be odd)
 * @param dn Length of the denominator
 * @param dinv (-d)^-1 mod B
 * @return Carry bits
 */
template<typename T>
T mpbase<T>::basecase_bdiv_qr(T* q_limbs, T* n_limbs, size_t nn, const T* d_limbs, size_t dn, T dinv)
{
    assert(dn > 0);
    assert(nn > dn);
    assert((d_limbs[0] & 1) != 0);
    assert(-(d_limbs[0] * dinv) == 1);
    assert(n_limbs == q_limbs || !OVERLAP_P(n_limbs, nn, q_limbs, nn - dn));

    T cy = 0;
    for (size_t i = nn - dn, cy = 0; i != 0; i--) {
        T q = dinv * n_limbs[0];
        T hi = addmul_1(n_limbs, d_limbs, dn, q);
        *q_limbs++ = q;

        hi += cy;
        cy = hi < cy;
        hi += n_limbs[dn];
        cy += hi < n_limbs[dn];
        n_limbs[dn] = hi;
        n_limbs++;
    }

    return cy;
}

/**
 * @brief Hensel binary division with equal length, q = -n * d^{-1} mod B^nn, destroys numerator
 * @param q_limbs Quotient, qn = un - dn
 * @param n_limbs Numerator
 * @param d_limbs Denominator (must be odd)
 * @param n Length of the numerator and denominator
 * @param dinv (-d)^-1 mod B
 * @param scratch Intermediate storage of floor(n/2) words
 */
template<typename T>
void mpbase<T>::general_bdiv_q_n(T* q_limbs, T* n_limbs, const T* d_limbs, size_t n, T dinv, T* scratch)
{
    while (ABOVE_THRESHOLD(n, BDIV_Q_THRESHOLD)) {
        size_t lo = n >> 1;          // floor(n/2)
        size_t hi = n - lo;          // ceil(n/2)

        T cy = general_bdiv_qr_n(q_limbs, n_limbs, d_limbs, lo, dinv, scratch);

        mul_low_n(scratch, q_limbs, d_limbs + hi, lo);
        add_n(n_limbs + hi, n_limbs + hi, scratch, lo);

        if (lo < hi) {
            cy += addmul_1(n_limbs + lo, q_limbs, lo, d_limbs[lo]);
            n_limbs[n - 1] += cy;
        }
        q_limbs += lo;
        n_limbs += lo;
        n -= lo;
    }
    basecase_bdiv_q(q_limbs, n_limbs, n, d_limbs, n, dinv);
}

/**
 * @brief Hensel binary division, q = -n * d^{-1} mod B^nn, destroys numerator
 * @param q_limbs Quotient, qn = un - dn
 * @param n_limbs Numerator
 * @param nn Length of the numerator and denominator
 * @param d_limbs Denominator (must be odd)
 * @param dn Length of the numerator and denominator
 * @param dinv (-d)^-1 mod B
 */
template<typename T>
void mpbase<T>::general_bdiv_q(T* q_limbs, T* n_limbs, size_t nn, const T* d_limbs, size_t dn, T dinv)
{
    assert(dn >= 2);
    assert(nn - dn >= 0);
    assert(d_limbs[0] & 1);

    size_t qn;
    T cy;
    phantom_vector<T> tpvec(dn);
    T* tp = tpvec.data();

    qn = nn;

    if (qn > dn) {
        // Reduce qn mod dn in a super-efficient manner
        do {
            qn -= dn;
        } while (qn > dn);

        // Perform the typically smaller block first
        if (BELOW_THRESHOLD(qn, BASECASE_BDIV_QR_THRESHOLD)) {
            cy = basecase_bdiv_qr(q_limbs, n_limbs, 2 * qn, d_limbs, qn, dinv);
        }
        else {
            cy = general_bdiv_qr_n(q_limbs, n_limbs, d_limbs, qn, dinv, tp);
        }

        if (qn != dn) {
            if (qn > dn - qn) {
                mul(tp, q_limbs, qn, d_limbs + qn, dn - qn);
            }
            else {
                mul(tp, d_limbs + qn, dn - qn, q_limbs, qn);
            }
            incr_u(tp + qn, cy);

            add(n_limbs + qn, n_limbs + qn, nn - qn, tp, dn);
            cy = 0;
        }

        n_limbs += qn;
        q_limbs += qn;

        qn = nn - qn;
        while (qn > dn) {
            add_1(n_limbs + dn, n_limbs + dn, qn - dn, cy);
            cy = general_bdiv_qr_n(q_limbs, n_limbs, d_limbs, dn, dinv, tp);
            q_limbs += dn;
            n_limbs += dn;
            qn -= dn;
        }
        general_bdiv_q_n(q_limbs, n_limbs, d_limbs, dn, dinv, tp);
    }
    else {
        if (BELOW_THRESHOLD(qn, BDIV_Q_THRESHOLD)) {
            basecase_bdiv_q(q_limbs, n_limbs, qn, d_limbs, qn, dinv);
        }
        else {
            general_bdiv_q_n(q_limbs, n_limbs, d_limbs, qn, dinv, tp);
        }
    }
}

/**
 * @brief Division, q = -n * d^{-1} mod B^nn, destroys numerator
 * @param q_limbs Quotient
 * @param n_limbs Numerator
 * @param d_limbs Denominator (must be odd)
 * @param n Length of the numerator and denominator
 * @param dinv (-d)^-1 mod B
 * @param scratch Intermediate storage of floor(n/2) words
 * @return 1 if numerator is grater than or equal to the denominator
 */
template<typename T>
T mpbase<T>::general_div_qr_n(T* q_limbs, T* n_limbs, const T* d_limbs, size_t n, T dinv, T* scratch)
{
    size_t lo, hi;
    T cy, qh, ql;

    lo = n >> 1;          // floor(n/2)
    hi = n - lo;          // ceil(n/2)

    if (BELOW_THRESHOLD (hi, DIV_QR_THRESHOLD))
        qh = basecase_div_qr(q_limbs + lo, n_limbs + 2 * lo, 2 * hi, d_limbs + lo, hi, dinv);
    else
        qh = general_div_qr_n(q_limbs + lo, n_limbs + 2 * lo, d_limbs + lo, hi, dinv, scratch);

    mul(scratch, q_limbs + lo, hi, d_limbs, lo);

    cy = sub_n(n_limbs + lo, n_limbs + lo, scratch, n);
    if (qh != 0)
        cy += sub_n(n_limbs + n, n_limbs + n, d_limbs, lo);

    while (cy != 0)
    {
        qh -= sub_1(q_limbs + lo, q_limbs + lo, hi, 1);
        cy -= add_n(n_limbs + lo, n_limbs + lo, d_limbs, n);
    }

    if (BELOW_THRESHOLD (lo, DIV_QR_THRESHOLD))
        ql = basecase_div_qr(q_limbs, n_limbs + hi, 2 * lo, d_limbs + hi, lo, dinv);
    else
        ql = general_div_qr_n(q_limbs, n_limbs + hi, d_limbs + hi, lo, dinv, scratch);

    mul(scratch, d_limbs, hi, q_limbs, lo);

    cy = sub_n(n_limbs, n_limbs, scratch, n);
    if (ql != 0)
        cy += sub_n(n_limbs + lo, n_limbs + lo, d_limbs, hi);

    while (cy != 0)
    {
        sub_1(q_limbs, q_limbs, lo, 1);
        cy -= add_n(n_limbs, n_limbs, d_limbs, n);
    }

    return qh;
}

/**
 * @brief Division, q = -n * d^{-1} mod B^nn, destroys numerator
 * @param q_limbs Quotient
 * @param n_limbs Numerator
 * @param nn Length of the numerator
 * @param d_limbs Denominator (must be odd)
 * @param dn Length of the denominator
 * @param dinv (-d)^-1 mod B
 * @return 1 if numerator is grater than or equal to the denominator
 */
template<typename T>
T mpbase<T>::general_div_qr(T* q_limbs, T* n_limbs, size_t nn, const T* d_limbs, size_t dn, T dinv)
{
    size_t qn;
    T qh, cy;
    phantom_vector<T> tpvec(dn);
    T* tp = tpvec.data();

    assert(dn >= 6);
    assert(nn - dn >= 3);
    assert(d_limbs[dn-1] & LIMB_HIGHBIT);

    qn = nn - dn;
    q_limbs += qn;
    n_limbs += nn;
    d_limbs += dn;

    if (qn > dn) {
        // Reduce qn mod dn without division, optimizing small operations
        do {
            qn -= dn;
        } while (qn > dn);

        q_limbs -= qn;         // Quotient points at the low limb of the next quotient block
        n_limbs -= qn;         // Numerator points in the middle of the partial remainder

        if (qn == 1) {
            T q, n2, n1, n0, d1, d0;

            qh = cmp(n_limbs - dn + 1, d_limbs - dn, dn) >= 0;
            if (qh) {
                sub_n(n_limbs - dn + 1, n_limbs - dn + 1, d_limbs - dn, dn);
            }

            n2 = n_limbs[0];
            n1 = n_limbs[-1];
            n0 = n_limbs[-2];
            d1 = d_limbs[-1];
            d0 = d_limbs[-2];

            assert(n2 < d1 || (n2 == d1 && n1 <= d0));

            if ((n2 == d1) && n1 == d0) {
                q = LIMB_MASK;
                cy = submul_1(n_limbs - dn, d_limbs - dn, dn, q);
                assert(cy == n2);
            }
            else {
                number<T>::udiv_qrnnndd_preinv(&q, &n1, &n0, n2, n1, n0, d1, d0, dinv);

                if (dn > 2) {
                    T cy, cy1;
                    cy = submul_1(n_limbs - dn, d_limbs - dn, dn - 2, q);

                    cy1 = n0 < cy;
                    n0 = (n0 - cy) & LIMB_MASK;
                    cy = n1 < cy1;
                    n1 = (n1 - cy1) & LIMB_MASK;
                    n_limbs[-2] = n0;

                    if (cy != 0) {
                        n1 += d1 + add_n(n_limbs - dn, n_limbs - dn, d_limbs - dn, dn - 1);
                        qh -= (q == 0);
                        q = (q - 1) & LIMB_MASK;
                    }
                }
                else {
                    n_limbs[-2] = n0;
                }

                n_limbs[-1] = n1;
            }
            q_limbs[0] = q;
        }
        else {
            if (qn == 2) {
                qh = divrem_2(q_limbs, 0L, n_limbs - 2, 4, d_limbs - 2);
            }
            else if (BELOW_THRESHOLD(qn, DIV_QR_THRESHOLD)) {
                qh = basecase_div_qr(q_limbs, n_limbs - qn, 2 * qn, d_limbs - qn, qn, dinv);
            }
            else {
                qh = general_div_qr_n(q_limbs, n_limbs - qn, d_limbs - qn, qn, dinv, tp);
            }

            if (qn != dn) {
                if (qn > dn - qn) {
                    mul(tp, q_limbs, qn, d_limbs - dn, dn - qn);
                }
                else {
                    mul(tp, d_limbs - dn, dn - qn, q_limbs, qn);
                }

                cy = sub_n(n_limbs - dn, n_limbs - dn, tp, dn);
                if (qh != 0) {
                    cy += sub_n(n_limbs - dn + qn, n_limbs - dn + qn, d_limbs - dn, dn - qn);
                }

                while (cy != 0) {
                    qh -= sub_1(q_limbs, q_limbs, qn, 1);
                    cy -= add_n(n_limbs - dn, n_limbs - dn, d_limbs - dn, dn);
                }
            }
        }

        qn = nn - dn - qn;
        do {
            q_limbs -= dn;
            n_limbs -= dn;
            general_div_qr_n(q_limbs, n_limbs - dn, d_limbs - dn, dn, dinv, tp);
            qn -= dn;
        } while (qn > 0);
    }
    else {
        q_limbs -= qn;         // Quotient points at the low limb of the next quotient block
        n_limbs -= qn;         // Numerator points in the middle of the partial remainder

        if (BELOW_THRESHOLD(qn, DIV_QR_THRESHOLD)) {
            qh = basecase_div_qr(q_limbs, n_limbs - qn, 2 * qn, d_limbs - qn, qn, dinv);
        }
        else {
            qh = general_div_qr_n(q_limbs, n_limbs - qn, d_limbs - qn, qn, dinv, tp);
        }

        if (qn != dn) {
            if (qn > dn - qn) {
                mul(tp, q_limbs, qn, d_limbs - dn, dn - qn);
            }
            else {
                mul(tp, d_limbs - dn, dn - qn, q_limbs, qn);
            }

            cy = sub_n(n_limbs - dn, n_limbs - dn, tp, dn);
            if (qh != 0) {
                cy += sub_n(n_limbs - dn + qn, n_limbs - dn + qn, d_limbs - dn, dn - qn);
            }

            while (cy != 0) {
                qh -= sub_1(q_limbs, q_limbs, qn, 1);
                cy -= add_n(n_limbs - dn, n_limbs - dn, d_limbs - dn, dn);
            }
        }
    }

    return qh;
}

/**
 * @brief Hensel binary division of equal length numerator and denominator
 * @param q_limbs Quotient, q = -n * d^{-1} mod 2^{qn * log2(B)}
 * @param n_limbs Numerator and remainder returned in nn high half limbs (r = (n + q * d) * 2^{-qn * log2(B)})
 * @param d_limbs Denominator (must be odd)
 * @param n Length of the numerator and denominator
 * @param dinv (-d)^-1 mod B
 * @param scratch Temporary storage
 * @return Carry from addition n + q*d
 */
template<typename T>
T mpbase<T>::general_bdiv_qr_n(T* q_limbs, T* n_limbs, const T* d_limbs, size_t n, T dinv, T* scratch)
{
    size_t lo, hi;
    T cy;
    T rh;

    lo = n >> 1;          // floor(n/2)
    hi = n - lo;          // ceil(n/2)

    if (BELOW_THRESHOLD (lo, BASECASE_BDIV_QR_THRESHOLD))
        cy = basecase_bdiv_qr(q_limbs, n_limbs, 2 * lo, d_limbs, lo, dinv);
    else
        cy = general_bdiv_qr_n(q_limbs, n_limbs, d_limbs, lo, dinv, scratch);

    mul(scratch, d_limbs + lo, hi, q_limbs, lo);

    incr_u(scratch + lo, cy);
    rh = add(n_limbs + lo, n_limbs + lo, n + hi, scratch, n);

    if (BELOW_THRESHOLD (hi, BASECASE_BDIV_QR_THRESHOLD))
        cy = basecase_bdiv_qr(q_limbs + lo, n_limbs + lo, 2 * hi, d_limbs, hi, dinv);
    else
        cy = general_bdiv_qr_n(q_limbs + lo, n_limbs + lo, d_limbs, hi, dinv, scratch);

    mul(scratch, q_limbs + lo, hi, d_limbs + hi, lo);

    incr_u(scratch + hi, cy);
    rh += add_n(n_limbs + n, n_limbs + n, scratch, n);

    return rh;
}

/**
 * @brief Hensel binary division of different length numerator and denominator
 * @param q_limbs Quotient, q = -n * d^{-1} mod 2^{qn * log2(B)}
 * @param n_limbs Numerator and remainder returned in nn high half limbs (r = (n + q * d) * 2^{-qn * log2(B)})
 * @param nn Length of the numerator
 * @param d_limbs Denominator (must be odd)
 * @param dn Length of the denominator
 * @param dinv (-d)^-1 mod B
 * @return Carry from addition n + q*d
 */
template<typename T>
T mpbase<T>::general_bdiv_qr(T* q_limbs, T* n_limbs, size_t nn, const T* d_limbs, size_t dn, T dinv)
{
    size_t qn;
    phantom_vector<T> tpvec(dn);
    T* tp = tpvec.data();
    T cy, rr;

    assert(dn >= 2);
    assert(nn - dn >= 1);
    assert(d_limbs[0] & 1);

    qn = nn - dn;

    if (qn > dn) {
        // Reduce qn mod dn without division
        do {
            qn -= dn;
        } while (qn > dn);

        if (BELOW_THRESHOLD(qn, BASECASE_BDIV_QR_THRESHOLD)) {
            cy = basecase_bdiv_qr(q_limbs, n_limbs, 2 * qn, d_limbs, qn, dinv);
        }
        else {
            cy = general_bdiv_qr_n(q_limbs, n_limbs, d_limbs, qn, dinv, tp);
        }

        rr = 0;
        if (qn != dn) {
            if (qn > dn - qn)
                mul(tp, q_limbs, qn, d_limbs + qn, dn - qn);
            else
                mul(tp, d_limbs + qn, dn - qn, q_limbs, qn);
            incr_u(tp + qn, cy);

            rr = add(n_limbs + qn, n_limbs + qn, nn - qn, tp, dn);
            cy = 0;
        }

        n_limbs += qn;
        q_limbs += qn;

        qn = nn - dn - qn;
        do {
            rr += add_1(n_limbs + dn, n_limbs + dn, qn, cy);
            cy = general_bdiv_qr_n(q_limbs, n_limbs, d_limbs, dn, dinv, tp);
            q_limbs += dn;
            n_limbs += dn;
            qn -= dn;
        } while (qn > 0);
        return rr + cy;
    }

    if (BELOW_THRESHOLD(qn, BASECASE_BDIV_QR_THRESHOLD)) {
        cy = basecase_bdiv_qr(q_limbs, n_limbs, 2 * qn, d_limbs, qn, dinv);
    }
    else {
        cy = general_bdiv_qr_n(q_limbs, n_limbs, d_limbs, qn, dinv, tp);
    }

    rr = 0;
    if (qn != dn) {
        if (qn > dn - qn) {
            mul(tp, q_limbs, qn, d_limbs + qn, dn - qn);
        }
        else {
            mul(tp, d_limbs + qn, dn - qn, q_limbs, qn);
        }
        incr_u(tp + qn, cy);

        rr = add(n_limbs + qn, n_limbs + qn, nn - qn, tp, dn);
        cy = 0;
    }

    return rr + cy;
}

/**
 * @brief Division with truncation
 * @param q_limbs Quotient
 * @param n_limbs Remainder
 * @param n_limbs Numerator
 * @param nn Length of the numerator
 * @param d_limbs Denominator (must be odd)
 * @param dn Length of the denominator
 */
template<typename T>
void mpbase<T>::tdiv_qr(T* q_limbs, T* r_limbs, const T* n_limbs, size_t nn, const T* d_limbs, size_t dn)
{
    assert(nn >= 0);
    assert(dn >= 0);
    assert(dn == 0 || d_limbs[dn - 1] != 0);
    assert(!OVERLAP_P(q_limbs, nn - dn + 1, n_limbs, nn));
    assert(!OVERLAP_P(q_limbs, nn - dn + 1, d_limbs, dn));

    switch (dn)
    {
    case 0:
    {
        throw std::runtime_error("denominator is zero");
    }

    case 1:
    {
        r_limbs[0] = div_qr_1(q_limbs, n_limbs, nn, d_limbs[0]);
        return;
    }

    case 2:
    {
        phantom_vector<T> n2p(nn + 1);
        if ((d_limbs[1] & LIMB_HIGHBIT) == 0) {
            T d2p[2];
            int cnt = bit_manipulation::clz(d_limbs[1]);
            d2p[1] = (d_limbs[1] << cnt) | (d_limbs[0] >> (std::numeric_limits<T>::digits - cnt));
            d2p[0] = (d_limbs[0] << cnt) & LIMB_MASK;
            T cy = lshift(n2p.data(), n_limbs, nn, cnt);
            n2p[nn] = cy;
            T qhl = divrem_2(q_limbs, 0, n2p.data(), nn + (cy != 0), d2p);
            if (cy == 0) {
                q_limbs[nn - 2] = qhl;  // always store nn-2+1 quotient limbs
            }
            r_limbs[0] = (n2p[0] >> cnt)
                | ((n2p[1] << (std::numeric_limits<T>::digits - cnt)) & LIMB_MASK);
            r_limbs[1] = (n2p[1] >> cnt);
        }
        else {
            copy(n2p.data(), n_limbs, nn);
            T qhl = divrem_2(q_limbs, 0, n2p.data(), nn, d_limbs);
            q_limbs[nn - 2] = qhl;   // always store nn-2+1 quotient limbs
            r_limbs[0] = n2p[0];
            r_limbs[1] = n2p[1];
        }
        return;
    }

    default:
    {
        T dinv;
        int adjust = n_limbs[nn - 1] >= d_limbs[dn - 1];  // conservative tests for quotient size
        if (nn + adjust >= 2 * dn)
        {
            phantom_vector<T> n2pvec, d2pvec;
            T *d2p, *n2p;
            size_t cnt = 0;

            q_limbs[nn - dn] = 0;              // zero high quotient limb
            if ((d_limbs[dn - 1] & LIMB_HIGHBIT) == 0) {  // normalize divisor
                size_t cnt = bit_manipulation::clz(d_limbs[dn - 1]);
                d2pvec.resize(dn);
                d2p = d2pvec.data();
                lshift(d2p, d_limbs, dn, cnt);
                n2pvec.resize(nn + 1);
                n2p = n2pvec.data();
                T cy = lshift(n2p, n_limbs, nn, cnt);
                n2p[nn] = cy;
                nn += adjust;
            }
            else {
                d2p = const_cast<T*>(d_limbs);
                n2pvec.resize(nn + 1);
                n2p = n2pvec.data();
                copy(n2p, n_limbs, nn);
                n2p[nn] = 0;
                nn += adjust;
            }

            mod_metadata<T> mod;
            mod.init_2(d2p[dn - 1], d2p[dn - 2]);
            dinv = mod.m_inv;

            if (BELOW_THRESHOLD(dn, DIV_QR_THRESHOLD)) {
                basecase_div_qr(q_limbs, n2p, nn, d2p, dn, dinv);
            }
            else if (BELOW_THRESHOLD(dn, MU_DEN_DIV_QR_THRESHOLD) ||    // fast condition
                        BELOW_THRESHOLD(nn, 2 * MU_DIV_QR_THRESHOLD) ||  // fast condition
                        // slow condition
                        static_cast<double>(2 * (MU_DIV_QR_THRESHOLD - MU_DEN_DIV_QR_THRESHOLD)) * dn
                        + static_cast<double>(MU_DEN_DIV_QR_THRESHOLD) * nn > static_cast<double>(dn) * nn) {
                general_div_qr(q_limbs, n2p, nn, d2p, dn, dinv);
            }
            else {
                size_t itch = mu_div_qr_scratch_size(nn, dn);
                phantom_vector<T> scratch(itch);
                mu_div_qr(q_limbs, r_limbs, n2p, nn, d2p, dn, scratch.data());
                n2p = r_limbs;
            }

            if (cnt != 0) {
                rshift(r_limbs, n2p, dn, cnt);
            }
            else {
                copy(r_limbs, n2p, dn);
            }
            return;
        }

        // The numerator/partial remainder is now less than twice the size of the denominator

        {
            // Problem:
            //    Divide a numerator with nn limbs by a denominator with dn limbs forming
            //    a quotient of qn=nn-dn+1 limbs. We use an algorithm that has an expected
            //    running time that is dependent on qn.
            //    1) Divide the 2 qn most significant limbs from the numerator by the qn
            //       most significant limbs from the denominator to obtain an estimate of
            //       the quotient that may be 1 or 2 limbs too large. Compute the remainder
            //       from the division.
            //    2) If the most significant limb from the remainder < p, where p is the
            //       product of the most significant limb from the quotient and the the next
            //       ignored limb from the denominator we decrement the quotient estimate and
            //       adjust the remainder.
            //    3) If the remainder >= the quotient estimate then the quotient has been found.
            //    4) Othwerwise, subtract the quotient estimate times the next ignored limb
            //       of the denominator from the remainder. If the quotient is too large then
            //       decrement the quotient estimate and adjust the remainder.
            //    5) Skip one word from the denominator.

            T* tp;
            T cy;
            size_t in, rn;
            T quotient_too_large;
            size_t cnt;

            size_t qn = nn - dn;
            q_limbs[qn] = 0;             // zero high quotient limb
            qn += adjust;                // qn cannot become bigger

            if (0 == qn) {
                copy(r_limbs, n_limbs, dn);
                return;
            }

            phantom_vector<T> n2pvec(2 * qn + 1), d2pvec, tpvec;
            T* n2p = n2pvec.data();
            T* d2p;

            in = dn - qn;

            // Normalize denominator by shifting to the left to set the MSB, mirror the
            // shift with the numerator
            if (0 == (d_limbs[dn - 1] & LIMB_HIGHBIT)) {
                cnt = bit_manipulation::clz(d_limbs[dn - 1]);

                d2pvec.resize(qn);
                d2p = d2pvec.data();
                lshift(d2p, d_limbs + in, qn, cnt);
                d2p[0] |= d_limbs[in - 1] >> (std::numeric_limits<T>::digits - cnt);

                cy = lshift(n2p, n_limbs + nn - 2 * qn, 2 * qn, cnt);
                if (adjust) {
                    n2p[2 * qn] = cy;
                    n2p++;
                }
                else {
                    n2p[0] |= n_limbs[nn - 2 * qn - 1] >> (std::numeric_limits<T>::digits - cnt);
                }
            }
            else {
                cnt = 0;
                d2p = const_cast<T*>(d_limbs) + in;

                copy(n2p, n_limbs + nn - 2 * qn, 2 * qn);
                if (adjust) {
                    n2p[2 * qn] = 0;
                    n2p++;
                }
            }

            // Get an approximate quotient using the extracted operands
            if (1 == qn) {
                T q0, r0;
                number<T>::udiv_qrnnd(&q0, &r0, n2p[1], n2p[0], d2p[0]);
                n2p[0] = r0;
                q_limbs[0] = q0;
            }
            else if (qn == 2) {
                divrem_2(q_limbs, 0L, n2p, 4L, d2p);
            }
            else
            {
                mod_metadata<T> mod;
                mod.init_2(d2p[qn - 1], d2p[qn - 2]);
                dinv = mod.m_inv;

                if (BELOW_THRESHOLD(qn, DIV_QR_THRESHOLD)) {
                    basecase_div_qr(q_limbs, n2p, 2 * qn, d2p, qn, dinv);
                }
                else if (BELOW_THRESHOLD(qn, MU_DIV_QR_THRESHOLD)) {
                    general_div_qr(q_limbs, n2p, 2 * qn, d2p, qn, dinv);
                }
                else {
                    size_t itch = mu_div_qr_scratch_size(2 * qn, qn);
                    phantom_vector<T> scratch(itch);
                    T* r2p = r_limbs;

                    // If numerator and remainder are at same location move the remainder to upper words
                    if (n_limbs == r2p) {
                        r2p += nn - qn;
                    }
                    mu_div_qr(q_limbs, r2p, n2p, 2 * qn, d2p, qn, scratch.data());
                    copy(n2p, r2p, qn);
                }
            }

            rn = qn;

            // Multiply the first ignored divisor limb by the most significant quotient
            // limb. If that product is > the partial remainder's most significant limb
            // then the quotient estimate is too big.
            {
                T dl, x;
                T h, dummy;

                if (in - 2 < 0)
                    dl = 0;
                else
                    dl = d_limbs[in - 2];

                x = (d_limbs[in - 1] << cnt) | ((dl >> 1) >> ((~cnt) & ((1 << bits_log2<T>::value()) - 1)));
                number<T>::umul(&h, &dummy, x, q_limbs[qn - 1]);

                if (n2p[qn - 1] < h) {
                    decr_u(q_limbs, T(1));
                    T cy = add_n(n2p, n2p, d2p, qn);
                    if (cy) {
                        // The partial remainder is safely large
                        n2p[qn] = cy;
                        ++rn;
                    }
                }
            }

            quotient_too_large = 0;
            if (cnt != 0) {
                T cy1, cy2;

                // Append partially used numerator limb to partial remainder
                cy1 = lshift(n2p, n2p, rn, std::numeric_limits<T>::digits - cnt);
                n2p[0] |= n_limbs[in - 1] & (LIMB_MASK >> cnt);

                // Update partial remainder with partially used divisor limb
                cy2 = submul_1(n2p, q_limbs, qn, d_limbs[in - 1] & (LIMB_MASK >> cnt));
                if (qn != rn) {
                    n2p[qn] -= cy2;
                }
                else {
                    n2p[qn] = cy1 - cy2;

                    quotient_too_large = (cy1 < cy2);
                    ++rn;
                }
                --in;
            }

            // Partial remainder at this point has been un-normalized

            tpvec.resize(dn);
            tp = tpvec.data();

            // Recover the remainder
            if (in < qn) {
                if (0 == in) {
                    copy(r_limbs, n2p, rn);
                    goto finish;
                }
                mul(tp, q_limbs, qn, d_limbs, in);
            }
            else {
                mul(tp, d_limbs, in, q_limbs, qn);
            }

            cy = sub(n2p, n2p, rn, tp + in, qn);
            copy(r_limbs + in, n2p, dn - in);
            quotient_too_large |= cy;
            cy = sub_n(r_limbs, n_limbs, tp, in);
            cy = sub_1(r_limbs + in, r_limbs + in, rn, cy);
            quotient_too_large |= cy;
    finish:
            // Update the quotient and remainder if we had any carrys bits
            if (quotient_too_large) {
                decr_u(q_limbs, T(1));
                add_n(r_limbs, r_limbs, d_limbs, dn);
            }
        }
        return;
    }
    }
}

/**
 * @brief Determine if a is divisible by a denominator d without remainder
 * @param a_limbs Quotient
 * @param an Length of the numerator
 * @param d_limbs Denominator (must be odd)
 * @param dn Length of the denominator
 * @return 1 if remainder is non-zero, 0 otherwise
 */
template<typename T>
int mpbase<T>::divisible_p(const T *a_limbs, size_t an, const T *d_limbs, size_t dn)
{
    T alow, dlow, dmask;
    T *q_limbs, *r_limbs, *tp;
    size_t  i;
    T di;
    unsigned twos;

    assert(an >= 0);
    assert(an == 0 || a_limbs[an-1] != 0);
    assert(dn >= 1);
    assert(d_limbs[dn-1] != 0);

    // When a<d || an==0 only a==0 is divisible (dn is guaranteed to be greater than 0)
    if (an < dn) {
        return (an == 0);
    }

    // Iteratively remove least significant zero limbs from d
    for (;;)
    {
        alow = *a_limbs;
        dlow = *d_limbs;

        if (dlow != 0) {
            break;
        }

        if (alow != 0) {
            // a has fewer low zero limbs than d, so not divisible
            return 0;
        }

        // a!=0 and d!=0
        an--;
        assert(an >= 1);
        dn--;
        assert(dn >= 1);
        a_limbs++;
        d_limbs++;
    }

    // a must have at least as many low zero bits as the denominator d
    dmask = (dlow & -dlow) - 1;
    if (alow & dmask) {
        return 0;
    }

    if (dn == 1) {
        return mod_1(a_limbs, an, dlow) == 0;
    }

    if (dn == 2) {
        T dsecond = d_limbs[1];
        if (dsecond <= dmask) {
            twos = bit_manipulation::ctz(dlow);
            dlow = (dlow >> twos) | (dsecond << (std::numeric_limits<T>::digits - twos));
            assert(dlow);
            return (an < 0) ? modexact_1_odd(a_limbs, an, dlow)
                            : mod_1(a_limbs, an, dlow);
        }
    }

    // Allocate memory for the quotient and remainder
    r_limbs = reinterpret_cast<T*>(aligned_malloc((an + 1) * sizeof(T)));
    q_limbs = reinterpret_cast<T*>(aligned_malloc((an - dn + 1) * sizeof(T)));

    // If there are trailing zeros we normalize the denominator and remainder
    twos = bit_manipulation::ctz(d_limbs[0]);
    if (twos != 0) {
        tp = reinterpret_cast<T*>(aligned_malloc(dn * sizeof(T)));
        rshift(tp, d_limbs, dn, twos);
        d_limbs = tp;
        rshift(r_limbs, a_limbs, an, twos);
    }
    else {
        copy(r_limbs, a_limbs, an);
    }

    // If the remainder is small enough we canfree memory and exit,
    // otherwise we must compensate
    if (r_limbs[an - 1] >= d_limbs[dn - 1]) {
        r_limbs[an] = 0;
        an++;
    }
    else if (an == dn) {
        aligned_free(r_limbs);
        aligned_free(q_limbs);
        if (twos != 0) {
            aligned_free(tp);
        }
        return 0;
    }

    assert(an > dn);  // requirement of functions below

    // Solve the now simplified problem
    div_qr(q_limbs, r_limbs, an, d_limbs, dn);
    r_limbs += an - dn;

    // Test for {r_limbs,dn} zero or non-zero
    i = 0;
    do {
        if (r_limbs[i] != 0) {
            aligned_free(r_limbs);
            aligned_free(q_limbs);
            if (twos != 0) {
                aligned_free(tp);
            }
            return 0;
        }
    } while (++i < dn);

    aligned_free(r_limbs);
    aligned_free(q_limbs);
    if (twos != 0) {
        aligned_free(tp);
    }
    return 1;
}

/**
 * @brief Limb inversion (multiplicative inverse)
 * @param n Value to invert (must be odd)
 * @return Inverted value, i.e. n * inv = 1 (mod B)
 */
template<typename T>
T mpbase<T>::binvert_limb(T n)
{
    const uint8_t binvert_limb_lut[128] = {
        0x01, 0xAB, 0xCD, 0xB7, 0x39, 0xA3, 0xC5, 0xEF,
        0xF1, 0x1B, 0x3D, 0xA7, 0x29, 0x13, 0x35, 0xDF,
        0xE1, 0x8B, 0xAD, 0x97, 0x19, 0x83, 0xA5, 0xCF,
        0xD1, 0xFB, 0x1D, 0x87, 0x09, 0xF3, 0x15, 0xBF,
        0xC1, 0x6B, 0x8D, 0x77, 0xF9, 0x63, 0x85, 0xAF,
        0xB1, 0xDB, 0xFD, 0x67, 0xE9, 0xD3, 0xF5, 0x9F,
        0xA1, 0x4B, 0x6D, 0x57, 0xD9, 0x43, 0x65, 0x8F,
        0x91, 0xBB, 0xDD, 0x47, 0xC9, 0xB3, 0xD5, 0x7F,
        0x81, 0x2B, 0x4D, 0x37, 0xB9, 0x23, 0x45, 0x6F,
        0x71, 0x9B, 0xBD, 0x27, 0xA9, 0x93, 0xB5, 0x5F,
        0x61, 0x0B, 0x2D, 0x17, 0x99, 0x03, 0x25, 0x4F,
        0x51, 0x7B, 0x9D, 0x07, 0x89, 0x73, 0x95, 0x3F,
        0x41, 0xEB, 0x0D, 0xF7, 0x79, 0xE3, 0x05, 0x2F,
        0x31, 0x5B, 0x7D, 0xE7, 0x69, 0x53, 0x75, 0x1F,
        0x21, 0xCB, 0xED, 0xD7, 0x59, 0xC3, 0xE5, 0x0F,
        0x11, 0x3B, 0x5D, 0xC7, 0x49, 0x33, 0x55, 0xFF
    };

    assert((n & 1) == 1);

    T inv = binvert_limb_lut[(n/2) & 0x7F];                                   // 8-bit
    if (std::numeric_limits<T>::digits > 8)   inv = 2 * inv - inv * inv * n;  // 16-bit
    if (std::numeric_limits<T>::digits > 16)  inv = 2 * inv - inv * inv * n;  // 32-bit
    if (std::numeric_limits<T>::digits > 32)  inv = 2 * inv - inv * inv * n;  // 64-bit
    if (std::numeric_limits<T>::digits > 64)                                  // > 64-bit
    {
        int invbits = 64;
        do {
            inv      = 2 * inv - inv * inv * n;
            invbits *= 2;
        } while (invbits < std::numeric_limits<T>::digits);
    }

    assert(T(inv * n) == 1);
    return inv;
}

/**
 * @brief Memory required for mulmod calculation
 * @param rn Modulus length
 * @param an A length
 * @param bn B length
 * @return Memory requirement
 */
template<typename T>
size_t mpbase<T>::mulmod_bnm1_size(size_t rn, size_t an, size_t bn)
{
    size_t n    = rn >> 1;
    size_t itch = rn + 4 + (an > n ? (bn > n ? rn : n) : 0);
    return itch;
}

/**
 * @brief Memory required for mulmod next iteration
 * @param nLength of array
 * @return Memory requirement
 */
template<typename T>
size_t mpbase<T>::mulmod_bnm1_next_size(size_t n)
{
    size_t nh;

    if (BELOW_THRESHOLD(n,      MULMOD_BNM1_THRESHOLD)) {
        return n;
    }
    if (BELOW_THRESHOLD(n, 4 * (MULMOD_BNM1_THRESHOLD - 1) + 1)) {
        return (n + (2-1)) & (-2);
    }
    if (BELOW_THRESHOLD(n, 8 * (MULMOD_BNM1_THRESHOLD - 1) + 1)) {
        return (n + (4-1)) & (-4);
    }

    nh = (n + 1) >> 1;

    return (n + (8-1)) & (-8);
}

/**
 * @brief Memory required for powm() intermediate storage
 * @param n Length of array
 * @return Memory requirement
 */
template<typename T>
size_t mpbase<T>::binvert_powm_scratch_size(size_t n)
{
    size_t itch_local = mulmod_bnm1_next_size(n);
    size_t itch_out   = mulmod_bnm1_size(itch_local, n, (n + 1) >> 1);
    return itch_local + itch_out;
}

/**
 * @brief Multiplicative inverse
 * @param r_limbs Output
 * @param u_limbs Input
 * @param n Length of array
 * @param scratch Intermediate storage
 * @return Memory requirement
 */
template<typename T>
void mpbase<T>::binvert(T* r_limbs, const T* u_limbs, size_t n, T* scratch)
{
    size_t rn;
    size_t sizes[INV_SIZE_PREC];

    // Compute the computation precisions from highest to lowest, leaving the
    // base case size in rn
    size_t* sizp = sizes;
    for (rn = n; ABOVE_THRESHOLD(rn, BINV_NEWTON_THRESHOLD); rn = (rn + 1) >> 1) {
        *sizp++ = rn;
    }

    T* xp = scratch;

    // Compute a base value of rn limbs
    zero(xp, rn);
    xp[0] = 1;
    T di = binvert_limb(u_limbs[0]);
    if (BELOW_THRESHOLD(rn, BDIV_Q_THRESHOLD)) {
        basecase_bdiv_q(r_limbs, xp, rn, u_limbs, rn, -di);
    }
    else {
        general_bdiv_q(r_limbs, xp, rn, u_limbs, rn, -di);
    }

    negate(r_limbs, r_limbs, rn);

    // Use Newton iterations to get the desired precision
    size_t newrn;
    for (; rn < n; rn = newrn) {
        newrn = *--sizp;

        // X <- UR
        size_t m = mulmod_bnm1_next_size(newrn);
        mulmod_bnm1(xp, m, u_limbs, newrn, r_limbs, rn, xp + m);
        sub_1(xp + m, xp, rn - (m - newrn), 1);

        // R = R(X/B^rn)
        mul_low_n(r_limbs + rn, r_limbs, xp + rn, newrn - rn);
        negate(r_limbs + rn, r_limbs + rn, newrn - rn);
    }
}

/**
 * @brief Modular reduction satisfying r*B^k + a - c == q*d, If c<d then r will be in
 * the range 0<=r<d, or if c>=d then 0<=r<=d
 * @param in Input
 * @param n Length of input data array
 * @param d Single word denominator (must be odd)
 * @return Result
 */
template<typename T>
T mpbase<T>::modexact_1_odd(const T* in, size_t n, T d)
{
    T s, x, y, inverse, dummy, dmul, c1, c2;
    T c = 0;
    T h = 0;

    assert(n >= 1);
    assert(d & 1);

    inverse = binvert_limb(d);
    dmul = d;

    for (size_t i=0; i < n; i++) {
        assert(c == 0 || c == 1);

        s = in[i];
        x = s - c;
        c1 = x > s;
        y = x - h;
        c2 = y > x;
        c = c1 + c2;

        y = y * inverse;
        number<T>::umul(&h, &dummy, y, dmul);
    }

    h += c;
    return h;
}

/**
 * Modular reduction to a single limb word
 * @param n_limbs Numerator
 * @param n Length of the numerator
 * @param d_limb The single-limb denominator
 * @return Modulus
 */
template<typename T>
T mpbase<T>::mod_1(const T * n_limbs, size_t n, T d_limb)
{
    int normalization_steps;
    ssize_t i;
    T n1, n0, r;
    T dummy;

    if (n == 0) {
        return 0;
    }

    normalization_steps = bit_manipulation::clz(d_limb);
    if (0 != normalization_steps) {
        d_limb <<= normalization_steps;

        n1 = n_limbs[n - 1];
        r = n1 >> (std::numeric_limits<T>::digits - normalization_steps);

        for (i = n - 2; i >= 0; i--) {
            n0 = n_limbs[i];
            number<T>::udiv_qrnnd(&dummy, &r, r,
                (n1 << normalization_steps) | (n0 >> (std::numeric_limits<T>::digits - normalization_steps)),
                d_limb);
            n1 = n0;
        }
        number<T>::udiv_qrnnd(&dummy, &r, r, n1 << normalization_steps, d_limb);
        return r >> normalization_steps;
    }

    i = n - 1;
    r = n_limbs[i];

    if (r >= d_limb) {
        r = 0;
    }
    else {
        i--;
    }

    for (; i >= 0; i--) {
        n0 = n_limbs[i];
        number<T>::udiv_qrnnd(&dummy, &r, r, n0, d_limb);
    }

    return r;
}

/**
 * Base case for multiplication and modular reduction mod 2^n
 * @param r_limbs Residual
 * @param a_limbs A
 * @param b_limbs B
 * @param n Residual length in words
 * @param scratch Intermediate storage
 */
template<typename T>
void mpbase<T>::basecase_mulmod_bnm1(T* r_limbs, const T* a_limbs, const T* b_limbs, size_t n, T* scratch)
{
    assert(0 < n);
    mul_n(scratch, a_limbs, b_limbs, n);
    T cy = add_n(r_limbs, scratch, scratch + n, n);
    // If cy == 1 then r_limbs is at most B^rn - 2, so there can be no overflow
    add_1(r_limbs, r_limbs, n, cy);
}

/**
 * Base case for multiplication and modular reduction mod 2^(rn+1)
 * @param r_limbs Residual
 * @param a_limbs A
 * @param b_limbs B
 * @param n Residual length in words
 * @param scratch Intermediate storage
 */
template<typename T>
void mpbase<T>::bc_mulmod_bnp1(T* r_limbs, const T* a_limbs, const T* b_limbs, size_t n, T* scratch)
{
    assert(0 < n);
    mul_n(scratch, a_limbs, b_limbs, n + 1);
    assert(scratch[2*n+1] == 0);
    assert(scratch[2*n] < std::numeric_limits<T>::max());
    T cy = scratch[2*n] + sub_n(r_limbs, scratch, scratch + n, n);
    r_limbs[n] = 0;
    add_1(r_limbs, r_limbs, n + 1, cy);
}

/**
 * Multiplication and modular reduction to a word length
 * @param r_limbs Residual
 * @param rn Residual length
 * @param a_limbs A
 * @param an A length
 * @param b_limbs B
 * @param bn B length
 * @param scratch Intermediate storage
 */
template<typename T>
void mpbase<T>::mulmod_bnm1(T* r_limbs, size_t rn, const T* a_limbs, size_t an, const T* b_limbs, size_t bn, T* scratch)
{
    assert(0 < bn);
    assert(bn <= an);
    assert(an <= rn);

    if (bn < rn) {
        if (an + bn <= rn) {
            mul(r_limbs, a_limbs, an, b_limbs, bn);
        }
        else {
            mul(scratch, a_limbs, an, b_limbs, bn);
            T cy = add(r_limbs, scratch, rn, scratch + rn, an + bn - rn);
            add_1(r_limbs, r_limbs, rn, cy);
        }
    }
    else {
        basecase_mulmod_bnm1(r_limbs, a_limbs, b_limbs, rn, scratch);
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
