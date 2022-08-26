/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "core/mpbase.hpp"



#if NDEBUG
#define CARRY_ASSERT(x) \
    do                  \
    {                   \
        (x);            \
    } while (0)
#else
#define CARRY_ASSERT(x) \
    do                  \
    {                   \
        T cc = (x);     \
        assert(cc);     \
    } while (0)
#endif


namespace phantom {
namespace core {

template<typename T>
class toom_cook
{
public:

    /**
     * @brief Low-level recursive mul_toom22 decision (for equal length n)
     * 
     * @param out Output product
     * @param in1 Input 1 of length n
     * @param in2 Input 2 of length n
     * @param n Length of the input multiplicands
     * @param scratch Scratch memory
     */
    static void mul_toom22_n_recursive(T *out, const T *in1, const T *in2, size_t n, T *scratch)
    {
        if (BELOW_THRESHOLD(n, MUL_TOOM22_THRESHOLD)) {
            mpbase<T>::mul_gradeschool(out, in1, n, in2, n);
        }
        else {
            mpbase<T>::mul_toom22(out, in1, n, in2, n, scratch);
        }
    }

    /**
     * @brief Low-level recursive mul_toom22 decision 
     * 
     * @param out Output product
     * @param in1 Input 1 of length n1
     * @param n1 Length of the input 1
     * @param in2 Input 2 of length n2
     * @param n2 Length of the input 2
     * @param scratch Scratch memory
     */
    static void mul_toom22_recursive(T *out, const T *in1, size_t n1, const T *in2, size_t n2, T *scratch)
    {
        if (BELOW_THRESHOLD(n2, MUL_TOOM22_THRESHOLD)) {
            mpbase<T>::mul_gradeschool(out, in1, n1, in2, n2);
        }
        else if (4 * n1 < 5 * n2) {
            mpbase<T>::mul_toom22(out, in1, n1, in2, n2, scratch);
        }
        else {
            mpbase<T>::mul_toom32(out, in1, n1, in2, n2, scratch);
        }
    }

    /**
     * @brief Low-level recursive mul_toom33 decision (for equal length n)
     * 
     * @param out Output product
     * @param in1 Input 1 of length n
     * @param in2 Input 2 of length n
     * @param n Length of the input multiplicands
     * @param scratch Scratch memory
     */
    static void mul_toom33_n_recursive(T *out, const T *in1, const T *in2, size_t n, T *scratch)
    {
        if (BELOW_THRESHOLD(n, MUL_TOOM22_THRESHOLD)) {
            mpbase<T>::mul_gradeschool(out, in1, n, in2, n);
        }
        else if (BELOW_THRESHOLD(n, MUL_TOOM33_THRESHOLD)) {
            mpbase<T>::mul_toom22(out, in1, n, in2, n, scratch);
        }
        else {
            mpbase<T>::mul_toom33(out, in1, n, in2, n, scratch);
        }
    }

    /**
     * @brief Low-level recursive sqr_toom2 decision
     * 
     * @param out Output product
     * @param in Input of length n
     * @param n Length of the input multiplicands
     * @param scratch Scratch memory
     */
    static void sqr_toom2_recursive(T *out, const T *in, size_t n, T *scratch)
    {
        if (BELOW_THRESHOLD(n, SQR_TOOM2_THRESHOLD)) {
            mpbase<T>::sqr_gradeschool(out, in, n);
        }
        else {
            mpbase<T>::sqr_toom2(out, in, n, scratch);
        }
    }

    /**
     * @brief Low-level recursive sqr_toom3 decision
     * 
     * @param out Output product
     * @param in Input of length n
     * @param n Length of the input multiplicands
     * @param scratch Scratch memory
     */
    static void sqr_toom3_recursive(T *out, const T *in, size_t n, T *scratch)
    {
        if (BELOW_THRESHOLD(n, SQR_TOOM2_THRESHOLD)) {
            mpbase<T>::sqr_gradeschool(out, in, n);
        }
        else if (BELOW_THRESHOLD(n, SQR_TOOM3_THRESHOLD)) {
            mpbase<T>::sqr_toom2(out, in, n, scratch);
        }
        else {
            mpbase<T>::sqr_toom3(out, in, n, scratch);
        }
    }

};

/**
 * @brief Divide a multiple-precision integer by 3
 * 
 * @tparam T An unsigned integer data type
 * @param out Output data array
 * @param in Input data array
 * @param n Length of the arrays
 * @return T Output carry
 */
template<typename T>
static T divexact_by_3(T * out, const T * in, size_t n)
{
    T p0, p1, cy;
    T r = 0;
    T bd = static_cast<T>(-1) / 3;

    for (size_t i = 0; i < n; i++) {
        number<T>::umul(&p1, &p0, in[i], bd);
        cy     = r < p0;
        r      = r - p0;
        out[i] = r;
        r      = r - p1 - cy;
    }

    return r & 0x3;
}


/**
 * @brief Toom interpolation and recombination of 5 points on the product polynomial
 * 
 * @param c The result, on input set to |vinf|v1|v0|
 * @param v2 v2 point, located in scratch memory
 * @param vm1 vm1 point, located in scratch memory
 * @param n The base length of a part
 * @param s The length of the upper part
 * @param sign The sign of the vm1 point 
 * @param vinf0 The least significant limb of the vinf point
 */
template<typename T>
static void interpolate_recombine_5(T *c, T *v2, T *vm1, size_t n, size_t s, size_t t, bool sign, T vinf0)
{
    T cy, saved;
    size_t twon = n + n;
    size_t twos = s + t;
    size_t kk1  = twon + 1;
    T *v0   = c;
    T *c1   = c + n;
    T *v1   = c1 + n;
    T *c3   = v1 + n;
    T *vinf = c3 + n;

    //   v0                 {c,      2n}
    //   v1                 {c+2n,   2n+1}
    //   HIGH(vinf)         {c+4n+1, 2s-1}
    //   |vm1|              {t,      2n+1}
    //   v2                 {t+2n+1, 2n+1}
    //   EMPTY              {t+4n+2, 2s}

    // v2 = v2 - vm1, a carry bit will NOT be returned
    if (sign) {
        CARRY_ASSERT(mpbase<T>::add_n(v2, v2, vm1, kk1));
    }
    else {
        CARRY_ASSERT(mpbase<T>::sub_n(v2, v2, vm1, kk1));
    }

    // v2 = v2 / 3
    CARRY_ASSERT(divexact_by_3<T>(v2, v2, kk1));

    // vm1 = v1 - vm1, a carry bit will NOT be returned
    if (sign) {
        CARRY_ASSERT(mpbase<T>::add_n(vm1, v1, vm1, kk1));
    }
    else {
        CARRY_ASSERT(mpbase<T>::sub_n(vm1, v1, vm1, kk1));
    }

    // tm1 = vm1 = vm1 / 2
    CARRY_ASSERT(mpbase<T>::rshift(vm1, vm1, kk1, 1));

    // t1 = v1 = v1 - v0
    vinf[0] -= mpbase<T>::sub_n(v1, v1, v0, twon);

    // t2 = v2 = (v2 - v1) / 2 = ((v2-vm1)/3-t1)/2 = (v2-vm1-3*t1)/6
    mpbase<T>::sub_n(v2, v2, v1, kk1);
    mpbase<T>::rshift(v2, v2, kk1, 1);

    // v1 = t1-tm1 = v1 - vm1
    mpbase<T>::sub_n(v1, v1, vm1, kk1);

    // vm1 is recombined with c1, the carry is propagated into c3 - it is no longer used
    // so its array of n limbs is now free
    cy = mpbase<T>::add_n(c1, c1, vm1, kk1);
    mpbase<T>::incr_u(c3 + 1, cy);

    // Store vinf[0] and replace with input value
    saved = vinf[0];
    vinf[0] = vinf0;

    // v2 = v2 - 2*vinf
    cy = mpbase<T>::lshift(vm1, vinf, twos, 1);
    cy += mpbase<T>::sub_n(v2, v2, vm1, twos);
    mpbase<T>::decr_u(v2 + twos, cy);

    // Add the high half of t2 into vinf
    if (twos > n + 1) {
        cy = mpbase<T>::add_n(vinf, vinf, v2 + n, n + 1);
        mpbase<T>::incr_u(c3 + kk1, cy);
    }
    else {
        mpbase<T>::add_n(vinf, vinf, v2 + n, twos);
    }

    // Subtract vinf from v1, which also subtracts the high half of v2
    cy = mpbase<T>::sub_n(v1, v1, vinf, twos);
    mpbase<T>::decr_u(v1 + twos, cy);

    // Restore the vinf0 value
    vinf0 = vinf[0];
    vinf[0] = saved;

    // Subtract v2 from vm1, only the low half
    cy = mpbase<T>::sub_n(c1, c1, v2, n);
    mpbase<T>::decr_u(v1, cy);

    // Add v2 to t2 in {c+3k, ...}, only the low half, propagate the carry into vinf
    cy = mpbase<T>::add_n(c3, c3, v2, n);
    vinf[0] += cy;
    assert(vinf[0] >= cy);
    mpbase<T>::incr_u(vinf, vinf0);
}

/**
 * @brief Get the toom22 scratch length given the product length
 * 
 * @param n Product length
 * @return const size_t Memory required (in limbs)
 */
template<typename T>
const size_t mpbase<T>::get_toom22_scratch_size(size_t n)
{
    return 2 * (n + std::numeric_limits<T>::digits);
}

/**
 * @brief Toom-2 multiplication (km = 2, kn = 2), evaluate -1, 0, +inf
 * 
 * @param out Product
 * @param in1 Multiplicand 1
 * @param n1 Length of multiplicand 1
 * @param in2 Multiplicand 2
 * @param n2 Length of multiplicand 2
 * @param scratch Intermediate storage
 */
template<typename T>
void mpbase<T>::mul_toom22(T *out, const T *in1, size_t n1, const T *in2, size_t n2, T *scratch)
{
    bool vm1_is_neg = false;

    assert(n1 >= n2);

    size_t s = n1 >> 1;          // floor(n1/2)
    size_t n = n1 - s;           // ceil(n1/2)
    size_t t = n2 - n;           // Upper half length of in2
    assert(0 < s && s <= n && s >= n - 1);
    assert(0 < t && t <= s);

    const T *in1_0 = in1;
    const T *in1_1 = in1 + n;
    const T *in2_0 = in2;
    const T *in2_1 = in2 + n;

    T *v0    = out;           // 2*n in length
    T *vinf  = out + 2 * n;   // s + t in length
    T *vm1   = scratch;       // 2*n in length

    T *diff1 = out;
    T *diff2 = out + n;

    // Compute diff1 = |in1_0 - in1_1|
    if (s == n) {
        if (mpbase<T>::cmp(in1_0, in1_1, n) < 0) {
            mpbase<T>::sub_n(diff1, in1_1, in1_0, n);
            vm1_is_neg = true;
        }
        else {
            mpbase<T>::sub_n(diff1, in1_0, in1_1, n);
        }
    }
    else {  // n - s == 1
        if (in1_0[s] == 0 && mpbase<T>::cmp(in1_0, in1_1, s) < 0)
        {
            mpbase<T>::sub_n(diff1, in1_1, in1_0, s);
            diff1[s] = 0;
            vm1_is_neg = true;
        }
        else {
            diff1[s] = in1_0[s] - mpbase<T>::sub_n(diff1, in1_0, in1_1, s);
        }
    }

    // Compute diff2 = |in2_0 - in2_1|
    if (t == n) {
        if (mpbase<T>::cmp(in2_0, in2_1, n) < 0) {
            mpbase<T>::sub_n(diff2, in2_1, in2_0, n);
            vm1_is_neg = !vm1_is_neg;
        }
        else {
            mpbase<T>::sub_n(diff2, in2_0, in2_1, n);
        }
    }
    else {
        if (mpbase<T>::is_zero(in2_0 + t, n - t) && mpbase<T>::cmp(in2_0, in2_1, t) < 0) {
            mpbase<T>::sub_n(diff2, in2_1, in2_0, t);
            mpbase<T>::zero(diff2 + t, n - t);
            vm1_is_neg = !vm1_is_neg;
        }
        else {
            mpbase<T>::sub(diff2, in2_0, n, in2_1, t);
        }
    }

    // vm1 point (2*n limbs in length)
    toom_cook<T>::mul_toom22_n_recursive(vm1, diff1, diff2, n, scratch + 2 * n);

    // vinf point (s + t in length)
    if (s > t) {
        toom_cook<T>::mul_toom22_recursive(vinf, in1_1, s, in2_1, t, scratch + 2 * n);
    }
    else {
        toom_cook<T>::mul_toom22_n_recursive(vinf, in1_1, in2_1, s, scratch + 2 * n);
    }

    // v0 point (2*n limbs in length)
    toom_cook<T>::mul_toom22_n_recursive(v0, in1, in2, n, scratch + 2 * n);

    // High part of v0 point added to low part of vinf point: H(v0) + L(vinf)
    T cy = mpbase<T>::add_n(out + 2 * n, v0 + n, vinf, n);

    // LOW(v0) + HIGH(v0)
    T cy2 = cy + mpbase<T>::add_n(out + n, out + 2 * n, v0, n);

    // LOW(vinf) + HIGH(vinf)
    cy += mpbase<T>::add(out + 2 * n, out + 2 * n, n, vinf + n, s + t - n);

    if (vm1_is_neg) {
        cy += mpbase<T>::add_n(out + n, out + n, vm1, 2 * n);
    }
    else {
        cy -= mpbase<T>::sub_n(out + n, out + n, vm1, 2 * n);
        if (0 == cy + 1) {
            // cy is negative so add the cy2 carry to the 3rd part of the output
            assert(cy2 == 1);
            cy += mpbase<T>::add_1(out + 2 * n, out + 2 * n, n, cy2);
            assert(cy == 0);
            return;
        }
    }

    assert(cy  <= 2);
    assert(cy2 <= 2);

    mpbase<T>::incr_u(out + 2 * n, cy2);
    mpbase<T>::incr_u(out + 3 * n, cy);
}

/**
 * @brief Toom-2 squaring (k = 2), evaluate -1, 0, +inf
 * 
 * @param out Product
 * @param in1 Multiplicand 1
 * @param n1 Length of multiplicand 1
 * @param scratch Intermediate storage
 */
template<typename T>
void mpbase<T>::sqr_toom2(T *out, const T *in1, size_t n1, T *scratch)
{
    size_t s = n1 >> 1;
    size_t n = n1 - s;

    const T *in1_0 = in1;
    const T *in1_1 = in1 + n;

    assert(0 < s && s <= n && s >= n - 1);

    T *v0    = out;          // 2n
    T *vinf  = out + 2 * n;  // s+t
    T *vm1   = scratch;      // 2n

    T *diff1 = out;

    // Compute diff1
    if (s == n) {
        if (mpbase<T>::cmp(in1_0, in1_1, n) < 0) {
            mpbase<T>::sub_n(diff1, in1_1, in1_0, n);
        }
        else {
            mpbase<T>::sub_n(diff1, in1_0, in1_1, n);
        }
    }
    else {  // n - s == 1
        if (in1_0[s] == 0 && mpbase<T>::cmp(in1_0, in1_1, s) < 0) {
            mpbase<T>::sub_n(diff1, in1_1, in1_0, s);
            diff1[s] = 0;
        }
        else {
            diff1[s] = in1_0[s] - mpbase<T>::sub_n(diff1, in1_0, in1_1, s);
        }
    }

    // vm1, 2n limbs
    toom_cook<T>::sqr_toom2_recursive(vm1, diff1, n, scratch + 2 * n);

    // vinf, s+s limbs
    toom_cook<T>::sqr_toom2_recursive(vinf, in1_1, s, scratch + 2 * n);

    // v0, 2n limbs
    toom_cook<T>::sqr_toom2_recursive(v0, in1, n, scratch + 2 * n);

    // H(v0) + L(vinf)
    T cy = mpbase<T>::add_n(out + 2 * n, v0 + n, vinf, n);

    // L(v0) + H(v0)
    T cy2 = cy + mpbase<T>::add_n(out + n, out + 2 * n, v0, n);

    // L(vinf) + H(vinf)
    cy += mpbase<T>::add(out + 2 * n, out + 2 * n, n, vinf + n, s + s - n);
    cy -= mpbase<T>::sub_n(out + n, out + n, vm1, 2 * n);

    assert(cy + 1 <= 3);
    assert(cy2 <= 2);

    if (cy <= 2) {
        mpbase<T>::incr_u(out + 2 * n, cy2);
        mpbase<T>::incr_u(out + 3 * n, cy);
    }
    else {
        assert(cy2 == 1);
        cy += mpbase<T>::add_1(out + 2 * n, out + 2 * n, n, cy2);
        assert(cy == 0);
    }
}


/**
 * @brief Toom-2.5 multiplication (km = 3, kn = 2), evaluate -1, 0, +1, +inf
 * 
 * @param out Product
 * @param in1 Multiplicand 1
 * @param n1 Length of multiplicand 1
 * @param in2 Multiplicand 2
 * @param n2 Length of multiplicand 2
 * @param scratch Intermediate storage
 */
template<typename T>
void mpbase<T>::mul_toom32(T *out, const T *in1, size_t n1, const T *in2, size_t n2, T *scratch)
{
    bool vm1_neg;
    T cy;
    S hi;

    // Required, to ensure that s + t >= n
    assert(n2 + 2 <= n1 && n1 + 6 <= 3*n2);

    size_t n = 1 + (2 * n1 >= 3 * n2 ? (n1 - 1) / static_cast<size_t>(3) : (n2 - 1) >> 1);
    size_t s = n1 - 2 * n;
    size_t t = n2 - n;

    assert(0 < s && s <= n);
    assert(0 < t && t <= n);
    assert(s + t >= n);

    const T *in1_0 = in1;
    const T *in1_1 = in1 + n;
    const T *in1_2 = in1 + 2 * n;
    const T *in2_0 = in2;
    const T *in2_1 = in2 + n;

    // Product area of size n1 + n2 = 3*n + s + t >= 4*n + 2
    T *in11  = out;                         // n, most significant limb in in11_hi
    T *in21  = out + n;                     // n, most significant bit in in21_hi
    T *am1   = out + 2*n;                   // n, most significant bit in hi
    T *bm1   = out + 3*n;                   // n
    T *v1    = scratch;                     // 2n + 1
    T *vm1   = out;                         // 2n + 1

    // Scratch need: 2*n + 1 + scratch for the recursive multiplications

    // Compute in11 = in1_0 + in1_1 + in1_2, am1 = in1_0 - in1_1 + in1_2
    T in11_hi = mpbase<T>::add(in11, in1_0, n, in1_2, s);
    if (in11_hi == 0 && mpbase<T>::cmp(in11, in1_1, n) < 0) {
        CARRY_ASSERT(mpbase<T>::sub_n(am1, in1_1, in11, n));
        hi = 0;
        vm1_neg = true;
    }
    else {
        hi = in11_hi - mpbase<T>::sub_n(am1, in11, in1_1, n);
        vm1_neg = false;
    }
    in11_hi += mpbase<T>::add_n(in11, in11, in1_1, n);

    // Compute in21 = in2_0 + in2_1 and bm1 = in2_0 - in2_1
    T in21_hi;
    if (t == n) {
        in21_hi = mpbase<T>::add_n(in21, in2_0, in2_1, n);

        if (mpbase<T>::cmp(in2_0, in2_1, n) < 0) {
            CARRY_ASSERT(mpbase<T>::sub_n(bm1, in2_1, in2_0, n));
            vm1_neg = !vm1_neg;
        }
        else {
            CARRY_ASSERT(mpbase<T>::sub_n(bm1, in2_0, in2_1, n));
        }
    }
    else {
        in21_hi = mpbase<T>::add(in21, in2_0, n, in2_1, t);

        if (mpbase<T>::is_zero(in2_0 + t, n - t) && mpbase<T>::cmp(in2_0, in2_1, t) < 0) {
            CARRY_ASSERT(mpbase<T>::sub_n(bm1, in2_1, in2_0, t));
            mpbase<T>::zero(bm1 + t, n - t);
            vm1_neg = !vm1_neg;
        }
        else {
            CARRY_ASSERT(mpbase<T>::sub(bm1, in2_0, n, in2_1, t));
        }
    }

    mpbase<T>::mul_n(v1, in11, in21, n);
    if (in11_hi == 1) {
        cy = in21_hi + mpbase<T>::add_n(v1 + n, v1 + n, in21, n);
    }
    else if (in11_hi == 2) {
        cy = 2 * in21_hi + mpbase<T>::addmul_1(v1 + n, in21, n, static_cast<T>(2));
    }
    else {
        cy = 0;
    }

    if (in21_hi != 0) {
        cy += mpbase<T>::add_n(v1 + n, v1 + n, in11, n);
    }
    v1[2 * n] = cy;

    mpbase<T>::mul_n(vm1, am1, bm1, n);
    if (hi) {
        hi = mpbase<T>::add_n(vm1+n, vm1+n, bm1, n);
    }

    vm1[2*n] = hi;

    // v1 <-- (v1 + vm1) / 2 = x0 + x2
    if (vm1_neg) {
        mpbase<T>::sub_n(v1, v1, vm1, 2*n+1);
        CARRY_ASSERT(mpbase<T>::rshift(v1, v1, 2 * n + 1, 1));
    }
    else {
        mpbase<T>::add_n(v1, v1, vm1, 2*n+1);
        CARRY_ASSERT(mpbase<T>::rshift(v1, v1, 2 * n + 1, 1));
    }

    // y = (x0 + x2) * B + (x0 + x2) - vm1, 3*n + 1 limbs
    //   y0 (scratch, n)
    //   y1 (out + 2*n, n)
    //   y2 (scratch + n, n+1)

    hi = vm1[2*n];
    cy = mpbase<T>::add_n(out + 2*n, v1, v1 + n, n);
    mpbase<T>::incr_u(v1 + n, cy + v1[2*n]);

    if (vm1_neg) {
        cy = mpbase<T>::add_n(v1, v1, vm1, n);
        hi += mpbase<T>::add_nc(out + 2*n, out + 2*n, vm1 + n, n, cy);
        mpbase<T>::incr_u(v1 + n, hi);
    }
    else {
        cy = mpbase<T>::sub_n(v1, v1, vm1, n);
        hi += mpbase<T>::sub_nc(out + 2*n, out + 2*n, vm1 + n, n, cy);
        mpbase<T>::decr_u(v1 + n, hi);
    }

    mpbase<T>::mul_n(out, in1_0, in2_0, n);
    if (s > t) {
        mpbase<T>::mul(out+3*n, in1_2, s, in2_1, t);
    }
    else {
        mpbase<T>::mul(out+3*n, in2_1, t, in1_2, s);
    }

    cy = mpbase<T>::sub_n(out + n, out + n, out+3*n, n);
    hi = scratch[2*n] + cy;

    cy = mpbase<T>::sub_nc(out + 2*n, out + 2*n, out, n, cy);
    hi -= mpbase<T>::sub_nc(out + 3*n, scratch + n, out + n, n, cy);

    hi += mpbase<T>::add(out + n, out + n, 3*n, scratch, n);

    if (s + t > n) {
        hi -= mpbase<T>::sub(out + 2*n, out + 2*n, 2*n, out + 4*n, s+t-n);

        if (hi < 0) {
            mpbase<T>::decr_u(out + 4*n, -hi);
        }
        else {
            mpbase<T>::incr_u(out + 4*n, hi);
        }
    }
    else {
        assert(hi == 0);
    }
}

/**
 * @brief Get the toom22 scratch length given the product length
 * 
 * @param n Product length
 * @return const size_t Memory required (in limbs)
 */
template<typename T>
const size_t mpbase<T>::get_toom33_scratch_size(size_t n)
{
    return 3 * (n + std::numeric_limits<T>::digits);
}

/**
 * @brief Toom-3 multiplication (km = 3, kn = 3), evaluate -1, 0, +1, +2, +inf
 * 
 * @param out Product
 * @param in1 Multiplicand 1
 * @param n1 Length of multiplicand 1
 * @param in2 Multiplicand 2
 * @param n2 Length of multiplicand 2
 * @param scratch Intermediate storage
 */
template<typename T>
void mpbase<T>::mul_toom33(T *out, const T *in1, size_t n1, const T *in2, size_t n2, T *scratch)
{
    bool vm1_neg = false;

    size_t n = (n1 + 2) / static_cast<size_t>(3);
    size_t s = n1 - 2 * n;
    size_t t = n2 - 2 * n;

    const T *in1_0 = in1;
    const T *in1_1 = (in1 + n);
    const T *in1_2 = (in1 + 2*n);
    const T *in2_0 = in2;
    const T *in2_1 = (in2 + n);
    const T *in2_2 = (in2 + 2*n);

    assert(n1 >= n2);

    assert(0 < s && s <= n);
    assert(0 < t && t <= n);

    T *as1  = scratch + 4 * n + 4;
    T *asm1 = scratch + 2 * n + 2;
    T *as2  = out + n + 1;

    T *bs1  = out;
    T *bsm1 = scratch + 3 * n + 3;
    T *bs2  = out + 2 * n + 2;

    T *gp   = scratch;

    // Compute as1 and asm1
    T cy = mpbase<T>::add(gp, in1_0, n, in1_2, s);
    as1[n] = cy + mpbase<T>::add_n(as1, gp, in1_1, n);
    if (cy == 0 && mpbase<T>::cmp(gp, in1_1, n) < 0) {
        mpbase<T>::sub_n(asm1, in1_1, gp, n);
        asm1[n] = 0;
        vm1_neg = true;
    }
    else {
        cy -= mpbase<T>::sub_n(asm1, gp, in1_1, n);
        asm1[n] = cy;
    }

    // Compute as2
    cy = mpbase<T>::add_n(as2, in1_2, as1, s);
    if (s != n) {
        cy = mpbase<T>::add_1(as2 + s, as1 + s, n - s, cy);
    }
    cy  += as1[n];
    cy <<= 1;
    cy  += mpbase<T>::lshift(as2, as2, n, 1);
    cy  -= mpbase<T>::sub_n(as2, as2, in1_0, n);
    as2[n] = cy;

    // Compute bs1 and bsm1
    cy = mpbase<T>::add(gp, in2_0, n, in2_2, t);
    bs1[n] = cy + mpbase<T>::add_n(bs1, gp, in2_1, n);
    if (cy == 0 && mpbase<T>::cmp(gp, in2_1, n) < 0) {
        mpbase<T>::sub_n(bsm1, in2_1, gp, n);
        bsm1[n] = 0;
        vm1_neg = !vm1_neg;
    }
    else {
        cy -= mpbase<T>::sub_n(bsm1, gp, in2_1, n);
        bsm1[n] = cy;
    }

    // Compute bs2
    cy  = mpbase<T>::add_n(bs2, bs1, in2_2, t);
    if (t != n) {
        cy = mpbase<T>::add_1(bs2 + t, bs1 + t, n - t, cy);
    }
    cy  += bs1[n];
    cy <<= 1;
    cy  += mpbase<T>::lshift(bs2, bs2, n, 1);
    cy  -= mpbase<T>::sub_n(bs2, bs2, in2_0, n);
    bs2[n] = cy;

    assert(as1[n] <= 2);
    assert(bs1[n] <= 2);
    assert(asm1[n] <= 1);
    assert(bsm1[n] <= 1);
    assert(as2[n] <= 6);
    assert(bs2[n] <= 6);

    T *v0          = out;                     // 2n
    T *v1          = (out + 2 * n);           // 2n+1
    T *vinf        = (out + 4 * n);           // s+t
    T *vm1         = scratch;                 // 2n+1
    T *v2          = (scratch + 2 * n + 1);   // 2n+2
    T *scratch_out = (scratch + 5 * n + 5);

    // vm1, 2n+1 limbs
    toom_cook<T>::mul_toom33_n_recursive(vm1, asm1, bsm1, n + 1, scratch_out);

    toom_cook<T>::mul_toom33_n_recursive(v2, as2, bs2, n + 1, scratch_out);  // v2, 2n+1 limbs

    // vinf, s+t limbs
    if (s > t) {
        mpbase<T>::mul(vinf, in1_2, s, in2_2, t);
    }
    else {
        toom_cook<T>::mul_toom33_n_recursive(vinf, in1_2, in2_2, s, scratch_out);
    }

    T vinf0 = vinf[0];        // v1 overlaps with this

    cy = vinf[1];
    toom_cook<T>::mul_toom33_n_recursive(v1, as1, bs1, n + 1, scratch_out);
    vinf[1] = cy;

    toom_cook<T>::mul_toom33_n_recursive(v0, in1, in2, n, scratch_out);  // v0, 2n limbs

    interpolate_recombine_5<T>(out, v2, vm1, n, s, t, vm1_neg, vinf0);
}

/**
 * @brief Toom-3 squaring (k = 3), evaluate -1, 0, +1, +2, +inf
 * 
 * @param out Product
 * @param in1 Multiplicand 1
 * @param n1 Length of multiplicand 1
 * @param scratch Intermediate storage
 */
template<typename T>
void mpbase<T>::sqr_toom3(T *out, const T *in1, size_t n1, T *scratch)
{
    size_t n = (n1 + 2) / static_cast<size_t>(3);
    size_t s = n1 - 2 * n;
    assert(0 < s && s <= n);

    const T *in1_0 = in1;
    const T *in1_1 = in1 + n;
    const T *in1_2 = in1 + 2*n;

    T *as1   = scratch + 4 * n + 4;
    T *diff1 = scratch + 2 * n + 2;
    T *as2   = out + n + 1;

    T *gp    = scratch;

    // Compute as1 and diff1
    T cy = mpbase<T>::add(gp, in1_0, n, in1_2, s);
    as1[n] = cy + mpbase<T>::add_n(as1, gp, in1_1, n);
    if (cy == 0 && mpbase<T>::cmp(gp, in1_1, n) < 0) {
        mpbase<T>::sub_n(diff1, in1_1, gp, n);
        diff1[n] = 0;
    }
    else {
        cy -= mpbase<T>::sub_n(diff1, gp, in1_1, n);
        diff1[n] = cy;
    }

    // Compute as2
    cy = mpbase<T>::add_n(as2, in1_2, as1, s);
    if (s != n) {
        cy = mpbase<T>::add_1(as2 + s, as1 + s, n - s, cy);
    }
    cy += as1[n];
    cy = 2 * cy + mpbase<T>::lshift(as2, as2, n, 1);
    cy -= mpbase<T>::sub_n(as2, as2, in1_0, n);
    as2[n] = cy;

    assert(as1[n] <= 2);
    assert(diff1[n] <= 1);

    T *v0          = out;                  // 2n
    T *v1          = out + 2 * n;          // 2n+1
    T *vinf        = out + 4 * n;          // s+s
    T *vm1         = scratch;              // 2n+1
    T *v2          = scratch + 2 * n + 1;  // 2n+2
    T *scratch_out = scratch + 5 * n + 5;

    // vm1, 2n+1 limbs
    toom_cook<T>::sqr_toom3_recursive(vm1, diff1, n + 1, scratch_out);

    // v2, 2n+1 limbs
    toom_cook<T>::sqr_toom3_recursive(v2, as2, n + 1, scratch_out);

    // vinf, s+s limbs
    toom_cook<T>::sqr_toom3_recursive(vinf, in1_2, s, scratch_out);

    // v1 overlaps with this
    T vinf0 = vinf[0];

    cy = vinf[1];
    toom_cook<T>::sqr_toom3_recursive(v1, as1, n + 1, scratch_out);
    vinf[1] = cy;

    // v0, 2n limbs
    toom_cook<T>::sqr_toom3_recursive(v0, in1, n, scratch_out);

    // Perform final interpolation and recombination of the product
    interpolate_recombine_5<T>(out, v2, vm1, n, s, s, false, vinf0);
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
