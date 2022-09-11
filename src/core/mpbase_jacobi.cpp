/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "core/mpbase.hpp"


/// A codeword to signify failure using an illegal value
#define BITS_FAIL 255

/// Return 2/3 of the length n
#define GET_2_3_N(n)                    (2*(n) / 3)

/// Get the intermediate storage needed for the HGCD matrix for a given n
#define HGCD_MATRIX_INIT_SCRATCH(n)     (4 * ((n+1)/2 + 1))

/// Half-GCD recursion threshold
#define HGCD_THRESHOLD                  400

/// Threshold for Half-GCD length reduction
#define GCD_THRESHOLD                   500

/// Threshold for Schönhage–Strassen multiplication
#define MATRIX22_STRASSEN_THRESHOLD     25



namespace phantom {
namespace core {

template <typename T>
class jacobi;

/// Half GCD context
template <typename T>
struct hgcd_matrix_ctx
{
    size_t alloc;
    size_t n;
    T* p[2][2];
};

/// A struct defining a Jacobi context for Half GCD
template <typename T>
struct hgcd_jacobi_ctx
{
    hgcd_matrix_ctx<T> *M;
    unsigned *bitsp;
};

/// Half GCD matrix
template <typename T>
struct hgcd_matrix
{
    T u[2][2];
};

/// A function pointer for GCD subtraction/division
template<typename T>
using gcd_subdiv_step_callback = void (hgcd_jacobi_ctx<T> *, const T*, size_t, const T*, size_t, int, T*);


/**
 * @brief Multiplication for a 2x2 matrix
 * 
 * @tparam T Data type forunderlying arithmetic
 */
template<typename T>
class matrix22
{
public:
    /**
     * @brief Add the least significant n limbs of 2 arrays
     * @param out Output data array
     * @param in1 1st input data array
     * @param n1 Length of in1
     * @param in2 2nd input data array
     * @param n2 Length of in2
     * @param n Length of the data arrays
     * @return Returns n1 if n1==n2, otherwise returns n1 with carry compensation
     */
    static size_t add_signed_n(T* out, const T *in1, size_t n1, const T *in2, size_t n2, size_t n)
    {
        assert(n1 >= n && n2 >= n);
        assert(n1 >= n2);

        if (n1 != n2) {
            return n1 ^ mpbase<T>::abs_sub_n(out, in1, in2, n);
        }
        else {
            mpbase<T>::add_n(out, in1, in2, n);
            return n1;
        }
    }

    /**
     * Sets (r;b) = M^{-1}(a;b), with M^{-1} = (u11, -u01; -u10, u00) from the left
     * @param M Half-GCD matrix
     * @param r_limbs Pointer to r limb array
     * @param a_limbs Pointer to A limb array
     * @param b_limbs Pointer to B limb array
     * @param n Length of input arrays
     * @return size_t Adjusted length of r and b
     */
    static size_t mul1_inverse_vector(const hgcd_matrix<T> *M,
        T* r_limbs, const T* a_limbs, T* b_limbs, size_t n)
    {
#ifndef NDEBUG
        T h0, h1;

        // Compute (r;b) = (u11 a - u01 b; -u10 a + u00 b) as
        //     r  = u11 * a
        //     r -= u01 * b
        //     b *= u00
        //     b -= u10 * a

        h0 = mpbase<T>::mul_1(r_limbs, a_limbs, n, M->u[1][1]);
        h1 = mpbase<T>::submul_1(r_limbs, b_limbs, n, M->u[0][1]);
        assert(h0 == h1);

        h0 = mpbase<T>::mul_1(b_limbs, b_limbs, n, M->u[0][0]);
        h1 = mpbase<T>::submul_1(b_limbs, a_limbs, n, M->u[1][0]);
        assert(h0 == h1);
#endif

        n -= (r_limbs[n-1] | b_limbs[n-1]) == 0;
        return n;
    }

    /**
     * Multiply a and b, different sized arrays
     * @param r_limbs Pointer to r limb array
     * @param a_limbs Pointer to A limb array
     * @param an Length of input array A
     * @param b_limbs Pointer to B limb array
     * @param bn Length of input array B
     */
    static void mul_step(T* r_limbs, const T* a_limbs, size_t an, const T* b_limbs, size_t bn)
    {
        if (an >= bn)
            mpbase<T>::mul(r_limbs, a_limbs, an, b_limbs, bn);
        else
            mpbase<T>::mul(r_limbs, b_limbs, bn, a_limbs, an);
    }

    /**
     * Computes R = R * M, where R = (r0, r1; r2, r3) and resulting R elements are
     * of size rn + mn + 1.
     * Optimized for larger lengths.
     * @param r0 Pointer to r0 limb array
     * @param r1 Pointer to r1 limb array
     * @param r2 Pointer to r2 limb array
     * @param r3 Pointer to r3 limb array
     * @param rn Length of R arrays
     * @param m0 Pointer to m0 limb array
     * @param m1 Pointer to m1 limb array
     * @param m2 Pointer to m2 limb array
     * @param m3 Pointer to m3 limb array
     * @param mn Length of M arrays
     * @param scratch Intermediate storage memory (3*rn + 3*mn + 5)
     */
    static void mul_strassen(T* r0, T* r1, T* r2, T* r3, size_t rn,
                    const T* m0, const T* m1, const T* m2, const T* m3, size_t mn,
                    T* scratch)
    {
        T *s0, *t0, *u0, *u1;
        int r1s, r3s, s0s, t0s, u1s;
        s0 = scratch; scratch += rn + 1;
        t0 = scratch; scratch += mn + 1;
        u0 = scratch; scratch += rn + mn + 1;
        u1 = scratch;  // rn + mn + 2

        mul_step(u0, r1, rn, m2, mn);
        r3s = mpbase<T>::abs_sub_n(r3, r3, r2, rn);
        if (r3s) {
            r1s = mpbase<T>::abs_sub_n(r1, r1, r3, rn);
            r1[rn] = 0;
        }
        else {
            r1[rn] = mpbase<T>::add_n(r1, r1, r3, rn);
            r1s = 0;
        }
        if (r1s) {
            s0[rn] = mpbase<T>::add_n(s0, r1, r0, rn);
            s0s = 0;
        }
        else if (r1[rn] != 0) {
            s0[rn] = r1[rn] - mpbase<T>::sub_n(s0, r1, r0, rn);
            s0s = 1;
        }
        else {
            s0s = mpbase<T>::abs_sub_n(s0, r0, r1, rn);
            s0[rn] = 0;
        }
        mul_step(u1, r0, rn, m0, mn);
        r0[rn+mn] = mpbase<T>::add_n(r0, u0, u1, rn + mn);
        assert(r0[rn+mn] < 2);

        t0s = mpbase<T>::abs_sub_n(t0, m3, m2, mn);
        u1s = r3s^t0s^1;
        mul_step(u1, r3, rn, t0, mn);
        u1[rn+mn] = 0;
        if (t0s) {
            t0s = mpbase<T>::abs_sub_n(t0, m1, t0, mn);
            t0[mn] = 0;
        }
        else {
            t0[mn] = mpbase<T>::add_n(t0, t0, m1, mn);
        }

        if (t0[mn] != 0) {
            mul_step(r3, r1, rn, t0, mn + 1);
            assert(r1[rn] < 2);
            if (r1[rn] != 0) {
                mpbase<T>::add_n(r3 + rn, r3 + rn, t0, mn + 1);
            }
        }
        else {
            mul_step(r3, r1, rn + 1, t0, mn);
        }

        assert(r3[rn+mn] < 4);

        u0[rn+mn] = 0;
        if (r1s^t0s) {
            r3s = mpbase<T>::abs_sub_n(r3, u0, r3, rn + mn + 1);
        }
        else {
            mpbase<T>::add_n(r3, r3, u0, rn + mn + 1);
            r3s = 0;
        }

        if (t0s) {
            t0[mn] = mpbase<T>::add_n(t0, t0, m0, mn);
        }
        else if (t0[mn] != 0) {
            t0[mn] -= mpbase<T>::sub_n(t0, t0, m0, mn);
        }
        else {
            t0s = mpbase<T>::abs_sub_n(t0, t0, m0, mn);
        }
        mul_step(u0, r2, rn, t0, mn + 1);
        assert(u0[rn+mn] < 2);
        if (r1s) {
            mpbase<T>::sub_n(r1, r2, r1, rn);
        }
        else {
            r1[rn] += mpbase<T>::add_n(r1, r1, r2, rn);
        }
        rn++;
        t0s = add_signed_n(r2, r3, r3s, u0, t0s, rn + mn);
        assert(r2[rn+mn-1] < 4);
        r3s = add_signed_n(r3, r3, r3s, u1, u1s, rn + mn);
        assert(r3[rn+mn-1] < 3);
        mul_step(u0, s0, rn, m1, mn);
        assert(u0[rn+mn-1] < 2);
        t0[mn] = mpbase<T>::add_n(t0, m3, m1, mn);
        mul_step(u1, r1, rn, t0, mn + 1);
        mn += rn;
        assert(u1[mn-1] < 4);
        assert(u1[mn] == 0);
        add_signed_n(r1, r3, r3s, u0, s0s, mn);
        assert(r1[mn-1] < 2);
        if (r3s) {
            mpbase<T>::add_n(r3, u1, r3, mn);
        }
        else {
            mpbase<T>::add_n(r3, u1, r3, mn);
        }
        assert(r3[mn-1] < 2);
        if (t0s) {
            mpbase<T>::add_n(r2, u1, r2, mn);
        }
        else {
            mpbase<T>::add_n(r2, u1, r2, mn);
        }
        assert(r2[mn-1] < 2);
    }

    /**
     * Computes R = R * M, where R = (r0, r1; r2, r3) and resulting R elements are
     * of size rn + mn + 1.
     * @param r0 Pointer to r0 limb array
     * @param r1 Pointer to r1 limb array
     * @param r2 Pointer to r2 limb array
     * @param r3 Pointer to r3 limb array
     * @param rn Length of R arrays
     * @param m0 Pointer to m0 limb array
     * @param m1 Pointer to m1 limb array
     * @param m2 Pointer to m2 limb array
     * @param m3 Pointer to m3 limb array
     * @param mn Length of M arrays
     * @param scratch Intermediate storage memory (3*rn + 3*mn + 5)
     */
    static void mul(T* r0, T* r1, T* r2, T* r3, size_t rn,
                const T* m0, const T* m1, const T* m2, const T* m3, size_t mn,
                T* scratch)
    {
        if (BELOW_THRESHOLD(rn, MATRIX22_STRASSEN_THRESHOLD) ||
            BELOW_THRESHOLD(mn, MATRIX22_STRASSEN_THRESHOLD)) {
            T *p0, *p1;
            unsigned i;

            // Temporary storage requirement: 3 rn + 2 mn
            p0 = scratch + rn;
            p1 = p0 + rn + mn;

            for (i = 0; i < 2; i++) {
                mpbase<T>::copy(scratch, r0, rn);  // NOLINT

                if (rn >= mn) {
                    mpbase<T>::mul(p0, r0, rn, m0, mn);
                    mpbase<T>::mul(p1, r1, rn, m3, mn);
                    mpbase<T>::mul(r0, r1, rn, m2, mn);
                    mpbase<T>::mul(r1, scratch, rn, m1, mn);
                }
                else {
                    mpbase<T>::mul(p0, m0, mn, r0, rn);
                    mpbase<T>::mul(p1, m3, mn, r1, rn);
                    mpbase<T>::mul(r0, m2, mn, r1, rn);
                    mpbase<T>::mul(r1, m1, mn, scratch, rn);
                }
                r0[rn+mn] = mpbase<T>::add_n(r0, r0, p0, rn + mn);
                r1[rn+mn] = mpbase<T>::add_n(r1, r1, p1, rn + mn);

                r0 = r2; r1 = r3;
            }
        }
        else {
            mul_strassen(r0, r1, r2, r3, rn, m0, m1, m2, m3, mn, scratch);
        }
    }
};


template <typename T>
class jacobi
{
public:
    /**
     * @brief Jacobi update
     */
    static unsigned jacobi_update(unsigned bits, unsigned denominator, unsigned q)
    {
        const uint8_t jacobi_lut[208] = {
             0,  0,  0,  0,  0, 12,  8,  4,  1,  1,  1,  1,  1, 13,  9,  5,
             2,  2,  2,  2,  2,  6, 10, 14,  3,  3,  3,  3,  3,  7, 11, 15,
             4, 16,  6, 18,  4,  0, 12,  8,  5, 17,  7, 19,  5,  1, 13,  9,
             6, 18,  4, 16,  6, 10, 14,  2,  7, 19,  5, 17,  7, 11, 15,  3,
             8, 10,  9, 11,  8,  4,  0, 12,  9, 11,  8, 10,  9,  5,  1, 13,
            10,  9, 11,  8, 10, 14,  2,  6, 11,  8, 10,  9, 11, 15,  3,  7,
            12, 22, 24, 20, 12,  8,  4,  0, 13, 23, 25, 21, 13,  9,  5,  1,
            25, 21, 13, 23, 14,  2,  6, 10, 24, 20, 12, 22, 15,  3,  7, 11,
            16,  6, 18,  4, 16, 16, 16, 16, 17,  7, 19,  5, 17, 17, 17, 17,
            18,  4, 16,  6, 18, 22, 19, 23, 19,  5, 17,  7, 19, 23, 18, 22,
            20, 12, 22, 24, 20, 20, 20, 20, 21, 13, 23, 25, 21, 21, 21, 21,
            22, 24, 20, 12, 22, 19, 23, 18, 23, 25, 21, 13, 23, 18, 22, 19,
            24, 20, 12, 22, 15,  3,  7, 11, 25, 21, 13, 23, 14,  2,  6, 10
        };

        assert(bits < 26);
        assert(denominator < 2);
        assert(q < 4);

        return bits = jacobi_lut[(bits << 3) + (denominator << 2) + q];
    }

    /**
     * Half GCD required memory size
     * @param n Length of array
     * @return Memory words required
     */
    static size_t hgcd_scratch_size(size_t n)
    {
        if (BELOW_THRESHOLD(n, HGCD_THRESHOLD)) {
            return n;
        }

        // Get the recursion depth
        size_t nscaled = (n - 1) / (HGCD_THRESHOLD - 1);
        size_t count   = bit_manipulation::clz(nscaled);
        size_t k       = std::numeric_limits<T>::digits - count;

        return 20 * ((n+3) / 4) + 22 * k + HGCD_THRESHOLD;
    }

    /**
     * Half GCD initialization
     * @param ctx Context
     * @param n Length of array
     * @param p Pointer to array
     */
    static void hgcd_matrix_init(hgcd_matrix_ctx<T> *ctx, size_t n, T* p)
    {
        size_t s = (n+1)/2 + 1;
        ctx->alloc = s;
        ctx->n = 1;
        mpbase<T>::zero(p, 4 * s);
        ctx->p[0][0] = p;
        ctx->p[0][1] = p + s;
        ctx->p[1][0] = p + 2 * s;
        ctx->p[1][1] = p + 3 * s;

        ctx->p[0][0][0] = ctx->p[1][1][0] = 1;
    }

    /**
     * Multiply the least significant p limbs of (a;b) by M^-1
     * @param ctx Context
     * @param n Length of array
     * @param a_limbs Pointer to A
     * @param b_limbs Pointer to B
     * @param p Length of A and B
     * @param scratch Temporary storage of 2 * (p + M->n) words
     * @return Adjusted array length
     */
    static size_t hgcd_matrix_adjust(const hgcd_matrix_ctx<T> *ctx,
        size_t n, T* a_limbs, T* b_limbs, size_t p, T* scratch)
    {
        // M^-1 (a;b) = (r11, -r01; -r10, r00) (a ; b) = (r11 a - r01 b; - r10 a + r00 b

        T* t0 = scratch;
        T* t1 = scratch + p + ctx->n;
        T ah, bh, cy;

        assert(p + ctx->n  < n);

        // Compute the two values depending on a before overwriting it
        if (ctx->n >= p) {
            mpbase<T>::mul(t0, ctx->p[1][1], ctx->n, a_limbs, p);
            mpbase<T>::mul(t1, ctx->p[1][0], ctx->n, a_limbs, p);
        }
        else {
            mpbase<T>::mul(t0, a_limbs, p, ctx->p[1][1], ctx->n);
            mpbase<T>::mul(t1, a_limbs, p, ctx->p[1][0], ctx->n);
        }

        // Update a
        mpbase<T>::copy(a_limbs, t0, p);
        ah = mpbase<T>::add(a_limbs + p, a_limbs + p, n - p, t0 + p, ctx->n);

        if (ctx->n >= p) {
            mpbase<T>::mul(t0, ctx->p[0][1], ctx->n, b_limbs, p);
        }
        else {
            mpbase<T>::mul(t0, b_limbs, p, ctx->p[0][1], ctx->n);
        }

        cy = mpbase<T>::sub(a_limbs, a_limbs, n, t0, p + ctx->n);
        assert(cy <= ah);
        ah -= cy;

        // Update b
        if (ctx->n >= p) {
            mpbase<T>::mul(t0, ctx->p[0][0], ctx->n, b_limbs, p);
        }
        else {
            mpbase<T>::mul(t0, b_limbs, p, ctx->p[0][0], ctx->n);
        }

        mpbase<T>::copy(b_limbs, t0, p);
        bh = mpbase<T>::add(b_limbs + p, b_limbs + p, n - p, t0 + p, ctx->n);
        cy = mpbase<T>::sub(b_limbs, b_limbs, n, t1, p + ctx->n);
        assert(cy <= bh);
        bh -= cy;

        if (ah > 0 || bh > 0) {
            a_limbs[n] = ah;
            b_limbs[n] = bh;
            n++;
        }
        else {
            // The subtraction can reduce the size by at most one limb
            if (a_limbs[n-1] == 0 && b_limbs[n-1] == 0) {
                n--;
            }
        }
        assert(a_limbs[n-1] > 0 || b_limbs[n-1] > 0);
        return n;
    }

    /**
     * Sets (r;b) = (a;b) M, with M = (u00, u01; u10, u11)
     * @param M Context
     * @param r_limbs Result must have space for n + 1 limbs
     * @param a_limbs Pointer to A
     * @param b_limbs Pointer to B
     * @param n Length of arrays
     * @return Adjusted array length
     */
    static size_t hgcd_mul_matrix1_vector(const hgcd_matrix<T> *M,
        T* r_limbs, const T* a_limbs, T* b_limbs, size_t n)
    {
        T ah, bh;

        // Compute (r,b) = (u00 a + u10 b, u01 a + u11 b) as:
        //    r  = u00 * a
        //    r += u10 * b
        //    b *= u11
        //    b += u01 * a

        ah =     mpbase<T>::mul_1(r_limbs, a_limbs, n, M->u[0][0]);
        ah += mpbase<T>::addmul_1(r_limbs, b_limbs, n, M->u[1][0]);

        bh =     mpbase<T>::mul_1(b_limbs, b_limbs, n, M->u[1][1]);
        bh += mpbase<T>::addmul_1(b_limbs, a_limbs, n, M->u[0][1]);

        r_limbs[n] = ah;
        b_limbs[n] = bh;

        n += (ah | bh) > 0;
        return n;
    }

    /**
     * @brief Multiply ctx by M from the right
     * Since the M1 elements fit in limb_bits - 1 bits, M grows by at most one limb.
     * @param ctx Context
     * @param M Matrix
     * @param scratch Needs temporary storage ctx->n
     */
    static void hgcd_matrix_mul_1(hgcd_matrix_ctx<T> *ctx, const hgcd_matrix<T> *M, T* scratch)
    {
        size_t n0, n1;

        mpbase<T>::copy(scratch, ctx->p[0][0], ctx->n);
        n0 = hgcd_mul_matrix1_vector(M, ctx->p[0][0], scratch, ctx->p[0][1], ctx->n);
        mpbase<T>::copy(scratch, ctx->p[1][0], ctx->n);
        n1 = hgcd_mul_matrix1_vector(M, ctx->p[1][0], scratch, ctx->p[1][1], ctx->n);

        ctx->n = MAX(n0, n1);
        assert(ctx->n < ctx->alloc);
    }

    /**
     * @brief Multiply M0 by M1 from the right
     * Since the M1 elements fit in limb_bits - 1 bits, M0 grows by at most one limb.
     * @param M0 Context 0
     * @param M1 Context 1
     * @param scratch Needs temporary storage 3*(M->n + M1->n) + 5 limbs
     */
    static void hgcd_matrix_mul(hgcd_matrix_ctx<T> *M0, const hgcd_matrix_ctx<T> *M1, T* scratch)
    {
        assert(M0->n + M1->n < M0->alloc);

        assert((M0->p[0][0][M0->n-1] |
                M0->p[0][1][M0->n-1] |
                M0->p[1][0][M0->n-1] |
                M0->p[1][1][M0->n-1]) > 0);

        assert((M1->p[0][0][M1->n-1] |
                M1->p[0][1][M1->n-1] |
                M1->p[1][0][M1->n-1] |
                M1->p[1][1][M1->n-1]) > 0);

        matrix22<T>::mul(M0->p[0][0], M0->p[0][1], M0->p[1][0], M0->p[1][1], M0->n,
                         M1->p[0][0], M1->p[0][1], M1->p[1][0], M1->p[1][1], M1->n,
                         scratch);

        size_t n = M0->n + M1->n;

        n -= ((M0->p[0][0][n] | M0->p[0][1][n] | M0->p[1][0][n] | M0->p[1][1][n]) == 0);
        n -= ((M0->p[0][0][n] | M0->p[0][1][n] | M0->p[1][0][n] | M0->p[1][1][n]) == 0);
        n -= ((M0->p[0][0][n] | M0->p[0][1][n] | M0->p[1][0][n] | M0->p[1][1][n]) == 0);

        assert((M0->p[0][0][n] | M0->p[0][1][n] | M0->p[1][0][n] | M0->p[1][1][n]) > 0);

        M0->n = n + 1;
    }

    /**
     * @brief Update a matrix column, adding in Q * column (1-col)
     * @param ctx Context
     * @param q_limbs Quotient vector
     * @param qn Length of quotient vector
     * @param col Column to be updated
     * @param scratch Needs temporary storage qn + n <= ctx->alloc
     */
    static void hgcd_matrix_update_q(hgcd_matrix_ctx<T> *ctx, const T* q_limbs, size_t qn,
                            size_t col, T* scratch)
    {
        assert(col < 2);
        col &= 1;  // This fixes GCC warnings for -Warray-bounds

        if (qn == 1) {
            T q = q_limbs[0];
            T c0, c1;

            c0 = mpbase<T>::addmul_1(ctx->p[0][col], ctx->p[0][1-col], ctx->n, q);
            c1 = mpbase<T>::addmul_1(ctx->p[1][col], ctx->p[1][1-col], ctx->n, q);

            ctx->p[0][col][ctx->n] = c0;
            ctx->p[1][col][ctx->n] = c1;

            ctx->n += (c0 | c1) != 0;
        }
        else {
            // Normalization is required in order not to overflow ctx->p
            size_t n;
            for (n = ctx->n; n + qn > ctx->n; n--) {
                assert(n > 0);
                if (ctx->p[0][1-col][n-1] > 0 || ctx->p[1][1-col][n-1] > 0)
                    break;
            }

            assert(qn + n <= ctx->alloc);

            // Carries for the worst case of both high words from multiplication and carries from addition
            T c[2];

            for (size_t row = 0; row < 2; row++) {
                if (qn <= n)
                    mpbase<T>::mul(scratch, ctx->p[row][1-col], n, q_limbs, qn);
                else
                    mpbase<T>::mul(scratch, q_limbs, qn, ctx->p[row][1-col], n);

                assert(n + qn >= ctx->n);
                c[row] = mpbase<T>::add(ctx->p[row][col], scratch, n + qn, ctx->p[row][col], ctx->n);
            }

            n += qn;

            if (c[0] | c[1]) {
                ctx->p[0][col][n] = c[0];
                ctx->p[1][col][n] = c[1];
                n++;
            }
            else {
                n -= (ctx->p[0][col][n-1] | ctx->p[1][col][n-1]) == 0;
                assert(n >= ctx->n);
            }
            ctx->n = n;
        }

        assert(ctx->n < ctx->alloc);
    }

    /**
     * Callback method for Jacobi update
     * @param p Pointer to the bits context
     * @param g_limbs GCD pointer
     * @param gn Length of the GCD 
     * @param q_limbs GCD pointer
     * @param qn Length of the GCD 
     * @param d Denominator
     * @param scratch Temporary storage (unused)
     */
    static void jacobi_callback(hgcd_jacobi_ctx<T> *ctx, const T *g_limbs, size_t gn, const T *q_limbs, size_t qn,
        int d, T* scratch)
    {
        if (g_limbs) {
            assert(gn > 0);
            if (gn != 1 || g_limbs[0] != 1) {
                *ctx->bitsp = BITS_FAIL;
                return;
            }
        }

        if (q_limbs) {
            assert(qn > 0);
            assert(d >= 0);
            *ctx->bitsp = jacobi_update(*ctx->bitsp, d, q_limbs[0] & 3);
        }
    }

    /**
     * Multiply the least significant p limbs of (a;b) by M^-1
     * @param ctx Context pointer
     * @param g_limbs Pointer to A
     * @param gn Length of array
     * @param q_limbs Pointer to B
     * @param qn Length of A and B
     * @param d Denominator
     * @param scratch Temporary storage
     * @return Adjusted array length
     */
    static void hgcd_jacobi_callback(hgcd_jacobi_ctx<T> *ctx, const T* g_limbs, size_t gn,
        const T* q_limbs, size_t qn, int d, T* scratch)
    {
        assert(!g_limbs);
        assert(d >= 0);

        qn = mpbase<T>::normalized_size(q_limbs, qn);
        if (qn > 0) {
            hgcd_matrix_update_q(ctx->M, q_limbs, qn, d, scratch);
            *ctx->bitsp = jacobi_update(*ctx->bitsp, d, q_limbs[0] & 3);
        }
    }

    /**
     * An iterative step for hgcd_jacobi()
     * @param n Length of A and B
     * @param a_limbs Pointer to A
     * @param b_limbs Pointer to B
     * @param s Step length
     * @param M Context pointer
     * @param bitsp Pointer to the bits count
     * @param scratch Temporary storage
     * @return Adjusted array length
     */
    static size_t hgcd_jacobi_step(size_t n, T* a_limbs, T* b_limbs, size_t s,
        hgcd_matrix_ctx<T> *M, unsigned *bitsp, T* scratch)
    {
        assert(n > s);

        T mask = a_limbs[n-1] | b_limbs[n-1];
        assert(mask > 0);

        T ah, al, bh, bl;
        if (n == s + 1) {
            if (mask < 4) {
                goto subtract;
            }

            ah = a_limbs[n-1]; al = a_limbs[n-2];
            bh = b_limbs[n-1]; bl = b_limbs[n-2];
        }
        else if (mask & LIMB_HIGHBIT) {
            ah = a_limbs[n-1]; al = a_limbs[n-2];
            bh = b_limbs[n-1]; bl = b_limbs[n-2];
        }
        else {
            int shift = bit_manipulation::clz(mask);
            ah = EXTRACT_LIMB(shift, a_limbs[n-1], a_limbs[n-2]);
            al = EXTRACT_LIMB(shift, a_limbs[n-2], a_limbs[n-3]);
            bh = EXTRACT_LIMB(shift, b_limbs[n-1], b_limbs[n-2]);
            bl = EXTRACT_LIMB(shift, b_limbs[n-2], b_limbs[n-3]);
        }

        // Try an hgcd2 step
        hgcd_matrix<T> M1;
        if (hgcd2_jacobi(ah, al, bh, bl, &M1, bitsp)) {
            // M = M * M1
            hgcd_matrix_mul_1(M, &M1, scratch);

            // Multiply M1^{-1} (a;b)
            mpbase<T>::copy(scratch, a_limbs, n);
            return matrix22<T>::mul1_inverse_vector(&M1, a_limbs, scratch, b_limbs, n);
        }

    subtract:
        hgcd_jacobi_ctx<T> ctx;
        ctx.M = M;
        ctx.bitsp = bitsp;

        return gcd_subdiv_step(a_limbs, b_limbs, n, s, jacobi<T>::hgcd_jacobi_callback, &ctx, scratch);
    }

    /**
     * Reduces a and b until |a-b| fits in n/2 + 1 limbs.
     * Generates the matrix ctx->M, where each element has at most (n+1)/2 - 1 limbs.
     * Makes recursive calls to self.
     * @param a_limbs Pointer to A
     * @param b_limbs Pointer to B
     * @param n Length of A and B
     * @param ctx Context pointer
     * @param bitsp Pointer to the bits count
     * @param scratch Temporary storage
     * @return size_t The new size of a,b. Otherwise, 0 if reduction failed.
     */
    static size_t hgcd_jacobi(T* a_limbs, T* b_limbs, size_t n,
        hgcd_matrix_ctx<T> *ctx, unsigned *bitsp, T* scratch)
    {
        size_t s = n/2 + 1;

        size_t nn;
        int success = 0;

        if (n <= s) {
            return 0;
        }

        assert((a_limbs[n-1] | b_limbs[n-1]) > 0);
        assert((n+1)/2 - 1 < ctx->alloc);

        if (ABOVE_THRESHOLD(n, HGCD_THRESHOLD)) {
            size_t n2 = (3*n)/4 + 1;
            size_t p = n/2;

            nn = hgcd_jacobi(a_limbs + p, b_limbs + p, n - p, ctx, bitsp, scratch);
            if (nn > 0) {
                // Needs 2*(p + M->n) <= 2*(floor(n/2) + ceil(n/2) - 1) = 2 (n - 1)
                n = hgcd_matrix_adjust(ctx, p + nn, a_limbs, b_limbs, p, scratch);
                success = 1;
            }

            while (n > n2) {
                // Needs n + 1 storage
                nn = hgcd_jacobi_step(n, a_limbs, b_limbs, s, ctx, bitsp, scratch);
                if (!nn)
                    return success ? n : 0;
                n = nn;
                success = 1;
            }

            if (n > s + 2) {
                hgcd_matrix_ctx<T> M1;
                size_t scratch_offset;

                p = 2*s - n + 1;
                scratch_offset = HGCD_MATRIX_INIT_SCRATCH(n - p);

                hgcd_matrix_init(&M1, n - p, scratch);
                nn = hgcd_jacobi(a_limbs + p, b_limbs + p, n - p, &M1, bitsp, scratch + scratch_offset);
                if (nn > 0) {
                    assert(ctx->n + 2 >= M1.n);
                    assert(ctx->n + M1.n < ctx->alloc);

                    // Needs 2(p + M->n) <= 2(2*s - n2 + 1 + n2 - s - 1)
                    //     = 2*s <= 2*(floor(n/2) + 1) <= n + 2
                    n = hgcd_matrix_adjust(&M1, p + nn, a_limbs, b_limbs, p, scratch + scratch_offset);

                    hgcd_matrix_mul(ctx, &M1, scratch + scratch_offset);
                    success = 1;
                }
            }
        }

        for (;;) {
            // Needs s+3 < n
            nn = hgcd_jacobi_step(n, a_limbs, b_limbs, s, ctx, bitsp, scratch);
            if (!nn) {
                return success ? n : 0;
            }

            n = nn;
            success = 1;
        }
    }

    /**
     * Reduces 2-limb a and b
     * @param ah High limb of A
     * @param al Low limb of A
     * @param bh High limb of B
     * @param bl Low limb of B
     * @param M Matrix
     * @param bitsp Pointer to the bits count
     * @return size_t The new size of a,b. Otherwise, 0 if reduction failed.
     */
    static int hgcd2_jacobi(T ah, T al, T bh, T bl, hgcd_matrix<T> *M, unsigned *bitsp)
    {
        T u00, u01, u10, u11;
        unsigned bits = *bitsp;

        if (ah < 2 || bh < 2) {
            return 0;
        }

        if (ah > bh || (ah == bh && al > bl)) {
            number<T>::usub(&ah, &al, ah, al, bh, bl);
            if (ah < 2) {
                return 0;
            }

            u00 = u01 = u11 = 1;
            u10 = 0;
            bits = jacobi_update(bits, 1, 1);
        }
        else {
            number<T>::usub(&bh, &bl, bh, bl, ah, al);
            if (bh < 2) {
                return 0;
            }

            u00 = u10 = u11 = 1;
            u01 = 0;
            bits = jacobi_update(bits, 0, 1);
        }

        if (ah < bh) {
            goto subtract_a;
        }

        for (;;) {
            assert(ah >= bh);
            if (ah == bh) {
                goto done;
            }

            if (ah < (T(1) << (std::numeric_limits<T>::digits / 2))) {
                ah = (ah << (std::numeric_limits<T>::digits / 2) ) + (al >> (std::numeric_limits<T>::digits / 2));
                bh = (bh << (std::numeric_limits<T>::digits / 2) ) + (bl >> (std::numeric_limits<T>::digits / 2));

                break;
            }

            // Subtract a -= q b, and multiply M from the right by (1 q ; 0 1),
            // affecting the second column of M
            assert(ah > bh);
            number<T>::usub(&ah, &al, ah, al, bh, bl);

            if (ah < 2) {
                goto done;
            }

            if (ah <= bh) {
                // Use q = 1
                u01 += u00;
                u11 += u10;
                bits = jacobi_update(bits, 1, 1);
            }
            else {
                T r[2], q;
                number<T>::udiv_qrrnndd(&q, &r[1], &r[0], ah, al, bh, bl);
                al = r[0]; ah = r[1];
                if (ah < 2) {
                    // A is too small, but q is correct
                    u01 += q * u00;
                    u11 += q * u10;
                    bits = jacobi_update(bits, 1, q & 3);
                    goto done;
                }
                q++;
                u01 += q * u00;
                u11 += q * u10;
                bits = jacobi_update(bits, 1, q & 3);
            }

    subtract_a:
            assert(bh >= ah);
            if (ah == bh) {
                goto done;
            }

            if (bh < (T(1) << (std::numeric_limits<T>::digits / 2))) {
                ah = (ah << (std::numeric_limits<T>::digits / 2) ) + (al >> (std::numeric_limits<T>::digits / 2));
                bh = (bh << (std::numeric_limits<T>::digits / 2) ) + (bl >> (std::numeric_limits<T>::digits / 2));

                goto subtract_a1;
            }

            // Subtract b -= q a, and multiply M from the right by (1 0 ; q 1)
            // affecting the first column of M
            number<T>::usub(&bh, &bl, bh, bl, ah, al);

            if (bh < 2) {
                goto done;
            }

            if (bh <= ah) {
                // Use q = 1
                u00 += u01;
                u10 += u11;
                bits = jacobi_update(bits, 0, 1);
            }
            else {
                T r[2], q;
                number<T>::udiv_qrrnndd(&q, &r[1], &r[0], bh, bl, ah, al);
                bl = r[0]; bh = r[1];
                if (bh < 2)
                {
                    // B is too small, but q is correct
                    u00 += q * u01;
                    u10 += q * u11;
                    bits = jacobi_update(bits, 0, q & 3);
                    goto done;
                }
                q++;
                u00 += q * u01;
                u10 += q * u11;
                bits = jacobi_update(bits, 0, q & 3);
            }
        }

        // Single precision loop
        for (;;) {
            assert(ah >= bh);
            if (ah == bh) {
                break;
            }

            ah -= bh;
            if (ah < (T(1) << (std::numeric_limits<T>::digits / 2 + 1))) {
                break;
            }

            if (ah <= bh) {
                // Use q = 1
                u01 += u00;
                u11 += u10;
                bits = jacobi_update(bits, 1, 1);
            }
            else {
                T r, q;
                number<T>::udiv_qrnd(&q, &r, ah, bh);
                ah = r;
                if (ah < (T(1) << (std::numeric_limits<T>::digits / 2 + 1)))
                {
                    // A is too small, but q is correct
                    u01 += q * u00;
                    u11 += q * u10;
                    bits = jacobi_update(bits, 1, q & 3);
                    break;
                }
                q++;
                u01 += q * u00;
                u11 += q * u10;
                bits = jacobi_update(bits, 1, q & 3);
            }

    subtract_a1:
            assert(bh >= ah);
            if (ah == bh) {
                break;
            }

            bh -= ah;
            if (bh < (T(1) << (std::numeric_limits<T>::digits / 2 + 1))) {
                break;
            }

            if (bh <= ah) {
                // Use q = 1
                u00 += u01;
                u10 += u11;
                bits = jacobi_update(bits, 0, 1);
            }
            else {
                T r, q;
                number<T>::udiv_qrnd(&q, &r, bh, ah);
                bh = r;
                if (bh < (T(1) << (std::numeric_limits<T>::digits / 2 + 1)))
                {
                    // B is too small, but q is correct
                    u00 += q * u01;
                    u10 += q * u11;
                    bits = jacobi_update(bits, 0, q & 3);
                    break;
                }
                q++;
                u00 += q * u01;
                u10 += q * u11;
                bits = jacobi_update(bits, 0, q & 3);
            }
        }

    done:
        M->u[0][0] = u00;
        M->u[0][1] = u01;
        M->u[1][0] = u10;
        M->u[1][1] = u11;
        *bitsp = bits;

        return 1;
    }

    /**
     * Subtraction and division of A and bB
     * @param a_limbs Pointer to A
     * @param b_limbs Pointer to B
     * @param n Length of A and B
     * @param s Step size
     * @param cb Callback function
     * @param ctx Context pointer
     * @param scratch Temporary storage
     * @return size_t The new size of a,b. Otherwise, 0 if reduction failed.
     */
    static size_t gcd_subdiv_step(T* a_limbs, T* b_limbs, size_t n, size_t s,
        gcd_subdiv_step_callback<T> *cb, hgcd_jacobi_ctx<T> *ctx, T* scratch)
    {
        assert(n > 0);
        assert(a_limbs[n-1] > 0 || b_limbs[n-1] > 0);

        size_t an = mpbase<T>::normalized_size(a_limbs, n);
        size_t bn = mpbase<T>::normalized_size(b_limbs, n);

        static const T one = T(1);
        int swapped = 0;

        // Arrange so that a < b, subtract b -= a, and maintain normalization
        if (an == bn) {
            int c = mpbase<T>::cmp(a_limbs, b_limbs, an);
            if (0 == c) {
                // For gcdext, return the smallest of the two cofactors, so pass d = -1
                if (0 == s) {
                    cb(ctx, a_limbs, an, nullptr, 0, -1, nullptr);
                }
                return 0;
            }
            else if (c > 0) {
                swap_ptrs<T>(a_limbs, b_limbs);
                swapped ^= 1;
            }
        }
        else {
            if (an > bn) {
                swap_ptrs<T>(a_limbs, b_limbs);
                bit_manipulation::swap<size_t>(an, bn);
                swapped ^= 1;
            }
        }
        if (an <= s) {
            if (s == 0)
                cb(ctx, b_limbs, bn, nullptr, 0, swapped ^ 1, nullptr);
            return 0;
        }

        mpbase<T>::sub(b_limbs, b_limbs, bn, a_limbs, an);
        bn = mpbase<T>::normalized_size(b_limbs, bn);
        assert(bn > 0);

        if (bn <= s) {
            // Undo subtraction
            T cy = mpbase<T>::add(b_limbs, a_limbs, an, b_limbs, bn);
            if (cy > 0) {
                b_limbs[an] = cy;
            }
            return 0;
        }

        // Arrange so that a < b
        if (an == bn) {
            int c = mpbase<T>::cmp(a_limbs, b_limbs, an);
            if (0 == c) {
                if (s > 0) {
                    // Just record subtraction and return
                    cb(ctx, nullptr, 0, &one, 1, swapped, nullptr);
                }
                else {
                    // Found gcd
                    cb(ctx, b_limbs, bn, nullptr, 0, swapped, nullptr);
                }
                return 0;
            }

            cb(ctx, nullptr, 0, &one, 1, swapped, nullptr);

            if (c > 0) {
                swap_ptrs<T>(a_limbs, b_limbs);
                swapped ^= 1;
            }
        }
        else {
            cb(ctx, nullptr, 0, &one, 1, swapped, nullptr);

            if (an > bn) {
                swap_ptrs<T>(a_limbs, b_limbs);
                bit_manipulation::swap<size_t>(an, bn);
                swapped ^= 1;
            }
        }

        mpbase<T>::div_quorem(scratch, nullptr, b_limbs, bn, a_limbs, an);
        size_t qn = bn - an + 1;
        bn = mpbase<T>::normalized_size(b_limbs, an);

        if (bn <= s) {
            if (s == 0) {
                cb(ctx, a_limbs, an, scratch, qn, swapped, scratch + qn);
                return 0;
            }

            // Quotient is one too large, so decrement it and add back A
            if (bn > 0) {
                T cy = mpbase<T>::add(b_limbs, a_limbs, an, b_limbs, bn);
                if (cy)
                    b_limbs[an++] = cy;
            }
            else {
                mpbase<T>::copy(b_limbs, a_limbs, an);
            }

            mpbase<T>::sub_1(scratch, scratch, qn, T(1));
        }

        cb(ctx, nullptr, 0, scratch, qn, swapped, scratch + qn);
        return an;
    }

    /**
     * Final operation to calculate the Jacobi symbol
     * @param bits Reduced number of bits, 0 or 1
     * @return int 1 or -1
     */
    static int jacobi_finish(unsigned bits)
    {
        // (a, b) = (1,0) or (0,1)
        assert((bits & 14) == 0);

        return 1 - 2*(bits & 1);
    }

};

/**
 * Jacobi initialization
 * @param a Least significant word of A
 * @param b Least significant word of B
 * @param s Sign
 * @return Bits
 */
template<typename T>
unsigned int mpbase<T>::jacobi_init(T a, T b, unsigned s)
{
    assert(b & 1);
    assert(s <= 1);
    return ((a & 3) << 2) + (b & 2) + s;
}

/**
 * Jacobi Symbol base case
 * @param a Least significant word of A
 * @param b Least significant word of B
 * @param bit 
 * @return Jacobi symbol of 1, 0 or -1
 */
template<typename T>
int mpbase<T>::basecase_jacobi(T a, T b, int bit)
{
    assert(b & 1);

    if (0 == a) {
        return 1 == b ? 1-2*(bit & 1) : 0;
    }

    // We represent a and b shifted right so the LSB is implicit
    int c = bit_manipulation::ctz(a);
    b >>= 1;
    bit ^= c & (b ^ (b >> 1));
    a >>= c;
    a >>= 1;

    while (a != b) {
        T t    = a - b;
        T bgta = static_cast<S>(t) >> (std::numeric_limits<T>::digits - 1);

        // If b > a, invoke reciprocity
        bit ^= (bgta & a & b);

        // b = min (a, b)
        b += (bgta & t);

        // a = |a - b|
        a = (t ^ bgta) - bgta;

        // Number of trailing zeros is the same no matter if we look at t or a
        c = bit_manipulation::ctz(t);
        c++;
        // (2/b) = -1 if b = 3 or 5 mod 8
        bit ^= c & (b ^ (b >> 1));
        a >>= c;
    }

    return 0 == a ? 1-2*(bit & 1) : 0;
}

/**
 * Jacobi symbol, special case for n=2
 * @param a_limbs Pointer to A limb array
 * @param b_limbs Pointer to B limb array
 * @param bit Reduced bit
 * @return int 0, 1 or -1
 */
template<typename T>
int mpbase<T>::jacobi_2(const T* a_limbs, const T* b_limbs, unsigned bit)
{
    int c;

    T al = a_limbs[0];
    T ah = a_limbs[1];
    T bl = b_limbs[0];
    T bh = b_limbs[1];

    assert(bl & 1);

    bl = ((bh << (std::numeric_limits<T>::digits - 1)) & LIMB_MASK) | (bl >> 1);
    bh >>= 1;

    if ((bh | bl) == 0) {
        return 1 - 2*(bit & 1);
    }

    if ((ah | al) == 0) {
        return 0;
    }

    if (al == 0) {
        al = ah;
        ah = 0;
        bit ^= std::numeric_limits<T>::digits & (bl ^ (bl >> 1));
    }

    c = bit_manipulation::ctz(al);
    bit ^= c & (bl ^ (bl >> 1));
    c++;
    if (c == std::numeric_limits<T>::digits) {
        al = ah;
        ah = 0;
    }
    else {
        al = ((ah << (std::numeric_limits<T>::digits - c)) & LIMB_MASK) | (al >> c);
        ah >>= c;
    }

    // Reduce the higher significance words of a and b to zero
    while ((ah | bh) > 0) {
        T th, tl;
        T bgta;

        // t = a - b, if t is zero then return 0
        number<T>::usub(&th, &tl, ah, al, bh, bl);
        if ((tl | th) == 0) {
            return 0;
        }

        // If the MSB of th is set then b must be greater than a, so invoke reciprocity
        // Note that bgta will be all ones if b is negative, 0 otherwise
        bgta = LIMB_HIGHBIT_TO_MASK(th);
        bit ^= (bgta & al & bl);

        // Select b such that: b = min (a, b), return the symbol if b is reduced to 0
        number<T>::uadd(&bh, &bl, bh, bl, th & bgta, tl & bgta);
        if ((bh | bl) == 0) {
            return 1 - 2*(bit & 1);
        }

        // Select a such that: a = |a - b|
        al = (bgta ^ tl) - bgta;
        ah = (bgta ^ th);

        // If b > a, al == 0 implies that we have a carry to propagate
        if (al == 0) {
            al = ah - bgta;
            ah = 0;
            bit ^= std::numeric_limits<T>::digits & (bl ^ (bl >> 1));
        }

        c = bit_manipulation::ctz(al);
        c++;
        bit ^= c & (bl ^ (bl >> 1));
        if (c == std::numeric_limits<T>::digits) {
            al = ah;
            ah = 0;
        }
        else {
            al = ((ah << (std::numeric_limits<T>::digits - c)) & LIMB_MASK) | (al >> c);
            ah >>= c;
        }
    }

    assert(bl > 0);

    while ((al | bl) & LIMB_HIGHBIT) {
        // Obtain the difference t and the mask bgta for the b > a condition
        T t    = al - bl;
        T bgta = -(bl > al);

        if (t == 0) {
            return 0;
        }

        // If b > a, invoke reciprocity
        bit ^= (bgta & al & bl);

        // Select b such that: b = min (a, b)
        bl += (bgta & t);

        // Select a such that: a = |a - b|
        al = (t ^ bgta) - bgta;

        c = bit_manipulation::ctz(t);
        c++;
        bit ^= c & (bl ^ (bl >> 1));

        // If only the MSB of t is set, i.e. the maximum negative value, return the symbol
        if (c == std::numeric_limits<T>::digits) {
            return 1 - 2*(bit & 1);
        }

        // Remove the trailing bits from the difference
        al >>= c;
    }

    // Fall back to the base case algorithm
    return basecase_jacobi(2*al+1, 2*bl+1, bit);
}

/**
 * Jacobi symbol for arrays of length n
 * @param a_limbs Pointer to A limb array
 * @param b_limbs Pointer to B limb array
 * @param n Length of input arrays
 * @param bits Reduced bits
 * @return int 0, 1 or -1
 */
template<typename T>
int mpbase<T>::jacobi_n(T *a_limbs, T *b_limbs, size_t n, unsigned bits)
{
    assert(n > 0);
    assert((a_limbs[n-1] | b_limbs[n-1]) > 0);
    assert((b_limbs[0] | a_limbs[0]) & 1);

    size_t scratch_size = n;
    size_t matrix_scratch;
    T* scratch;

    // Update the scratch size if we need to reduce n
    if (ABOVE_THRESHOLD(n, GCD_THRESHOLD)) {
        size_t p = GET_2_3_N(n);

        matrix_scratch = HGCD_MATRIX_INIT_SCRATCH(n - p);
        size_t hgcd_scratch = jacobi<T>::hgcd_scratch_size(n - p);
        size_t update_scratch = p + n - 1;

        size_t new_scratch_size = matrix_scratch + MAX(hgcd_scratch, update_scratch);
        if (new_scratch_size > scratch_size) {
            scratch_size = new_scratch_size;
        }
    }

    // Allocate memory for intermediate storage
    scratch = reinterpret_cast<T*>(aligned_malloc(sizeof(T) * scratch_size));

    // Reduce vector/matrix size to the upper threshold
    while (ABOVE_THRESHOLD(n, GCD_THRESHOLD)) {
        hgcd_matrix_ctx<T> M;
        size_t p = GET_2_3_N(n);

        matrix_scratch = HGCD_MATRIX_INIT_SCRATCH(n - p);
        jacobi<T>::hgcd_matrix_init(&M, n - p, scratch);

        size_t nn = jacobi<T>::hgcd_jacobi(a_limbs + p, b_limbs + p, n - p, &M, &bits, scratch + matrix_scratch);
        if (nn > 0) {
            assert(M.n <= (n - p - 1)/2);
            assert(M.n + p <= (p + n - 1) / 2);
            // Temporary storage 2(p + M->n) <= p + n - 1
            n = jacobi<T>::hgcd_matrix_adjust(&M, p + nn, a_limbs, b_limbs, p, scratch + matrix_scratch);
        }
        else {
            hgcd_jacobi_ctx<T> ctx;
            ctx.M     = nullptr;
            ctx.bitsp = &bits;

            // Temporary storage n
            n = jacobi<T>::gcd_subdiv_step(a_limbs, b_limbs, n, 0, jacobi<T>::jacobi_callback, &ctx, scratch);
            if (!n) {
                aligned_free(scratch);
                return bits == BITS_FAIL ? 0 : jacobi<T>::jacobi_finish(bits);
            }
        }
    }

    // Reduce vector/matrix size to less than or equal to 2
    while (n > 2) {
        hgcd_matrix<T> M;
        T ah, al, bh, bl;

        T mask = a_limbs[n-1] | b_limbs[n-1];
        assert(mask > 0);

        if (mask & LIMB_HIGHBIT) {
            ah = a_limbs[n-1]; al = a_limbs[n-2];
            bh = b_limbs[n-1]; bl = b_limbs[n-2];
        }
        else {
            int shift = bit_manipulation::clz(mask);
            ah = EXTRACT_LIMB(shift, a_limbs[n-1], a_limbs[n-2]);
            al = EXTRACT_LIMB(shift, a_limbs[n-2], a_limbs[n-3]);
            bh = EXTRACT_LIMB(shift, b_limbs[n-1], b_limbs[n-2]);
            bl = EXTRACT_LIMB(shift, b_limbs[n-2], b_limbs[n-3]);
        }

        // Try an hgcd2_jacobi step
        if (jacobi<T>::hgcd2_jacobi(ah, al, bh, bl, &M, &bits)) {
            n = matrix22<T>::mul1_inverse_vector(&M, scratch, a_limbs, b_limbs, n);
            swap_ptrs<T>(a_limbs, scratch);
        }
        else {
            hgcd_jacobi_ctx<T> ctx;
            ctx.M     = nullptr;
            ctx.bitsp = &bits;

            // hgcd2_jacobi failed - either one of a or b is very small, or the difference is very small
            n = jacobi<T>::gcd_subdiv_step(a_limbs, b_limbs, n, 0, &jacobi<T>::jacobi_callback, &ctx, scratch);
            if (!n) {
                // Subtraction and division failed, free resources and return the symbol of 1 or -1
                aligned_free(scratch);
                return bits == BITS_FAIL ? 0 : jacobi<T>::jacobi_finish(bits);
            }
        }
    }

    // Free intermediate memory resources
    aligned_free(scratch);

    assert(b_limbs[0] & 1);

    if (n == 2) {
        int res = jacobi_2(a_limbs, b_limbs, bits & 1);
        return res;
    }

    // n == 1
    if (1 == b_limbs[0]) {
        // If b is equal to 1 then we can return with thr Jacobi symbol
        return 1 - 2*(bits & 1);
    }
    else {
        // If b != 1 then we must calculate the Jacobi symbol with basecase_jacobi()
        return basecase_jacobi(a_limbs[0], b_limbs[0], bits);
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
