/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "core/mpbase.hpp"

/// Threshold for choice of FFT or non-FFT multiplication
#define MUL_FFT_MODF_THRESHOLD   (MUL_TOOM33_THRESHOLD * 3)

/// Threshold for choice of FFT or non-FFT squaring
#define SQR_FFT_MODF_THRESHOLD   (SQR_TOOM3_THRESHOLD * 3)

/// The threshold where FFT multiplication becomes optimal
#define MUL_FFT_THRESHOLD           1000

/// The threshold where FFT squaring becomes optimal
#define SQR_FFT_THRESHOLD           750

namespace phantom {
namespace core {


/**
 * @brief A helper class for FFT multiplication with commonly used methods
 * 
 * @tparam T Data type used for underlying multiple precision arithmetic
 */
template <typename T>
class fft_multiplication
{
    /// First k to use for an FFT multiply, where FFT runs in log(2^k)/log(2^(k-1)).
    /// k=3 is 1.5, k=4 is 1.33 which beats Toom3 (runs in log(5)/log(3), i.e. 1.46).
    static constexpr size_t _fft_first_k = 4;

    static constexpr size_t _fft_table_size = 7;

    static constexpr size_t _fft_table[2][_fft_table_size] = {
        {
            MUL_TOOM33_THRESHOLD * 4,    // k=5
            MUL_TOOM33_THRESHOLD * 8,    // k=6
            MUL_TOOM33_THRESHOLD * 16,   // k=7
            MUL_TOOM33_THRESHOLD * 32,   // k=8
            MUL_TOOM33_THRESHOLD * 96,   // k=9
            MUL_TOOM33_THRESHOLD * 288,  // k=10
            0
        },
        {
            SQR_TOOM3_THRESHOLD * 4,     // k=5
            SQR_TOOM3_THRESHOLD * 8,     // k=6
            SQR_TOOM3_THRESHOLD * 16,    // k=7
            SQR_TOOM3_THRESHOLD * 32,    // k=8
            SQR_TOOM3_THRESHOLD * 96,    // k=9
            SQR_TOOM3_THRESHOLD * 288,   // k=10
            0
        }
    };

public:
    /**
     * @brief Generate the FFT bit reverse table
     * 
     * @param l k-by-[1..2^k] bit reverse coefficients
     * @param k Selected k
     */
    static void init(int **l, int k)
    {
        l[0][0] = 0;
        for (size_t i = 1, K = 1; i <= k; i++, K <<= 1) {
            int *li = l[i];
            for (size_t j = 0; j < K; j++) {
                li[j] = 2 * l[i - 1][j];
                li[K + j] = 1 + li[j];
            }
        }
    }

    /**
     * @brief Return an optimal k value for multiplication or squaring
     * 
     * @param n Number of limbs in array
     * @param sqr 0 if multiplication, 1 if squaring
     * @return int k value for window
     */
    static int best_k(size_t n, size_t sqr)
    {
        size_t i;

        for (i = 0; fft_multiplication<T>::_fft_table[sqr][i] != 0; i++)
        {
            if (n < fft_multiplication<T>::_fft_table[sqr][i]){
                return i + _fft_first_k;
            }
        }

        if (i == 0 || n < 4 * fft_multiplication<T>::_fft_table[sqr][i - 1]) {
            return i + _fft_first_k;
        }
        else {
            return i + _fft_first_k + 1;
        }
    }

    /**
     * @brief Multiplication by a power of 2, r = a*2^d mod 2^(n*B)+1 with a = {a, n+1}
     * 
     * @param r Output product (n+1 limbs)
     * @param a Input array, a[n] <= 1 (n+1 limbs)
     * @param d Exponent value
     * @param n Length of input array
     */
    static void mul_2exp_modF(T _RESTRICT_ *r, const T _RESTRICT_ *a, size_t d, ssize_t n)
    {
        T cc, rd;

        unsigned int bits = d & (std::numeric_limits<T>::digits - 1);
        ssize_t      m    = d >> bits_log2<T>::value();

        if (m >= n) {
            // r[0..m-1]  <--  lshift(a[n-m]..a[n-1], bits)
            // r[m..n-1]  <-- -lshift(a[0]..a[n-m-1], bits)

            m -= n;
            if (0 != bits) {
                mpbase<T>::lshift(r, a + n - m, m + 1, bits);
                rd = r[m];
                cc = mpbase<T>::lshiftc(r + m, a, n - m, bits);
            }
            else {
                mpbase<T>::copy(r, a + n - m, m);
                rd = a[n];
                mpbase<T>::ones_complement(r + m, a, n - m);
                cc = 0;
            }

            r[n] = 0;

            // Add carry + 1 to r[0], no overflow can occur here
            cc++;
            mpbase<T>::incr_u(r, cc);

            // Add rd + 1 to r[m], rd can potentiallyoverflow
            rd++;
            cc = (0 == rd) ? 1 : rd;
            r = r + m + (0 == rd);
            mpbase<T>::incr_u(r, cc);
        }
        else
        {
            // r[0..m-1]  <-- -lshift(a[n-m]..a[n-1], bits)
            // r[m..n-1]  <--  lshift(a[0]..a[n-m-1], bits)

            if (bits != 0) {
                mpbase<T>::lshiftc(r, a + n - m, m + 1, bits);
                rd = ~r[m];
                cc = mpbase<T>::lshift(r + m, a, n - m, bits);
            }
            else {
                mpbase<T>::ones_complement(r, a + n - m, m + 1);
                rd = a[n];
                mpbase<T>::copy(r + m, a, n - m);
                cc = 0;
            }

            // now complement {r, m}, subtract cc from r[0], subtract rd from r[m]

            if (m != 0) {
                // Add 1 to r[0] and subtract 1 from r[m]
                if (cc-- == 0) {
                    cc = mpbase<T>::add_1(r, r, n, static_cast<T>(1));
                }
                cc = mpbase<T>::sub_1(r, r, m, cc);

                // Actually need rd incremented but it may overflow, as both are subtracted
                // from r[m..n] we add 1 to cc instead
                cc++;
            }

            // Subtract cc and rd from r[m..n], compensating if r[n] is negative
            r[n] = -mpbase<T>::sub_1(r + m, r + m, n - m, cc);
            r[n] -= mpbase<T>::sub_1(r + m, r + m, n - m, rd);
            if (r[n] & LIMB_HIGHBIT) {
                r[n] = mpbase<T>::add_1(r, r, n, static_cast<T>(1));
            }
        }
    }

    /**
    * @brief Return the smallest possible number of limbs >= pl for an fft of size 2^k
    * 
    * @param pl Product length
    * @param k Window size
    * @return size_t Smallest multiple of 2^k >= pl
    */
    static size_t next_size(size_t pl, int k)
    {
        pl = 1 + ((pl - 1) >> k);  // ceil (pl/2^k)
        return pl << k;
    }

    /**
     * @brief Least common multiple of a and 2^k
     * 
     * @param a INput value a
     * @param k Input value k (representing 2^k)
     * @return size_t lcm(a, 2^k)
     */
    static size_t lcm(size_t a, size_t k)
    {
        int l = k;

        while ((a & 0x1) == 0 && k > 0)
        {
            a >>= 1;
            k--;
        }
        return a << l;
    }

    /**
     * @brief Reduce a modulo 2^(n*B) + 1
     * 
     * @param ap Pointer to a of length n+1, a[n] <= 1
     * @param n Length of input array
     */
    static void normalize(T *ap, size_t n)
    {
        if (ap[n] != 0) {
            mpbase<T>::decr_u(ap, static_cast<T>(1));
            if (ap[n] == 0) {
                mpbase<T>::zero(ap, n);
                ap[n] = 1;
            }
            else {
                ap[n] = 0;
            }
        }
    }

    /**
     * @brief Decomposition of a sequence into frequency components
     * 
     * @param A Temporary storage of length (nprime2 + 1) * 2^k
     * @param Ap Output
     * @param K 2*k
     * @param nprime Basic decomposition length factor
     * @param n Input data array
     * @param nl Length of input array
     * @param l n / 2^k
     * @param Mp Windows size factor
     * @param scratch Temporary storage
     */
    static void decompose(T *A, T **Ap, ssize_t K, ssize_t nprime,
                          const T *n, ssize_t nl, ssize_t l, ssize_t Mp, T *scratch)
    {
        using S = signed_type_t<T>;

        ssize_t i, j;
        T *tmp = nullptr;
        ssize_t Kl = K * l;

        if (nl > Kl) {
            // Normalize {n, nl} mod 2^(Kl*B)+1
            ssize_t dif = nl - Kl;
            S cy;

            tmp = reinterpret_cast<T *>(aligned_malloc(sizeof(T) * (Kl + 1)));

            if (dif > Kl) {
                int subp = 0;

                cy = mpbase<T>::sub_n(tmp, n, n + Kl, Kl);
                n += 2 * Kl;
                dif -= Kl;

                while (dif > Kl) {
                    if (subp) {
                        cy += mpbase<T>::sub_n(tmp, tmp, n, Kl);
                    }
                    else {
                        cy -= mpbase<T>::add_n(tmp, tmp, n, Kl);
                    }

                    subp ^= 1;
                    n += Kl;
                    dif -= Kl;
                }

                if (subp) {
                    cy += mpbase<T>::sub(tmp, tmp, Kl, n, dif);
                }
                else {
                    cy -= mpbase<T>::add(tmp, tmp, Kl, n, dif);
                }

                if (cy >= 0) {
                    cy = mpbase<T>::add_1(tmp, tmp, Kl, cy);
                }
                else {
                    cy = mpbase<T>::sub_1(tmp, tmp, Kl, -cy);
                }
            }
            else {
                // dif <= Kl, i.e. nl <= 2 * Kl
                cy = mpbase<T>::sub(tmp, n, Kl, n + Kl, dif);
                cy = mpbase<T>::add_1(tmp, tmp, Kl, cy);
            }

            tmp[Kl] = cy;
            nl      = Kl + 1;
            n       = tmp;
        }

        for (i = 0; i < K; i++) {
            Ap[i] = A;

            if (nl > 0) {
                j = (l <= nl && i < K - 1) ? l : nl;
                nl -= j;
                mpbase<T>::copy(scratch, n, j);  // NOLINT
                mpbase<T>::zero(scratch + j, nprime + 1 - j);
                n += l;
                mul_2exp_modF(A, scratch, i * Mp, nprime);
            }
            else {
                mpbase<T>::zero(A, nprime + 1);
            }

            A += nprime + 1;
        }
        assert(0 == nl);

        if (tmp != nullptr) {
            aligned_free(tmp);
        }
    }

    /**
     * @brief Modulo addition appropriate to the FFT size, out = in1+in2 mod 2^(n*B)+1
     * 
     * @param out Output
     * @param in1 Input data array 1, in1[n] <= 1
     * @param in2 Input data array 2, in2[n] <= 1
     * @param n Length of input operands
     */
    static void add_modF(T *out, const T *in1, const T *in2, ssize_t n)
    {
        T c = in1[n] + in2[n] + mpbase<T>::add_n(out, in1, in2, n);

        // 0 <= c <= 3
        T x = (c - 1) & -(c != 0);
        out[n] = c - x;
        mpbase<T>::decr_u(out, x);
    }

    /**
     * @brief Modulo subtraction appropriate to the FFT size, out = in1-in2 mod 2^(n*B)+1
     * 
     * @param out Output
     * @param in1 Input data array 1, in1[n] <= 1
     * @param in2 Input data array 2, in2[n] <= 1
     * @param n Length of input operands
     */
    static void sub_modF(T *out, const T *in1, const T *in2, ssize_t n)
    {
        T c = in1[n] - in2[n] - mpbase<T>::sub_n(out, in1, in2, n);

        // -2 <= c <= 1
        T x = (-c) & -((c & LIMB_HIGHBIT) != 0);
        out[n] = x + c;
        mpbase<T>::incr_u(out, x);
    }

    /**
     * @brief Recursive FFT
     * 
     * @param Ap A[0..inc*(K-1] residues mod 2^N+1, transformed such that A[inc*ll[k][i]] = \sum (2^omega)^(ij) A[inc*j] mod 2^N+1
     * @param K 2^k
     * @param ll Bit reverse table
     * @param omega 2^omega is a primitive root mod 2^N+1
     * @param n Length, such that N = n*B
     * @param inc Step size
     * @param scratch Temporary storage
     */
    static void fft(T **Ap, size_t K, int **ll,
                    size_t omega, size_t n, size_t inc, T *scratch)
    {
        if (K == 2) {
            mpbase<T>::copy(scratch, Ap[0], n + 1);
            mpbase<T>::add_n(Ap[0], Ap[0], Ap[inc], n + 1);
            T cy = mpbase<T>::sub_n(Ap[inc], scratch, Ap[inc], n + 1);
            if (Ap[0][n] > 1) {
                Ap[0][n] = 1 - mpbase<T>::sub_1(Ap[0], Ap[0], n, Ap[0][n] - 1);
            }
            if (cy) {
                Ap[inc][n] = mpbase<T>::add_1(Ap[inc], Ap[inc], n, ~Ap[inc][n] + 1);
            }
        }
        else {
            size_t K2 = K >> 1;
            int *lk = *ll;

            fft(Ap, K2, ll - 1, 2 * omega, n, inc * 2, scratch);
            fft(Ap + inc, K2, ll - 1, 2 * omega, n, inc * 2, scratch);

            for (size_t j = 0; j < K2; j++, lk += 2, Ap += 2 * inc) {
                mul_2exp_modF(scratch, Ap[inc], lk[0] * omega, n);
                sub_modF(Ap[inc], Ap[0], scratch, n);
                add_modF(Ap[0], Ap[0], scratch, n);
            }
        }
    }

    /**
     * @brief Recursive inverse FFT
     * 
     * @param Ap A^[ll[k][0]]..A^[ll[k][K-1]], Ap[][n] <= 1
     * @param K 2^k
     * @param omega 2^omega is a primitive root mod 2^N+1
     * @param n Length, such that N = n*B
     * @param tp Temporary storage
     */
    static void fftinv(T **Ap, size_t K, size_t omega, size_t n, T *tp)
    {
        if (K == 2) {
            T cy;
            mpbase<T>::copy(tp, Ap[0], n + 1);
            mpbase<T>::add_n(Ap[0], Ap[0], Ap[1], n + 1);
            cy = mpbase<T>::sub_n(Ap[1], tp, Ap[1], n + 1);
            if (Ap[0][n] > 1) {
                Ap[0][n] = 1 - mpbase<T>::sub_1(Ap[0], Ap[0], n, Ap[0][n] - 1);
            }
            if (cy) {
                Ap[1][n] = mpbase<T>::add_1(Ap[1], Ap[1], n, ~Ap[1][n] + 1);
            }
        }
        else {
            size_t K2 = K >> 1;

            fftinv(Ap,      K2, 2 * omega, n, tp);
            fftinv(Ap + K2, K2, 2 * omega, n, tp);

            for (size_t j = 0; j < K2; j++, Ap++) {
                mul_2exp_modF(tp, Ap[K2], j * omega, n);
                sub_modF(Ap[K2], Ap[0], tp, n);
                add_modF(Ap[0],  Ap[0], tp, n);
            }
        }
    }

    /**
     * @brief Multiplication (or squaring) of 2 operands
     * 
     * in1[i] = in1[i]*in2[i] mod 2^(n*B)+1 for 0 <= i < K
     * 
     * @param in1 Input 1
     * @param in2 Input 2
     * @param n Length of inputs
     * @param K Steps
     */
    static void mul_modF_K(T **in1, T **in2, ssize_t n, ssize_t K)
    {
        int i;
        int sqr = (in1 == in2);

        if (n >= (sqr ? SQR_FFT_MODF_THRESHOLD : MUL_FFT_MODF_THRESHOLD)) {
            ssize_t K2, nprime2, Nprime2, M2, maxLK, l, Mp2;
            int k;
            int **fft_l, *tmp;
            T **Ap, **Bp, *A, *B, *scratch;

            k = best_k(n, sqr);
            K2 = static_cast<size_t>(1) << k;
            assert((n & (K2 - 1)) == 0);
            maxLK = MAX(K2, std::numeric_limits<T>::digits);
            M2 = (n * std::numeric_limits<T>::digits) >> k;
            l = n >> k;
            Nprime2 = ((2 * M2 + k + 2 + maxLK) / maxLK) * maxLK;
            nprime2 = Nprime2 >> bits_log2<T>::value();

            if (nprime2 >= (sqr ? SQR_FFT_MODF_THRESHOLD : MUL_FFT_MODF_THRESHOLD)) {
                // nprime2 must be a multiple of the next K
                ssize_t K3;
                for (;;) {
                    K3 = static_cast<size_t>(1) << best_k(nprime2, sqr);
                    if ((nprime2 & (K3 - 1)) == 0) {
                        break;
                    }
                    nprime2 = (nprime2 + K3 - 1) & -K3;
                    Nprime2 = nprime2 >> bits_log2<T>::value();
                }
            }
            assert(nprime2 < n);

            Mp2 = Nprime2 >> k;

            Ap = reinterpret_cast<T **>(aligned_malloc(sizeof(T *) * K2));
            Bp = reinterpret_cast<T **>(aligned_malloc(sizeof(T *) * K2));
            scratch = reinterpret_cast<T *>(aligned_malloc(sizeof(T) * (4 * (nprime2 + 1) << k)));
            A = scratch + (2 * (nprime2 + 1) << k);
            B = A + ((nprime2 + 1) << k);
            fft_l = reinterpret_cast<int**>(aligned_malloc(sizeof(int*) * (k + 1)));
            tmp = reinterpret_cast<int*>(aligned_malloc(sizeof(int) * ((size_t) 2 << k)));
            for (i = 0; i <= k; i++) {
                fft_l[i] = tmp;
                tmp += static_cast<T>(1) << i;
            }

            init(fft_l, k);

            for (i = 0; i < K; i++, in1++, in2++) {
                normalize(*in1, n);
                if (!sqr)
                    normalize(*in2, n);

                decompose(A, Ap, K2, nprime2, *in1, (l << k) + 1, l, Mp2, scratch);
                if (!sqr)
                    decompose(B, Bp, K2, nprime2, *in2, (l << k) + 1, l, Mp2, scratch);

                T cy = mul_internal(*in1, n, k, Ap, Bp, A, B, nprime2,
                                    l, Mp2, fft_l, scratch, sqr);
                (*in1)[n] = cy;
            }

            aligned_free(Ap);
            aligned_free(Bp);
            aligned_free(scratch);
            aligned_free(fft_l);
            aligned_free(tmp);
        }
        else {
            T cc;
            size_t n2 = 2 * n;
            T *temp   = reinterpret_cast<T *>(aligned_malloc(sizeof(T) * n2));
            T *temp_n = temp + n;
            for (i = 0; i < K; i++) {
                T *a = *in1++;
                T *b = *in2++;

                if (sqr) {
                    mpbase<T>::sqr(temp, a, n);
                }
                else {
                    mpbase<T>::mul_n(temp, b, a, n);
                }

                cc = 0;
                if (a[n] != 0) {
                    cc = mpbase<T>::add_n(temp_n, temp_n, b, n);
                }

                if (b[n] != 0) {
                    cc += mpbase<T>::add_n(temp_n, temp_n, a, n) + a[n];
                }
                if (cc != 0) {
                    cc = mpbase<T>::add_1(temp, temp, n2, cc);
                    temp[0] += cc;
                }
                a[n] = mpbase<T>::sub_n(a, temp, temp_n, n) && mpbase<T>::add_1(a, a, n, static_cast<T>(1));
            }

            aligned_free(temp);
        }
    }

    /**
     * @brief The latter stages of FFT multiplication
     */
    static T mul_internal(T *out, ssize_t pl, int k,
                          T **Ap, T **Bp, T *A, T *B,
                          size_t nprime, size_t l, size_t Mp,
                          int **fft_l, T *scratch, int sqr)
    {
        ssize_t K, i, pla, lo, sh, j;
        T *p;
        T cc;

        K = static_cast<ssize_t>(1) << k;

        // FFT, multiplication and IFFT for evaluate, pointwise multiply and interpolate
        fft(Ap, K, fft_l + k, 2 * Mp, nprime, 1, scratch);
        if (!sqr) {
            fft(Bp, K, fft_l + k, 2 * Mp, nprime, 1, scratch);
        }
        mul_modF_K(Ap, sqr ? Ap : Bp, nprime, K);
        fftinv(Ap, K, 2 * Mp, nprime, scratch);

        // Division modulo 2^k modulo 2^(n*B)+1 (modulo operations)
        Bp[0] = scratch + nprime + 1;
        div_2exp_modF(Bp[0], Ap[0], k, nprime);
        for (i = 1; i < K; i++) {
            Bp[i] = Ap[i - 1];
            div_2exp_modF(Bp[i], Ap[i], k + (K - i) * Mp, nprime);
        }

        // Combination to form the product
        mpbase<T>::zero(scratch, nprime + 1);
        pla = l * (K - 1) + nprime + 1;
        p = B;
        mpbase<T>::zero(p, pla);
        cc = 0;
        for (i = K - 1, lo = l * i + nprime, sh = l * i; i >= 0; i--, lo -= l, sh -= l) {
            T *n = p + sh;

            j = (K - i) & (K - 1);

            if (mpbase<T>::add_n(n, n, Bp[j], nprime + 1)) {
                cc += mpbase<T>::add_1(n + nprime + 1, n + nprime + 1,
                            pla - sh - nprime - 1, static_cast<T>(1));
            }
            scratch[2 * l] = i + 1;
            if (mpbase<T>::cmp(Bp[j], scratch, nprime + 1) > 0) {
                cc -= mpbase<T>::sub_1(n, n, pla - sh, static_cast<T>(1));
                cc -= mpbase<T>::sub_1(p + lo, p + lo, pla - lo, static_cast<T>(1));
            }
        }

        // Carry propagation
        if (cc == static_cast<T>(-1)) {
            if ((cc = mpbase<T>::add_1(p + pla - pl, p + pla - pl, pl, static_cast<T>(1)))) {
                mpbase<T>::sub_1(p + pla - pl - 1, p + pla - pl - 1, pl + 1, static_cast<T>(1));
                mpbase<T>::sub_1(p + pla - 1, p + pla - 1, 1, static_cast<T>(1));
            }
        }
        else if (cc == 1) {
            if (pla >= 2 * pl) {
                while ((cc = mpbase<T>::add_1(p + pla - 2 * pl, p + pla - 2 * pl, 2 * pl, cc))) {
                }
            }
            else {
                cc = mpbase<T>::sub_1(p + pla - pl, p + pla - pl, pl, cc);
                assert(0 == cc);
            }
        }
        else {
            assert(0 == cc);
        }

        return norm_modF(out, pl, p, pla);
    }

    /**
     * @brief Divide an array by 2^k modulo 2^(n*B)+1
     * 
     * @param out Output array
     * @param in Input array
     * @param k Exponent 2^k
     * @param n Length of input array
     */
    static void div_2exp_modF(T *out, const T *in, size_t k, size_t n)
    {
        assert(out != in);

        // Select a shift equivalent to multiplication by 2^(n*B) - k
        size_t i = static_cast<size_t>(2) * n * std::numeric_limits<T>::digits - k;
        mul_2exp_modF(out, in, i, n);

        // Normalize to satisfy modulo condition
        normalize(out, n);
    }

    /**
     * @brief Normalization modulo 2^(n*B)+1
     * 
     * @param out Output
     * @param out_n Required length of output
     * @param in Input
     * @param in_n Input length
     * @return T Carry out
     */
    static T norm_modF(T *out, size_t out_n, T *in, size_t in_n)
    {
        ssize_t l, m, rpn;
        T cc;

        assert((out_n <= in_n) && (in_n <= 3 * out_n));
        m = in_n - 2 * out_n;
        if (m > 0) {
            l   = out_n;
            cc  = mpbase<T>::add_n(out, in, in + 2 * out_n, m);
            rpn = mpbase<T>::add_1(out + m, in + m, out_n - m, cc);
        }
        else {
            l   = in_n - out_n;
            mpbase<T>::copy(out, in, out_n);
            rpn = 0;
        }

        cc   = mpbase<T>::sub_n(out, out, in + out_n, l);
        rpn -= mpbase<T>::sub_1(out + l, out + l, out_n - l, cc);
        if (rpn < 0) {
            rpn = mpbase<T>::add_1(out, out, out_n, static_cast<T>(1));
        }
        return rpn;
    }

    /**
     * @brief FFT-based multiplication
     * 
     * @param out Output
     * @param out_n Required output length
     * @param in1 Input 1
     * @param in1_n Input 1 length
     * @param in2 Input 2
     * @param in2_n Input 2 length
     * @param k Window constant
     * @return T Carry out
     */
    static T mul(T *out, size_t out_n,
                const T *in1, size_t in1_n,
                const T *in2, size_t in2_n,
                int k)
    {
        ssize_t K      = static_cast<size_t>(1) << k;;
        ssize_t maxLK  = lcm(std::numeric_limits<T>::digits, k);
        ssize_t N      = out_n * std::numeric_limits<T>::digits;
        ssize_t M      = N >> k;
        ssize_t l      = 1 + ((M - 1) >> bits_log2<T>::value());
        ssize_t Nprime = (1 + (2 * M + k + 2) / maxLK) * maxLK;
        ssize_t nprime = Nprime >> bits_log2<T>::value();
        ssize_t Mp;
        T **Ap, **Bp, *A, *B, *scratch;
        int **fft_l, *tmp, *tmp1;
        int sqr = (in1 == in2 && in1_n == in2_n);

        assert(next_size(out_n, k) == out_n);

        fft_l = reinterpret_cast<int **>(aligned_malloc(sizeof(int *) * (k + 1)));
        tmp1 = reinterpret_cast<int *>(aligned_malloc(sizeof(int) * ((size_t)2 << k)));
        tmp = tmp1;
        for (size_t i = 0; i <= k; i++) {
            fft_l[i] = tmp;
            tmp += static_cast<size_t>(1) << i;
        }
        init(fft_l, k);

        if (nprime >= (sqr ? SQR_FFT_MODF_THRESHOLD : MUL_FFT_MODF_THRESHOLD)) {
            ssize_t K2;
            for (;;) {
                K2 = static_cast<size_t>(1) << best_k(nprime, sqr);
                if ((nprime & (K2 - 1)) == 0)
                    break;
                nprime = (nprime + K2 - 1) & -K2;
                Nprime = nprime * std::numeric_limits<T>::digits;
            }
        }
        assert(nprime < out_n);

        scratch = reinterpret_cast<T *>(aligned_malloc(sizeof(T) * (2 * (nprime + 1))));
        Mp = Nprime >> k;

        A = reinterpret_cast<T *>(aligned_malloc(sizeof(T) * (K * (nprime + 1))));
        Ap = reinterpret_cast<T **>(aligned_malloc(sizeof(T *) * K));
        decompose(A, Ap, K, nprime, in1, in1_n, l, Mp, scratch);
        if (sqr) {
            size_t pla = l * (K - 1) + nprime + 1;
            B = reinterpret_cast<T *>(aligned_malloc(sizeof(T) * pla));
            Bp = reinterpret_cast<T **>(aligned_malloc(sizeof(T *) * K));
        }
        else {
            B = reinterpret_cast<T *>(aligned_malloc(sizeof(T) * (K * (nprime + 1))));
            Bp = reinterpret_cast<T **>(aligned_malloc(sizeof(T *) * K));
            decompose(B, Bp, K, nprime, in2, in2_n, l, Mp, scratch);
        }

        T h = mul_internal(out, out_n, k, Ap, Bp, A, B, nprime, l, Mp, fft_l, scratch, sqr);

        aligned_free(fft_l);
        aligned_free(tmp1);
        aligned_free(scratch);
        aligned_free(A);
        aligned_free(Ap);
        aligned_free(B);
        aligned_free(Bp);
        return h;
    }
};

/// Declare an instance of the bit reverse table
template<typename T>
constexpr size_t fft_multiplication<T>::_fft_table[2][fft_multiplication<T>::_fft_table_size];

/**
 * FFT-based multiplication of 2 arrays
 * @param out Product
 * @param in1 Multiplicand 1
 * @param n1 Length of multiplicand 1
 * @param in2 Multiplicand 2
 * @param n2 Length of multiplicand 2
 * @return Carry word
 */
template<typename T>
void mpbase<T>::mul_fft(T * out, const T *in1, size_t n1, const T *in2, size_t n2)
{
    T *scratch;
    ssize_t pl, pl2, pl3, l;
    ssize_t cc, c2, oldcc;
    int k2, k3;
    int sqr = (in1 == in2 && n1 == n2);

    // Number of product limbs
    pl = n1 + n2;

    // Perform an fft mod 2^(2N)+1 and one mod 2^(3N)+1
    //     pl3 = 3/2 * pl2
    //     pl3 is a multiple of 2^k3
    //     pl2 is a multiple of 2^k2
    //     k3 >= k2, both are multiples of 2^k2
    //     (pl2,pl3) = (2*j*2^k2,3*j*2^k2), which works for 3*j <= pl/2^k2 <= 5*j
    //
    // Consecutive intervals MUST overlap, i.e. 5*j >= 3*(j+1) from above, where j >= 2.
    // Thus this scheme requires pl >= 6 * 2^_fft_first_k.
    //
    // Start search with pl2 = ceil(2*pl/5) (minus one to offset increment in loop),
    // i.e. pl2 = ceil(2*pl/5) - 1 = (2*pl+4)/5 - 1 = (2*pl-1)/5
    pl2 = (2 * pl - 1) / 5;
    do {
        pl2++;
        k2  = fft_multiplication<T>::best_k(pl2, sqr);
        pl2 = fft_multiplication<T>::next_size(pl2, k2);
        pl3 = 3 * pl2 / 2;
        k3  = fft_multiplication<T>::best_k(pl3, sqr);
    } while (fft_multiplication<T>::next_size(pl3, k3) != pl3);

    assert(pl3 <= pl);

    // Allocate pl2 limbs for intermediate storage
    scratch = reinterpret_cast<T *>(aligned_malloc(sizeof(T) * pl2));

    // Calculate lambda - mu, FFT mod 2^(2N)+1 and mod 2^(3N)+1
    cc = fft_multiplication<T>::mul(out, pl3, in1, n1, in2, n2, k3);      // mu
    assert(cc == 0);
    cc = fft_multiplication<T>::mul(scratch, pl2, in1, n1, in2, n2, k2);  // lambda
    cc = -cc + mpbase<T>::sub_n(scratch, scratch, out, pl2);              // lambda - LOW(mu)
    assert(0 <= cc && cc <= 1);

    l = pl3 - pl2;

    // lambda + HIGH(mu) + carry
    c2 = mpbase<T>::add_n(scratch, scratch, out + pl2, l);
    cc = mpbase<T>::add_1(scratch + l, scratch + l, l, static_cast<T>(c2)) - cc;
    assert(-1 <= cc && cc <= 1);
    if (cc < 0) {
        cc = mpbase<T>::add_1(scratch, scratch, pl2, static_cast<T>(-cc));
    }
    assert(0 <= cc && cc <= 1);

    // LOW(scratch) -= HIGH(scratch), HIGH(scratch) += LOW(scratch)
    oldcc = cc;
    {
        T *tmp = reinterpret_cast<T *>(aligned_malloc(sizeof(T) * l));
        mpbase<T>::copy(tmp, scratch, l);  // NOLINT
        c2  = mpbase<T>::sub_n(scratch,      scratch, scratch + l, l);
        cc += mpbase<T>::add_n(scratch + l, tmp,     scratch + l, l);
        aligned_free(tmp);
    }
    c2 += oldcc;

    // Normalize {scratch, pl2} then divide by 2
    cc -= mpbase<T>::sub_1(scratch + l, scratch + l, l, static_cast<T>(c2));
    if (cc > 0) {
        cc = -mpbase<T>::sub_1(scratch, scratch, pl2, static_cast<T>(cc));
    }
    if (cc < 0) {
        cc = mpbase<T>::add_1(scratch, scratch, pl2, static_cast<T>(-cc));
    }

    // If odd, add 2^(pl2*B)+1 to the normalized scratch (0 <= cc <= 1)
    if (scratch[0] & 1) {
        cc += 1 + mpbase<T>::add_1(scratch, scratch, pl2, static_cast<T>(1));
    }
    mpbase<T>::rshift(scratch, scratch, pl2, 1);
    if (cc) {
        scratch [pl2 - 1] |= LIMB_HIGHBIT;
    }

    // {scratch,pl2}-cc = (lambda-mu)/(1-2^(l*B)) mod 2^(pl2*B) + 1
    c2 = mpbase<T>::add_n(out, out, scratch, pl2);

    // Since pl2+pl3 >= pl we can just copy the remaining limbs
    mpbase<T>::copy(out + pl3, scratch, pl - pl3);  // NOLINT

    // scratch is now longer needed so free the resource
    aligned_free(scratch);

    // Add the carry bits at pl2
    mpbase<T>::add_1(out + pl2, out + pl2, pl - pl2, static_cast<T>(c2));
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
