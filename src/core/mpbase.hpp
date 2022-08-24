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
#include <cstdint>
#include <cmath>
#include <vector>

#include "core/bit_manipulation.hpp"
#include "core/number.hpp"
#include "core/mod_metadata.hpp"
#include "core/mpbase_defines.hpp"
#include "./phantom.hpp"



namespace phantom {
namespace core {

/** 
 * @brief Multiple Precision number class for low-level arithmetic
 * 
 * Performance critical multiple-precision arithmetic
 */
template<typename T>
class mpbase
{
    /// Check for valid types
    static_assert(std::is_same<T, uint8_t>::value  ||
                  std::is_same<T, uint16_t>::value ||
                  std::is_same<T, uint32_t>::value ||
                  std::is_same<T, uint64_t>::value,
                  "number instantiated with unsupported type");

    /// Signed version of the user-defined template type
    using S = signed_type_t<T>;

    /*using pow_redc_mul = void (*)(T*, T*, T*, size_t);
    using pow_redc_sqr = void (*)(T*, T*, size_t);
    using pow_redc_reduce = void (*)(T*, T*, const T*, size_t, const T*);*/
    #define REDUCE(r_limbs, tp, mp, n, mip)  redc_reduce(r_limbs, tp, mp, mip[0])


    /// Instances can NOT be created
    mpbase() {}

public:
    /**
     * Reset the data array to all zeros
     * @param inout Data array to be zeroed
     * @param n Length of the data arrays
     */
    static void zero(T *inout, size_t n);

    /**
     * One's complement of the data array
     * @param out Output data array (can be same as in)
     * @param in Input data array
     * @param n Length of the data arrays
     */
    static void ones_complement(T* out, const T *in, size_t n);

    /**
     * Negation of a data array
     * @param out Output data array (can be same as in)
     * @param in Input data array
     * @param n Length of the data arrays
     * @return 0 if in is zero, 1 otherwise
     */
    static T negate(T* out, const T *in, size_t n);

    /**
     * Copy a data array (assume in and out are different)
     * @param out Output data array (can be same as in)
     * @param in Input data array
     * @param n Length of the data arrays
     */
    static void copy(T *out, const T *in, size_t n);  // NOLINT

    /**
     * @brief Fill memory of specified type with the defined value
     * @param dst Destination address
     * @param n Number of words to fill
     * @param value The fill value
     */
    static void fill(T* dst, size_t n, T value);

    /**
     * Return the active size of the data array
     * @param in Input data array
     * @param n Length of the data array
     * @return Normalized length
     */
    static size_t normalized_size(const T *in, size_t n);

    /**
     * Left shift a data array by a number of bits, return the overflow
     * @param out Output data array
     * @param in Input data array
     * @param n Length of the data array
     * @return Overflow carry bits
     */
    static T lshift(T *out, const T *in, size_t n, size_t count);

    /**
     * Left shift a data array by a number of bits and return the complement, return the overflow
     * @param out Output data array
     * @param in Input data array
     * @param n Length of the data array
     * @return Overflow carry bits
     */
    static T lshiftc(T *out, const T *in, size_t n, size_t count);

    /**
     * Right shift a data array by a number of bits, return the underflow
     * @param out Output data array
     * @param in Input data array
     * @param n Length of the data array
     * @return Underflow carry bits
     */
    static T rshift(T *out, const T *in, size_t n, size_t count);

    /**
     * Right shift a data array to remove any trailing zeros
     * @param inout Data to be modified
     * @param n length of the data array
     * @return The number of bits the array is right shifted
     */
    static size_t make_odd(T* inout, size_t n);

    /**
     * Count trailing zeros in an array
     * @param in Data array
     * @param n Length of the data array
     * @return Number of trailing zeros
     */
    static size_t ctz(const T* in, size_t n);

    /**
     * Extract the bits at a specific position within a window
     * @param in Input data array
     * @param bi Starting bit index
     * @param nbits Window size of the array in bits
     * @return Extracted bits
     */
    static T getbits(const T *in, uint32_t bi, uint32_t nbits);

    /**
     * Determine if array is all zero's
     * @param in Input data array
     * @param n Length of the data array
     * @return true if in is zero, false otherwise
     */
    static bool is_zero(const T *in, size_t n);

    /**
     * Compare two arrays of the same length (length must be normalized)
     * @param in1 Input data array 1
     * @param in2 Input data array 2
     * @param n Length of the data arrays
     * @return 1 if in1 is larger, 0 if equal and -1 is smaller
     */
    static int32_t cmp(const T *in1, const T *in2, size_t n);

    /**
     * Compare two arrays of different length (length must be normalized)
     * @param in1 Input data array 1
     * @param n1 Length of the data array 1
     * @param in2 Input data array 2
     * @param n2 Length of the data array 2
     * @return 1 if in1 is larger, 0 if equal and -1 if smaller
     */
    static int32_t cmp_n(const T *in1, size_t n1, const T *in2, size_t n2);

    /**
     * Add a single word to an array, return the carry bit
     * @param out Output data array
     * @param in1 Input data array
     * @param n Length of the data array in1
     * @param in2 Input data word
     * @return Carry bit
     */
    static T add_1(T *out, const T *in1, size_t n, T in2);

    /**
     * Add two arrays of identical length, return the carry bit
     * @param out Output data array
     * @param in1 1st input data array
     * @param in2 2nd input data array
     * @param n Length of the data arrays
     * @return Carry bit
     */
    static T add_n(T *out, const T *in1, const T *in2, size_t n);

    /**
     * Add two arrays of identical length and a carry word, return the carry bits
     * @param out Output data array
     * @param in1 1st input data array
     * @param in2 2nd input data array
     * @param n Length of the data arrays
     * @param cin An input carry word
     * @return Carry bits
     */
    static T add_nc(T *out, const T *in1, const T *in2, size_t n, T cin);

    /**
     * Add two arrays of different length, return the carry bit
     * @param out Output data array
     * @param in1 1st input data array
     * @param n1 Length of the data array in1
     * @param in2 2nd input data array
     * @param n2 Length of the data array in2
     * @param cin An input carry word
     * @return Carry bit
     */
    static T add(T *out, const T *in1, size_t n1, const T *in2, size_t n2);

    /**
     * Subtract a single word from an array, return the carry bit
     * @param out Output data array
     * @param in1 Input data array
     * @param n Length of the data array
     * @param in2 Input data word
     * @return Carry bit
     */
    static T sub_1(T *out, const T *in1, size_t n, T in2);

    /**
     * Subtract two arrays of identical length, return the carry bit
     * @param out Output data array
     * @param in1 1st input data array
     * @param in2 2nd input data array
     * @param n Length of the data arrays
     * @return Carry bit
     */
    static T sub_n(T *out, const T *in1, const T *in2, size_t n);

    /**
     * Subtract two arrays of identical length and a carry word, return the carry bits
     * @param out Output data array
     * @param in1 1st input data array
     * @param in2 2nd input data array
     * @param n Length of the data arrays
     * @param cin An input carry word
     * @return Carry bits
     */
    static T sub_nc(T *out, const T *in1, const T *in2, size_t n, T cin);

    /**
     * Subtract two arrays of different length, return the carry bit
     * @param out Output data array
     * @param in1 1st input data array
     * @param n1 Length of the data array in1
     * @param in2 2nd input data array
     * @param n2 Length of the data array in2
     * @param cin An input carry word
     * @return Carry bit
     */
    static T sub(T *out, const T *in1, size_t n1, const T *in2, size_t n2);

    /**
     * Add arrays x and y, subtract array z, return the carry
     * @param out Output data array
     * @param x 1st input data array
     * @param y 2nd input data array to be added
     * @param z 3rd input data array to be subtracted
     * @param n Length of the data arrays
     * @return Carry
     */
    static int addsub_n(T *out, const T *x, const T *y, const T *z, size_t n);

    /**
     * Absolute difference between two arrays
     * @param out Output data array
     * @param in1 1st input data array
     * @param in2 2nd input data array
     * @param n Length of the data arrays
     * @return Returns 0 if in1 is greater than or equal to in2, 1 otherwise 
     */
    static int abs_sub_n(T *out, const T *in1, const T *in2, size_t n);

    /**
     * Multiply an array by a single word and add to inout
     * @param inout Output data array
     * @param in1 Input data array
     * @param n Length of the data array
     * @param in2 Input data word
     * @return Carry word
     */
    static T addmul_1(T *inout, const T *in1, size_t n, T in2);

    /**
     * Multiply an array by a 2-word array and add to inout
     * @param inout Output data array
     * @param in1 Input data array
     * @param n Length of the data array
     * @param in2 Input 2-word data array
     * @return Carry word
     */
    static T addmul_2(T * inout, const T *in1, size_t n, const T *in2);

    /**
     * Multiply an array by a 2-word array and subtract from inout
     * @param inout Output data array
     * @param in1 Input data array
     * @param n Length of the data array
     * @param in2 Input 2-word data array
     * @return Carry word
     */
    static T submul_1(T * inout, const T *in1, size_t n, T in2);

    /**
     * Square an array (based on gradeschool algorithm)
     * @param out Output data array
     * @param in Input data array
     * @param n Length of the data array
     */
    static void sqr_gradeschool(T * out, const T *in, size_t n);

    /**
     * @brief Toom-2 squaring (k = 2)
     * 
     * @param out Product
     * @param in1 Multiplicand 1
     * @param n1 Length of multiplicand 1
     * @param scratch Intermediate storage
     */
    static void sqr_toom2(T *out, const T *in1, size_t n1, T *scratch);

    /**
     * @brief Toom-3 squaring (k = 3)
     * 
     * @param out Product
     * @param in1 Multiplicand 1
     * @param n1 Length of multiplicand 1
     * @param scratch Intermediate storage
     */
    static void sqr_toom3(T *out, const T *in1, size_t n1, T *scratch);

    /**
     * Square an array
     * @param out Output data array
     * @param in Input data array
     * @param n Length of the data array
     */
    static void sqr(T * out, const T *in, size_t n);

    /**
     * Multiply an array by a single word
     * @param out Output data array
     * @param in1 Input data array
     * @param n Length of the data array
     * @param in2 Input data word
     * @return Carry word
     */
    static T mul_1(T * out, const T *in1, size_t n, T in2);

    /**
     * Gradeschool multiplication of 2 arrays of different length
     * @param out Output data array
     * @param in1 Input data array 1
     * @param n1 Length of input data array 1
     * @param in2 Input data array 2
     * @param n2 Length of input data array 2
     * @return Carry word
     */
    static T mul_gradeschool(T * out, const T *in1, size_t n1, const T *in2, size_t n2);

    /**
     * @brief Get the toom22 scratch length given the product length
     * 
     * @param n Product length
     * @return const size_t Memory required (in limbs)
     */
    static const size_t get_toom22_scratch_size(size_t n);

    /**
     * @brief Get the toom33 scratch length given the product length
     * 
     * @param n Product length
     * @return const size_t Memory required (in limbs)
     */
    static const size_t get_toom33_scratch_size(size_t n);

    /**
     * @brief Toom-2 multiplication (km = 2, kn = 2)
     * 
     * @param out Product
     * @param in1 Multiplicand 1
     * @param n1 Length of multiplicand 1
     * @param in2 Multiplicand 2
     * @param n2 Length of multiplicand 2
     * @param scratch Intermediate storage
     */
    static void mul_toom22(T *out, const T *in1, size_t n1, const T *in2, size_t n2, T *scratch);

    /**
     * @brief Toom-2.5 multiplication (km = 3, kn = 2)
     * 
     * @param out Product
     * @param in1 Multiplicand 1
     * @param n1 Length of multiplicand 1
     * @param in2 Multiplicand 2
     * @param n2 Length of multiplicand 2
     * @param scratch Intermediate storage
     */
    static void mul_toom32(T *out, const T *in1, size_t n1, const T *in2, size_t n2, T *scratch);

    /**
     * @brief Toom-3 multiplication (km = 3, kn = 3)
     * 
     * @param out Product
     * @param in1 Multiplicand 1
     * @param n1 Length of multiplicand 1
     * @param in2 Multiplicand 2
     * @param n2 Length of multiplicand 2
     * @param scratch Intermediate storage
     */
    static void mul_toom33(T *out, const T *in1, size_t n1, const T *in2, size_t n2, T *scratch);

    /**
     * Multiply two arrays (n1 must be greater than or equal to n2)
     * @param out Output data array
     * @param in1 Input data array 1
     * @param n1 Length of input data array 1
     * @param in2 Input data array 2
     * @param n2 Length of input data array 2
     * @return Carry word
     */
    static T mul(T * out, const T *in1, size_t n1, const T *in2, size_t n2);

    /**
     * Multiply two arrays - optimised for same length
     * @param out Output data array
     * @param in1 Input data array 1
     * @param in2 Input data array 2
     * @param n Length of input data arrays
     */
    static void mul_n(T * out, const T *in1, const T *in2, size_t n);

    /**
     * Multiply two arrays - return lower n words
     * @param out Output data array
     * @param in1 Input data array 1
     * @param in2 Input data array 2
     * @param n Length of input data arrays
     */
    static void mul_low_n(T * out, const T *in1, const T *in2, size_t n);

    /**
     * Square an array - return lower n words
     * @param out Output data array
     * @param in Input data array
     * @param n Length of input data arrays
     */
    static void sqr_low_n(T * out, const T *in, size_t n);

    /**
     * Modular power of a number, r = b ^ e mod m. m must be odd, e > 1 and t must
     * be MAX(binvert_powm_scratch_size(n),2n) words.
     * @param r_limbs Result array
     * @param b_limbs Base array
     * @param bn Base array length
     * @param ep Exponent array
     * @param en Exponent array length
     * @param mp Modulus array
     * @param n Modulus array length
     * @param tp Temporary scratch memory for intermediate parameters
     */
    static void powm(T *r_limbs, const T *b_limbs, size_t bn, const T *ep, size_t en, const T *mp, size_t n, T *tp);

    /**
     * Calculate the power of a number (maintain only the least significant n limbs)
     * @param out Output data array
     * @param base The base number
     * @param exp The exponent
     * @param exp_n Length of the exponent
     * @param n Length of input and output data array
     * @param tmp Temporary memory for intermediate storage of n limbs
     */
    static void pow_low(T* out, const T* base, const T* exp, size_t exp_n, size_t n, T* tmp);

    /**
     * @brief Division for a single-precision denominator (NOTE: The numerator is destroyed and the remainder is returned)
     * @param q_limbs Output quotient
     * @param n_limbs Numerator
     * @param n Length of numerator in limb words
     * @param mod Modulus struct containing the pre-inverted single-precision denominator
     * @return 
     */
    static T div_qr_1_preinv(T *q_limbs, const T *n_limbs,
        size_t n, const mod_metadata<T>& mod);

    /**
     * Division with a quotient and remainder using a 2-limb pre-inverted fixed-point reciprocal of the denominator
     * @param q_limbs Quotient
     * @param r_limbs Remainder
     * @param n_limbs Numerator (NOTE: The numerator is destroyed)
     * @param n Length of the numerator
     * @param mod Struct with a double-precision denominator that is pre-inverted to form a
     * limb-sized fixed-point reciprocal
     */
    static void div_qr_2_preinv(T *q_limbs, T *r_limbs,
        const T *n_limbs, size_t n, const mod_metadata<T>& mod);

    /**
     * Division with a quotient and remainder using a single limb denominator
     * @param q_limbs Quotient
     * @param r_limbs Remainder
     * @param n_limbs Numerator (NOTE: The numerator is destroyed)
     * @param n Length of the numerator
     * @param mod Struct with a double-precision denominator that is pre-inverted to form a
     * limb-sized fixed-point reciprocal
     */
    static T div_qr_1(T *q_limbs, const T *n_limbs, size_t n, T d);

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
    static void div_qr_general_preinv(T *q_limbs, T *n_limbs,
        size_t n, const T *d_limbs, size_t dn, const mod_metadata<T>& mod);

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
    static void div_qr_preinv(T *q_limbs, T *n_limbs,
        size_t n, const T *d_limbs, size_t dn, const mod_metadata<T>& mod);

    /**
     * @brief Division with a quotient and remainder (NOTE: The numerator will be overwritten)
     * @param q_limbs Quotient
     * @param n_limbs Numerator
     * @param n Length of the numerator
     * @param d_limbs Denominator
     * @param dn Length of the denominator
     */
    static void div_qr(T *q_limbs, T *n_limbs, size_t n, const T *d_limbs, size_t dn);

    /**
     * @brief Division with the numerator overwritten by the remainder and a 2 limb denominator
     * @param q_limbs Quotient
     * @param q_offset Length of the numerator
     * @param n_limbs Numerator
     * @param n Length of the numerator
     * @param d_limbs Denominator
     * @return 1 if numerator normalised to be smaller than denominator, 0 otherwise
     */
    static T divrem_2(T* q_limbs, size_t q_offset, T* n_limbs, size_t n, const T* d_limbs);

    /**
     * @brief Division wrapping the div_qr() method to conveniently obtain the remainder
     * @param q_limbs Quotient
     * @param r_limbs Remainder
     * @param n_limbs Numerator
     * @param nn Length of the numerator
     * @param d_limbs Denominator
     * @param dn Length of the denominator
     */
    static void div_quorem(T *q_limbs, T *r_limbs, const T *n_limbs, size_t nn, const T *d_limbs, size_t dn);

    /**
     * Compute the inverse size of a denominator for a selected quotient length
     * @param qn Quotient length
     * @param dn Denominator length
     * @return Length of the inverse
     */
    static size_t mu_div_qr_inverse_size(size_t qn, size_t dn);

    /**
     * Compute the scratch size required for mu_div_qr()
     * @param nn Numerator length
     * @param dn Denominator length
     * @return Scratch memory length
     */
    static size_t mu_div_qr_scratch_size(size_t nn, size_t dn);

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
    static T mu_div_qr(T* q_limbs, T* r_limbs, const T* n_limbs, size_t nn,
        const T* d_limbs, size_t dn, T* scratch);

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
    static T mu_div_qr_internal(T* q_limbs, T* r_limbs, const T* n_limbs, size_t nn,
        const T* d_limbs, size_t dn, T* scratch);

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
    static T divappr_qr_1(T* q_limbs, T* n_limbs, size_t nn, const T* d_limbs, size_t dn, T dinv);

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
    static T divappr_qr_2_n(T* q_limbs, T* n_limbs, const T* d_limbs, size_t n, T dinv, T* scratch);

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
    static T divappr_qr_2(T* q_limbs, T* n_limbs, size_t nn, const T* d_limbs, size_t dn, T dinv);

    /**
     * @brief Basecase for inversion approximation
     * @param i_limbs Inverted denominator
     * @param d_limbs Denominator
     * @param n Length of the denominator
     * @param scratch Intermediate memoey of length 3 * n + 2
     * @return 1 if numerator is greater than or equal to the denominator
     */
    static T basecase_invertappr(T* i_limbs, const T* d_limbs, size_t n, T* scratch);

    /**
     * @brief Newton iteration for inversion approximation
     * @param i_limbs Inverted denominator
     * @param d_limbs Denominator
     * @param n Length of the denominator
     * @param scratch Intermediate memoey of length 3 * n + 2
     * @return 1 if numerator is greater than or equal to the denominator
     */
    static T newton_invertappr(T* i_limbs, const T* d_limbs, size_t n, T* scratch);

    /**
     * @brief Newton iteration for inversion approximation
     * @param i_limbs Inverted denominator
     * @param d_limbs Denominator
     * @param n Length of the denominator
     * @param scratch Intermediate memoey of length 3 * n + 2
     * @return 1 if numerator is greater than or equal to the denominator
     */
    static T invertappr(T* i_limbs, const T* d_limbs, size_t n, T* scratch);

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
    static T preinv_mu_div_qr(T* q_limbs, T* r_limbs, const T* n_limbs, size_t nn,
        const T* d_limbs, size_t dn, const T* i_limbs, size_t in, T* scratch);

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
    static T basecase_div_qr(T* q_limbs, T* n_limbs, size_t nn, const T* d_limbs, size_t dn, T dinv);

    /**
     * @brief Hensel binary division, q = -n * d^{-1} mod B^nn, destroys numerator
     * @param q_limbs Quotient
     * @param n_limbs Numerator (overwritten with remainder))
     * @param nn Length of the numerator
     * @param d_limbs Denominator (must be odd)
     * @param dn Length of the denominator
     * @param dinv (-d)^-1 mod B
     */
    static void basecase_bdiv_q(T* q_limbs, T* n_limbs, size_t nn, const T* d_limbs, size_t dn, T dinv);

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
    static T basecase_bdiv_qr(T* q_limbs, T* n_limbs, size_t nn, const T* d_limbs, size_t dn, T dinv);

    /**
     * @brief Hensel binary division with equal length, q = -n * d^{-1} mod B^nn, destroys numerator
     * @param q_limbs Quotient, qn = un - dn
     * @param n_limbs Numerator
     * @param d_limbs Denominator (must be odd)
     * @param n Length of the numerator and denominator
     * @param dinv (-d)^-1 mod B
     * @param scratch Intermediate storage of floor(n/2) words
     */
    static void general_bdiv_q_n(T* q_limbs, T* n_limbs, const T* d_limbs, size_t n, T dinv, T* scratch);

    /**
     * @brief Hensel binary division, q = -n * d^{-1} mod B^nn, destroys numerator
     * @param q_limbs Quotient, qn = un - dn
     * @param n_limbs Numerator
     * @param nn Length of the numerator and denominator
     * @param d_limbs Denominator (must be odd)
     * @param dn Length of the numerator and denominator
     * @param dinv (-d)^-1 mod B
     */
    static void general_bdiv_q(T* q_limbs, T* n_limbs, size_t nn, const T* d_limbs, size_t dn, T dinv);

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
    static T general_div_qr_n(T* q_limbs, T* n_limbs, const T* d_limbs, size_t n, T dinv, T* scratch);

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
    static T general_div_qr(T* q_limbs, T* n_limbs, size_t nn, const T* d_limbs, size_t dn, T dinv);

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
    static T general_bdiv_qr_n(T* q_limbs, T* n_limbs, const T* d_limbs, size_t n, T dinv, T* scratch);

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
    static T general_bdiv_qr(T* q_limbs, T* n_limbs, size_t nn, const T* d_limbs, size_t dn, T dinv);

    /**
     * @brief Division with truncation
     * @param q_limbs Quotient
     * @param n_limbs Remainder
     * @param n_limbs Numerator
     * @param nn Length of the numerator
     * @param d_limbs Denominator (must be odd)
     * @param dn Length of the denominator
     */
    static void tdiv_qr(T* q_limbs, T* r_limbs, const T* n_limbs, size_t nn, const T* d_limbs, size_t dn);

    /**
     * @brief Determine if a is divisible by a denominator d without remainder
     * @param a_limbs Quotient
     * @param an Length of the numerator
     * @param d_limbs Denominator (must be odd)
     * @param dn Length of the denominator
     * @return 1 if remainder is non-zero, 0 otherwise
     */
    static int divisible_p(const T *a_limbs, size_t an, const T *d_limbs, size_t dn);

    /**
     * @brief Limb inversion
     * @param n Value to invert (must be odd)
     * @return Inverted value, i.e. n * inv = 1 (mod B)
     */
    static T binvert_limb(T n);

    /**
     * @brief Memory required for mulmod calculation
     * @param rn Modulus length
     * @param an A length
     * @param bn B length
     * @return Memory requirement
     */
    static size_t mulmod_bnm1_size(size_t rn, size_t an, size_t bn);

    /**
     * @brief Memory required for mulmod next iteration
     * @param nLength of array
     * @return Memory requirement
     */
    static size_t mulmod_bnm1_next_size(size_t n);

    /**
     * @brief Memory required for powm() intermediate storage
     * @param n Length of array
     * @return Memory requirement
     */
    static size_t binvert_powm_scratch_size(size_t n);

    /**
     * @brief Multiplicative inverse
     * @param r_limbs Output
     * @param u_limbs Input
     * @param n Length of array
     * @param scratch Intermediate storage
     * @return Memory requirement
     */
    static void binvert(T* r_limbs, const T* u_limbs, size_t n, T* scratch);

    /**
     * @brief Modular reduction satisfying r*B^k + a - c == q*d, If c<d then r will be in
     * the range 0<=r<d, or if c>=d then 0<=r<=d
     * @param in Input
     * @param n Length of input data array
     * @param d Single word denominator (must be odd)
     * @return Result
     */
    static T modexact_1_odd(const T* in, size_t n, T d);

    /**
     * Modular reduction to a single limb word
     * @param n_limbs Numerator
     * @param n Length of the numerator
     * @param d_limb The single-limb denominator
     * @return Modulus
     */
    static T mod_1(const T * n_limbs, size_t n, T d_limb);

    /**
     * Base case for multiplication and modular reduction mod 2^n
     * @param r_limbs Residual
     * @param a_limbs A
     * @param b_limbs B
     * @param n Residual length in words
     * @param scratch Intermediate storage
     */
    static void basecase_mulmod_bnm1(T* r_limbs, const T* a_limbs, const T* b_limbs, size_t n, T* scratch);

    /**
     * Base case for multiplication and modular reduction mod 2^(rn+1)
     * @param r_limbs Residual
     * @param a_limbs A
     * @param b_limbs B
     * @param n Residual length in words
     * @param scratch Intermediate storage
     */
    static void bc_mulmod_bnp1(T* r_limbs, const T* a_limbs, const T* b_limbs, size_t n, T* scratch);

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
    static void mulmod_bnm1(T* r_limbs, size_t rn, const T* a_limbs, size_t an,
        const T* b_limbs, size_t bn, T* scratch);

    /**
     * Convert U to REDC form, U_r = B^n * U mod M
     * @param r_limbs Residual
     * @param u_limbs U
     * @param un U length
     * @param m_limbs M
     * @param n Modulus length
     */
    static void redcify(T* r_limbs, const T* u_limbs, size_t un, const T* m_limbs, size_t n);

    /**
     * Montgomery reduction (REDC) with a single-word inverse
     * @param r_limbs Residual
     * @param u_limbs U
     * @param m_limbs M
     * @param n M
     * @param invm Inverse of modulus
     */
    static T redc_1(T* r_limbs, T* u_limbs, const T* m_limbs, size_t n, T invm);

    /**
     * Montgomery reduction (REDC) with a single-word inverse with carry fix
     * @param r_limbs Residual
     * @param u_limbs U
     * @param m_limbs M
     * @param n M
     * @param invm Inverse of modulus
     */
    static void redc_1_fix(T* r_limbs, T* u_limbs, const T* m_limbs, size_t n, T invm);

    /**
     * Montgomery reduction (REDC) with a double-word inverse
     * @param r_limbs Residual
     * @param u_limbs U
     * @param m_limbs M
     * @param n M
     * @param i_limbs Inverse of modulus
     */
    static T redc_2(T* r_limbs, T* u_limbs, const T* m_limbs, size_t n, const T* i_limbs);

    /**
     * Montgomery reduction (REDC) with an n-word inverse
     * @param r_limbs Residual
     * @param u_limbs U
     * @param m_limbs M
     * @param n M
     * @param i_limbs Inverse of modulus
     */
    static void redc_n(T* r_limbs, T* u_limbs, const T* m_limbs, size_t n, const T* i_limbs);

    /**
     * Jacobi initialization
     * @param a Least significant word of A
     * @param b Least significant word of B
     * @param s Sign
     * @return Bits
     */
    static unsigned int jacobi_init(T a, T b, unsigned s);

    /**
     * Jacobi Symbol base case
     * @param a Least significant word of A
     * @param b Least significant word of B
     * @param bit 
     * @return Jacobi symbol of 1, 0 or -1
     */
    static int basecase_jacobi(T a, T b, int bit);

    /**
     * Jacobi symbol, special case for n=2
     * @param a_limbs Pointer to A limb array
     * @param b_limbs Pointer to B limb array
     * @param bit Reduced bit
     * @return int 0, 1 or -1
     */
    static int jacobi_2(const T* a_limbs, const T* b_limbs, unsigned bit);

    /**
     * Jacobi symbol for arrays of length n
     * @param a_limbs Pointer to A limb array
     * @param b_limbs Pointer to B limb array
     * @param n Length of input arrays
     * @param bits Reduced bits
     * @return int 0, 1 or -1
     */
    static int jacobi_n(T *a_limbs, T *b_limbs, size_t n, unsigned bits);

    /**
     * @brief Add a single-word value to an array
     * @param p Array pointer
     * @param incr Word to add
     */
    static void incr_u(const T* p, T incr);

    /**
     * @brief Subtract a single-word value from an array
     * @param p Array pointer
     * @param decr Word to subtract
     */
    static void decr_u(const T* p, T decr);
};


// Forward declaration of common sizes
extern template class mpbase<uint8_t>;
extern template class mpbase<uint16_t>;
extern template class mpbase<uint32_t>;
extern template class mpbase<uint64_t>;

}  // namespace core
}  // namespace phantom
