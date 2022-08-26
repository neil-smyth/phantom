/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <algorithm>
#include <cstdint>
#include <cmath>
#include <iomanip>
#include <limits>
#include <vector>

#include "core/mpbase.hpp"
#include "core/mp.hpp"
#include "core/template_helpers.hpp"


namespace phantom {
namespace core {

/// Reduction algorithm
enum reduction_e {
    REDUCTION_BARRETT = 0,
    REDUCTION_MONTGOMERY,
    REDUCTION_NAIVE,
    REDUCTION_CUSTOM,
};

template<typename T>
class mpz;

template<typename T>
class mod_custom;

/**
 * @brief Modulus parameters and configuration struct
 * 
 * @tparam T Data limb type
 */
template<typename T>
struct mod_config
{
    mpz<T> mod;
    mpz<T> mod_inv;
    size_t mod_bits;
    size_t k;
    size_t blog2;
    reduction_e reduction;
    mpz<T> mont_R2;
    T      mont_inv;

    mod_custom<T>* cst;
};

/**
 * @brief A pure virtual base class used toprovide an interface for custom reduction algorithms
 * 
 * @tparam T Data limb type
 */
template<typename T>
class mod_custom
{
public:
    virtual ~mod_custom() {}

    virtual mpz<T>& reduce(mpz<T>& a, const mod_config<T>& cfg) = 0;
};

template<typename T>
class mp_gf2n;

/** 
 * @brief Core mpz class
 * 
 * Common methods for use within the mpz class
 */
template<typename T>
class mpz_core
{
    static_assert(std::is_same<T, uint8_t>::value  ||
                  std::is_same<T, uint16_t>::value ||
                  std::is_same<T, uint32_t>::value ||
                  std::is_same<T, uint64_t>::value,
                  "number instantiated with unsupported type");

    using S = signed_type_t<T>;
    using D = next_size_t<T>;
    using H = half_size<T>;

    struct mpz_base_coding {
        size_t max_digits;
        size_t log2_base;
    };

public:
    /// Comparative methods
    /// @{

    /// Compare two MP integer arrays
    static int32_t cmp(const T* in1, bool in1_sign, size_t in1_len, const T* in2, bool in2_sign, size_t in2_len)
    {
        // Use the 'used' parameter to quickly compare multiple precision integers of
        // different lengths, otherwise if they are both positive numbers of equal length they are
        // simply compared. If both numbers are negative and equal length then they are compared as
        // asbsolute values with the result inverted to account for the sign change.
        int in1_used = static_cast<int>(in1_len) * (in1_sign? -1 : 1);
        int in2_used = static_cast<int>(in2_len) * (in2_sign? -1 : 1);
        if (in1_used < in2_used) {
            return -1;
        }
        else if (in1_used > in2_used) {
            return 1;
        }

        // Compare the two multiple precision signed limb arrays
        if (!in1_sign) {
            return mpbase<T>::cmp(in1, in2, in1_used);
        }
        else {
            return mpbase<T>::cmp(in2, in1, -in1_used);
        }
    }

    /// Compare to a double value (double is converted to integer and rounded towards zero)
    static int32_t cmp_d(const T* num, bool sign, size_t len, double in)
    {
        if (sign) {
            if (in >= 0.0) {
                // lhs is negative and rhs is zero or positive
                return -1;
            }
            else {
                // lhs and rhs are negative, so compare their absolute values and invert the sign
                // as the negative value indicates it must be less than
                return -cmpabs_d(num, len, in);
            }
        }
        else {
            if (in < 0.0) {
                // lhs is positive and rhs is negative
                return 1;
            }
            else {
                // Both values are greater than or equal to zero compare them directly
                return cmpabs_d(num, len, in);
            }
        }
    }

    /// Compare two mpz objects in terms of the absolute magnitude
    static int32_t cmpabs(const T* in1, size_t in1_len, const T* in2, size_t in2_len)
    {
        // Compare the two limb arrays which are stored in an absolute format
        return mpbase<T>::cmp_n(in1, in1_len, in2, in2_len);
    }

    /// Compare an mpz object and a double in terms of their absolute magnitudes
    static int32_t cmpabs_d(const T* in1, size_t in1_len, double in2)
    {
        // If the double is zero then the output is either 0 or 1 depending on the limb size
        if (0.0 == in2) {
            return in1_len > 0;
        }

        // If the double is non-zero and the mpz object is zero then the result is less than
        if (0 == in1_len) {
            return -1;
        }

        // Ensure that the input double is the absolute value
        in2 = fabs(in2);

        // lhs absolute size is >= 1, therefore if the rhs is < 1.0 it is smaller
        if (in2 < 1.0) {
            return 1;
        }

        // If lhs is non-zero then we scale the double using the reciprocal of the maximum value
        size_t used = in1_len;
        const double b     = 2.0 * static_cast<double>(T(1) << (std::numeric_limits<T>::digits - 1));
        const double b_inv = 1.0 / b;
        for (size_t i=1; i < used; i++) {
            in2 *= b_inv;
        }

        // If the scaled double is greater than or equal to the largest integer value then
        // the result is less than
        if (in2 >= b) {
            return -1;
        }

        // From the most significant limb compare to the floor(rhs) until a comparison decision
        // has been reached or we run out of MP limbs (i.e. the two values are equal)
        while (used--) {
            T floor_in = static_cast<T>(in2);
            T limb     = in1[used];
            if (limb > floor_in) {
                return 1;
            }
            else if (limb < floor_in) {
                return -1;
            }

            in2 = b * (in2 - floor_in);
        }

        // If the scaled rhs is non-zero then the result is less than
        return (in2 > 0.0)? -1 : 0;
    }

    // Calculate the integer size in bits of the mpz object given a specific base
    static size_t sizeinbase(const T* in, size_t used, size_t base)
    {
        // Terminte early with a 1-bit zero value
        if (0 == used) {
            return (64 == base)? 4 : (32 == base)? 8 : 1;
        }

        size_t bits  = (used - 1) * std::numeric_limits<T>::digits +
                       (std::numeric_limits<T>::digits - bit_manipulation::clz(in[used - 1]));

        switch (base)
        {
        case  2: return bits;                                          // break not needed
        case  4: return (bits + 1) >> 1;                               // break not needed
        case  8: return ((bits + 2) * (HLIMB_BIT/3)) >>
                        (std::numeric_limits<T>::digits / 2);          // break not needed (divide by 3)
        case 10: return ceil(static_cast<float>(bits) / 3.321928095);  // break not needed
        case 16: return (bits + 3) >> 2;                               // break not needed (divide by 4)
        case 32: return ((bits + 39) / 40) * 8;                        // break not needed (divide by 5)
        case 64: return ((bits + 23) / 24) * 4;                        // break not needed (divide by 5)
        }

        return 0;
    }


    /// Add the two mpz integers as absolute values
    static int32_t abs_add(T* out, const T* in1, size_t in1_used, const T* in2, size_t in2_used)
    {
        // 'in1' must be greater than 'in2' for the add() function, so swap if necessary
        if (in1_used < in2_used) {
            const T* temp = in1;
            in1 = in2;
            in2 = temp;
            in1_used ^= in2_used;
            in2_used ^= in1_used;
            in1_used ^= in2_used;
        }

        // Ensure that 'out' has sufficient limbs and calculate the result accounting for the carry
        // returned by add().
        if (mpbase<T>::add(out, in1, in1_used, in2, in2_used)) {
            out[in1_used++] = 1;
        }

        size_t nsize = mpbase<T>::normalized_size(out, in1_used);

        // Return the length of the result
        return nsize;
    }

    /// Add an mpz integer and an unsigned integer as absolute values
    static int32_t abs_add(T* out, const T* in1, size_t in1_used, T in2)
    {
        // If 'in1' is zero the value is set to 'in2' and a length of 1 is
        // returned if in2 is non-zero
        if (0 == in1_used) {
            out[0] = in2;
            return in2 > 0;
        }

        // The output is extended by one limb and an addition with carry is performed
        if (mpbase<T>::add_1(out, in1, in1_used, in2)) {
            out[in1_used++] = 1;
        }
        return in1_used;
    }

    /// Subtract the two mpz integers as absolute values
    static int32_t abs_sub(T* out, const T* in1, size_t in1_used, const T* in2, size_t in2_used)
    {
        // Determine relative absolute sizes of the inputs
        int32_t cmp = mpbase<T>::cmp_n(in1, in1_used, in2, in2_used);

        if (0 == cmp) {
            // If identical the result is zero and a length of 0 is returned
            return 0;
        }
        else if (cmp > 0) {
            // If 'in1' is larger than 'in2' resize the output and subtract 'in2' from 'in1'
            mpbase<T>::sub(out, in1, in1_used, in2, in2_used);
            return mpbase<T>::normalized_size(out, in1_used);
        }
        else {
            // If 'in2' is larger than 'in1' resize the output and subtract 'in1' from 'in2'
            mpbase<T>::sub(out, in2, in2_used, in1, in1_used);
            return -mpbase<T>::normalized_size(out, in2_used);
        }
    }

    /// Subtract an mpz integer and an unsigned integer as absolute values
    static int32_t abs_sub(T* out, const T* in1, size_t in1_used, T in2)
    {
        // If 'in1' is zero the output is set to 'in2' and the length is returned
        if (0 == in1_used) {
            out[0] = in2;
            return -(in2 > 0);
        }

        // If 'in1' is single precision and less than in2 we calculate in2 - in1,
        // otherwise we resort to using sub_1()
        if (1 == in1_used && in1[0] < in2) {
            out[0] = in2 - in1[0];
            return -1;
        }
        else {
            mpbase<T>::sub_1(out, in1, in1_used, in2);
            int32_t nsize = mpbase<T>::normalized_size(out, in1_used);
            return nsize;
        }
    }


    /// Multiply an mpz object by an mpz object
    static int mul(T* out, const T* in1, size_t in1_used, bool in1_sign, const T* in2, size_t in2_used, bool in2_sign)
    {
        if (in1 == in2) {
            return square(out, in1, in1_used);
        }

        // If either operand is zero the result is zero
        if (0 == in1_used || 0 == in2_used) {
            return 0;
        }

        // Preallocate an intermediate output with appropriate bit length for the product.
        // Ensure that the first operand is larger than the second for mul() to operate correctly.
        if (in1_used >= in2_used) {
            mpbase<T>::mul(out, in1, in1_used, in2, in2_used);
        }
        else {
            mpbase<T>::mul(out, in2, in2_used, in1, in1_used);
        }

        // Resize the quotient to the appropriate size and sign
        bool sign = in1_sign ^ in2_sign;
        int used = mpbase<T>::normalized_size(out, in1_used + in2_used);
        if (sign) {
            used = -used;
        }

        return used;
    }

    /// Calculate the square of an mpz object
    static int square(T* out, const T* in, size_t in_used)
    {
        // If the object is zero the result is zero
        if (0 == in_used) {
            return 0;
        }

        // Preallocate an intermediate output with appropriate bit length for the product.
        // Ensure that the first operand is larger than the second for mul() to operate correctly.
        mpbase<T>::sqr(out, in, in_used);

        // Reduce the output size if the MSW are zero
        in_used = mpbase<T>::normalized_size(out, 2 * in_used);

        return in_used;
    }

    // Montgomery multiplication
    static int32_t mul_mont(T* out, const T* in1, size_t in1_used, const T* in2, size_t in2_used,
        const T* m, size_t n, T m_inv)
    {
        if (0 == in1_used || 0 == in2_used) {
            return 0;
        }

        // Reset the output to 0
        std::fill(out, out + n + 1, 0);

        // Simultaneously multiply and reduce
        for (auto i=0; i < n; i++) {
            D in1_masked = (i >= in1_used)? 0 : in1[i];
            T h, ui;
            number<T>::umul(&h, &ui, static_cast<T>(in1_masked), in2[0]);
            number<T>::umul(&h, &ui, out[0] + ui, m_inv);

            ui    = (out[0] + in1_masked * in2[0]) * m_inv;
            D uid = ui;

            D z1 = static_cast<D>(in2[0]) * in1_masked + out[0];
            D z2 = static_cast<D>(m[0]) * uid + (z1 & LIMB_MASK);
            T k1 = z1 >> std::numeric_limits<T>::digits;
            T k2 = z2 >> std::numeric_limits<T>::digits;

            for (S j = 1; j < n; j++) {
                D in2_masked = (j >= in2_used)? 0 : in2[j];
                z1 = in2_masked * in1_masked + out[j] + k1;
                z2 = static_cast<D>(m[j]) * uid + (z1 & LIMB_MASK) + k2;
                k1 = z1 >> std::numeric_limits<T>::digits;
                k2 = z2 >> std::numeric_limits<T>::digits;
                out[j-1] = z2;
            }

            D tmp = static_cast<D>(out[n]) + k1 + k2;
            out[n-1] = tmp;
            out[n]   = tmp >> std::numeric_limits<T>::digits;
        }

        // Reduce the output if it is equal or larger than the modulus
        if (mpbase<T>::cmp_n(out, mpbase<T>::normalized_size(out, n+1), m, n) != -1) {
            mpbase<T>::sub(out, out, n+1, m, n);
        }

        // Reduce the output size if the MSW are zero
        int32_t used = mpbase<T>::normalized_size(out, n);

        return used;
    }

    // Montgomery squaring
    static int32_t square_mont(T* out, const T* in, size_t in_used, const T* m, size_t n, T m_inv)
    {
        if (0 == in_used) {
            return 0;
        }

        // Reset the output to 0
        std::fill(out, out + n + 1, 0);

        // Simultaneously multiply and reduce
        for (auto i=0; i < n; i++) {
            D in1_masked = (i >= in_used)? 0 : in[i];
            T h, ui;
            number<T>::umul(&h, &ui, static_cast<T>(in1_masked), in[0]);
            number<T>::umul(&h, &ui, out[0] + ui, m_inv);

            ui    = (out[0] + in1_masked * in[0]) * m_inv;
            D uid = ui;

            D z1 = static_cast<D>(in[0]) * in1_masked + out[0];
            D z2 = static_cast<D>(m[0]) * uid + (z1 & LIMB_MASK);
            T k1 = z1 >> std::numeric_limits<T>::digits;
            T k2 = z2 >> std::numeric_limits<T>::digits;

            for (S j = 1; j < n; j++) {
                D in2_masked = (j >= in_used)? 0 : in[j];
                z1 = in2_masked * in1_masked + out[j] + k1;
                z2 = static_cast<D>(m[j]) * uid + (z1 & LIMB_MASK) + k2;
                k1 = z1 >> std::numeric_limits<T>::digits;
                k2 = z2 >> std::numeric_limits<T>::digits;
                out[j-1] = z2;
            }

            D tmp = static_cast<D>(out[n]) + k1 + k2;
            out[n-1] = tmp;
            out[n]   = tmp >> std::numeric_limits<T>::digits;
        }

        // Reduce the output if it is equal or larger than the modulus
        if (mpbase<T>::cmp_n(out, mpbase<T>::normalized_size(out, n+1), m, n) != -1) {
            mpbase<T>::sub(out, out, n+1, m, n);
        }

        // Reduce the output size if the MSW are zero
        int32_t used = mpbase<T>::normalized_size(out, n);

        return used;
    }

    // Montgomery reduction
    static int32_t reduce_mont(T* out, const T* in, size_t in_used, const T* m, size_t n, T m_inv)
    {
        // Reset the output
        std::copy(in, in + in_used, out);
        std::fill(out + in_used, out + 2*n, 0);

        // Simultaneously multiply and reduce
        for (size_t i=0; i < n; i++) {
            T ui = out[i] * m_inv;
            out[n+i] += mpbase<T>::addmul_1(out + i, m, n, ui);
        }
        std::copy(out + n, out + 2*n, out);
        std::fill(out + n, out + 2*n, 0);

        // Reduce the output if it is equal or larger than the modulus
        if (mpbase<T>::cmp_n(out, mpbase<T>::normalized_size(out, n), m, n) != -1) {
            mpbase<T>::sub(out, out, n, m, n);
        }

        // Reduce the output size if the MSW are zero
        int32_t used = mpbase<T>::normalized_size(out, n);

        return used;
    }
};

// Forward declaration with common types
extern template class mpz_core<uint8_t>;
extern template class mpz_core<uint16_t>;
extern template class mpz_core<uint32_t>;
#if defined(IS_64BIT)
extern template class mpz_core<uint64_t>;
#endif

}  // namespace core
}  // namespace phantom
