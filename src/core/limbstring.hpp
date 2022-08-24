/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <cstdint>
#include <cmath>
#include <iomanip>
#include <limits>
#include <string>
#include <vector>

#include "core/bit_manipulation.hpp"
#include "core/template_helpers.hpp"
#include "./phantom_memory.hpp"


namespace phantom {
namespace core {

template<typename T>
class mpz;


/** 
 * @brief Template class for conversion of mpz objects to/from strings
 * 
 * String to mpz manipulation in binary, octal, decimal, hexadecimal,
 * base-32 and base-64
 */
template<typename T>
class limbstring
{
    static_assert(std::is_same<T, uint8_t>::value  ||
                  std::is_same<T, uint16_t>::value ||
                  std::is_same<T, uint32_t>::value ||
                  std::is_same<T, uint64_t>::value,
                  "number instantiated with unsupported type");

    using S = signed_type_t<T>;

    /// A LUT to convert ASCII characters from base32 to an integer
    static const uint8_t _base32_to_u8[256];

    /// A LUT to convert ASCII characters from base64 to an integer
    static const uint8_t _base64_to_u8[256];

    /// A LUT to convert ASCII characters for base 2/8/16 to an integer
    static const uint8_t _ascii_to_u8[256];

    /// The base32 alphabet
    static const char* _ascii_base32;

    /// The base64 alphabet
    static const char* _ascii_base64;

private:

    struct mpz_base_coding {
        size_t max_digits;
        size_t log2_base;
    };

    /// Digits per word and the log2 of the base are stored in a machine-word size specific LUT
    /// @{
    static const size_t coding_levels = 5;
    static const mpz_base_coding base_coding_64[5];
    static const mpz_base_coding base_coding_32[5];
    static const mpz_base_coding base_coding_16[5];
    static const mpz_base_coding base_coding_8[5];
    /// @}

    /**
     * String conversion from base2/8/16 to a vector of T limbs
     * @param limbs Output vector of T objects
     * @param base_coding A pointer to the mpz_base_coding object describing the string
     * @param str The string be be decoded
     * @param base The base number system of the input string
     * @param base_code Internal code describing the base (0:2-bit, 1:8-bit, 2:16-bit)
     */
    static void init_power_2_string(phantom_vector<T> &limbs,
                                    const typename limbstring<T>::mpz_base_coding *base_coding,
                                    const char *str, size_t base, size_t base_code);

    /**
     * String conversion from base32 or base64 to a vector of T limbs
     * @param limbs Output vector of T objects
     * @param base_coding A pointer to the mpz_base_coding object describing the string
     * @param str The string be be decoded
     * @param base_lut A LUT describing conversion from 8-bit ASCII to an integer
     * @param base The base number system of the input string
     */
    static void init_basex_string(phantom_vector<T> &limbs, const typename limbstring<T>::mpz_base_coding *base_coding,
                                  const char *str, const uint8_t *base_lut, size_t base);

    /**
     * String conversion from decimal to a vector of T limbs
     * @param limbs Output vector of T objects
     * @param str The string be be decoded
     */
    static void init_decimal_string(phantom_vector<T> &limbs, const char *str);

    /**
     * Conversion of T limb arrays to byte vectors for base-32
     * @param block Output vector of byte vales
     * @param limbs Input vector of T objects
     * @param limb_bits Size of the limb array in bits
     */
    static void base32_gen_blocks(std::vector<uint8_t> &block, const T *limbs, size_t limb_bits);

    /**
     * Conversion of T limb arrays to byte vectors for base-64
     * @param block Output vector of byte vales
     * @param limbs Input vector of T objects
     * @param limb_bits Size of the limb array in bits
     */
    static void base64_gen_blocks(std::vector<uint8_t> &block, const T *limbs, size_t limb_bits);

public:
    /**
     * Convert an mpz object to a std::string with a user-defined base
     * @param number The mpz object to be converted
     * @param base The base number system of the output string
     * @param uppercase Optionally convert the string to use uppercase characters (default: false)
     * @return Output string
     */
    static std::string get_str(const mpz<T> &number, size_t base, bool uppercase = false);

    /**
     * Convert a string to a vector of T limbs
     * @param limbs Output vector of T limbs
     * @param sign The sign of the out vector of T limbs
     * @param str The string to be converted
     * @param base Base number of the input string
     */
    static void set_str(phantom_vector<T> &limbs, bool &sign, const char *str, size_t base);
};


template<>
const limbstring<uint64_t>::mpz_base_coding limbstring<uint64_t>::base_coding_64[5];

template <>
const limbstring<uint32_t>::mpz_base_coding limbstring<uint32_t>::base_coding_32[5];

template<>
const limbstring<uint16_t>::mpz_base_coding limbstring<uint16_t>::base_coding_16[5];

template <>
const limbstring<uint8_t>::mpz_base_coding limbstring<uint8_t>::base_coding_8[5];

// Forward declaration of common sizes
extern template class limbstring<uint8_t>;
extern template class limbstring<uint16_t>;
extern template class limbstring<uint32_t>;
#if defined(IS_64BIT)
extern template class limbstring<uint64_t>;
#endif

}  // namespace core
}  // namespace phantom
