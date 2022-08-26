/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "core/limbstring.hpp"
#include "./phantom_memory.hpp"
#include "core/mpz.hpp"


#define MAX_LIMBSTRING_LEN   10000


namespace phantom {
namespace core {

template<>
const limbstring<uint64_t>::mpz_base_coding limbstring<uint64_t>::base_coding_64[5] =
    { {64, 1}, {21, 3}, {16, 4}, {12, 5}, {10, 6} };

template<>
const limbstring<uint32_t>::mpz_base_coding limbstring<uint32_t>::base_coding_32[5] =
    { {32, 1}, {10, 3}, { 8, 4}, { 6, 5}, { 5, 6} };

template<>
const limbstring<uint16_t>::mpz_base_coding limbstring<uint16_t>::base_coding_16[5] =
    { {16, 1}, { 5, 3}, { 4, 4}, { 3, 5}, { 2, 6} };

template<>
const limbstring<uint8_t>::mpz_base_coding limbstring<uint8_t>::base_coding_8[5] =
    { {8, 1}, { 2, 3}, { 2, 4}, { 2, 5}, { 1, 6} };


/// A LUT to convert ASCII characters from base32 to an integer
template<typename T>
const uint8_t limbstring<T>::_base32_to_u8[256] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x34, 0xFF, 0xFF, 0xFF, 0x35,
    0xFF, 0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

/// A LUT to convert ASCII characters from base64 to an integer
template<typename T>
const uint8_t limbstring<T>::_base64_to_u8[256] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF, 0xFF, 0x3F,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x1F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

/// A LUT to convert ASCII characters for base 2/8/16 to an integer
template<typename T>
const uint8_t limbstring<T>::_ascii_to_u8[256] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x10, 0x11, 0x12, 0x13, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x10, 0x11, 0x12, 0x13, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

/// The base32 alphabet
template<typename T>
const char* limbstring<T>::_ascii_base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The base64 alphabet
template<typename T>
const char* limbstring<T>::_ascii_base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * String conversion from base2/8/16 to a vector of T limbs
 * @param limbs Output vector of T objects
 * @param base_coding A pointer to the mpz_base_coding object describing the string
 * @param str The string be be decoded (null-terminated)
 * @param base The base number system of the input string
 * @param base_code Internal code describing the base (0:2-bit, 1:8-bit, 2:16-bit)
 */
template<typename T>
void limbstring<T>::init_power_2_string(phantom_vector<T>& limbs,
    const typename limbstring<T>::mpz_base_coding* base_coding,
    const char* str, size_t base, size_t base_code)
{
    // Get the length of string str
    size_t len      = strnlen(str, MAX_LIMBSTRING_LEN);
    if (MAX_LIMBSTRING_LEN == len) {
        throw std::runtime_error("Truncation of string");
    }

    // Get the limb length
    size_t limb_len = (len / base_coding[base_code].max_digits);
    limbs.resize(limb_len);

    size_t used  = 0;
    T      limb  = 0;
    size_t index = 0;

    // Traverse the string from the end
    for (const char* s = str + len - 1; s >= str; s--) {
        // Convert the character to a digit in the specified base, returning with an error if invalid
        T digit = _ascii_to_u8[static_cast<uint8_t>(*s)];
        if (digit >= base) {
            throw std::runtime_error("string contains an invalid character");
        }

        // Incrementally construct a limb word from the digit, advancing to the next limb when complete
        limb |= digit << index;
        index += base_coding[base_code].log2_base;
        if (index >= std::numeric_limits<T>::digits) {
            limbs[used++] = limb;
            index -= std::numeric_limits<T>::digits;
            limb   = digit >> (base_coding[base_code].log2_base - index);
        }
    }

    // Append any remaining bits to the MP integer
    if (limb) {
        limbs.push_back(limb);
        used++;
    }
}

/**
 * String conversion from base32 or base64 to a vector of T limbs
 * @param limbs Output vector of T objects
 * @param base_coding A pointer to the mpz_base_coding object describing the string
 * @param str The string be be decoded
 * @param base_lut A LUT describing conversion from 8-bit ASCII to an integer
 * @param base The base number system of the input string
 */
template<typename T>
void limbstring<T>::init_basex_string(phantom_vector<T>& limbs,
                                      const typename limbstring<T>::mpz_base_coding* base_coding,
                                      const char* str,
                                      const uint8_t* base_lut,
                                      size_t base)
{
    // Get the length of string str
    size_t len = strnlen(str, MAX_LIMBSTRING_LEN);
    if (MAX_LIMBSTRING_LEN == len) {
        throw std::runtime_error("Truncation of string");
    }

    // Omit padding symbols
    while ('=' == str[len-1]) {
        len--;
    }

    // Create a single word vector initialized to 0
    limbs.resize(1);

    size_t used  = 0;
    int index = -((base >> 5)*len & 0x7);

    // Traverse the string from the end
    for (const char* s = str + len - 1; s >= str; s--) {
        // Convert the character to a digit in the specified base, returning with an error if invalid
        T digit = base_lut[static_cast<uint8_t>(*s)];
        if (digit >= base) {
            throw std::runtime_error("string contains an invalid character");
        }

        // Incrementally construct a limb word from the digit, advancing to the next limb when complete
        limbs[used] |= (index < 0)? digit >> -index : digit << index;
        index += base_coding->log2_base;
        if (index >= std::numeric_limits<T>::digits) {
            limbs.push_back(0);
            index -= std::numeric_limits<T>::digits;
            limbs[++used]   = digit >> (base_coding->log2_base - index);
        }
    }
}

/**
 * String conversion from decimal to a vector of T limbs
 * @param limbs Output vector of T objects
 * @param str The string be be decoded
 */
template<typename T>
void limbstring<T>::init_decimal_string(phantom_vector<T>& limbs, const char* str)
{
    // Get the length of string str
    size_t len = strnlen(str, MAX_LIMBSTRING_LEN);
    if (MAX_LIMBSTRING_LEN == len) {
        throw std::runtime_error("Truncation of string");
    }

    // Create a temporary MP integer and set to 0
    mpz<T> temp;

    // Traverse the string from the end
    for (const char* s = str; s != str + len; s++) {
        // If str[i] is ', ' then split
        if (*s == ',' || *s == ' ') {
            continue;
        }

        // Convert character to an integer and add to scaled mpz
        temp = temp * T(10) + T(*s - 48);
    }

    // Transfer the mpz limb array to the poutput
    limbs.swap(temp.get_limbs());
}

/**
 * Conversion of T limb arrays to byte vectors for base-32
 * @param block Output vector of byte vales
 * @param limbs Input vector of T objects
 * @param limb_bits Size of the limb array in bits
 */
template<typename T>
void limbstring<T>::base32_gen_blocks(std::vector<uint8_t>& block, const T* limbs, size_t limb_bits)
{
    uint8_t mask     = (1 << 5) - 1;
    size_t n_bits    = ((limb_bits + 7) >> 3) << 3;
    size_t n_symbols = (n_bits + 4) / 5;
    int    shift     = n_bits - 5 * n_symbols;
    block = std::vector<uint8_t>(n_symbols);

    for (size_t j=0, k=n_symbols; k-->0;) {
        uint8_t c = (shift < 0)? limbs[j] << -shift : limbs[j] >> shift;
        shift += 5;
        if (shift >= std::numeric_limits<T>::digits) {
            shift -= std::numeric_limits<T>::digits;
            c     |= limbs[++j] << (5 - shift);
        }
        block[k] = _ascii_base32[mask & c];
    }
}

/**
 * Conversion of T limb arrays to byte vectors for base-64
 * @param block Output vector of byte vales
 * @param limbs Input vector of T objects
 * @param limb_bits Size of the limb array in bits
 */
template<typename T>
void limbstring<T>::base64_gen_blocks(std::vector<uint8_t>& block, const T* limbs, size_t limb_bits)
{
    uint8_t mask     = (1 << 6) - 1;
    size_t n_bits    = ((limb_bits + 7) >> 3) << 3;
    size_t n_symbols = (n_bits + 5) / 6;
    int    shift     = n_bits - 6 * n_symbols;
    block = std::vector<uint8_t>(n_symbols);

    for (size_t j=0, k=n_symbols; k-->0;) {
        uint8_t c = (shift < 0)? limbs[j] << -shift : limbs[j] >> shift;
        shift += 6;
        if (shift >= std::numeric_limits<T>::digits) {
            shift -= std::numeric_limits<T>::digits;
            c     |= limbs[++j] << (6 - shift);
        }
        block[k] = _ascii_base64[mask & c];
    }
}

/**
 * Convert an mpz object to a std::string with a user-defined base
 * @param number The mpz object to be converted
 * @param base The base number system of the output string
 * @param uppercase Optionally convert the string to use uppercase characters (default: false)
 * @return Output string
 */
template<typename T>
std::string limbstring<T>::get_str(const mpz<T>& number, size_t base, bool uppercase)
{
    if (!(2 == base) && !(8 == base) && !(10 == base) && !(16 == base) && !(32 == base) && !(64 == base)) {
        return std::string("");
    }

    size_t used = number.get_limbsize();
    if (0 == used) {
        std::string response((64 == base)? "AA==" : (32 == base)? "AA======" : "0");
        return response;
    }

    size_t len = number.is_negative() + 2 + number.sizeinbase(base);
    auto vecstr = std::vector<char>(len);
    char* str = vecstr.data();

    // Prepend a sign character as required
    if (number.is_negative()) {
        *str++ = '-';
    }

    auto n_used = bit_manipulation::clz(number[used-1]);
    if (64 == base) {
        size_t k = 0;
        std::vector<uint8_t> block;
        base64_gen_blocks(block, number.get_limbs().data(), number.sizeinbase(2));

        for (size_t j=0; j < block.size(); j++, k++) {
            str[k] = block[j];
        }

        if (0 != (k & 0x3)) {
            for (size_t i = 0; i < 4 - (k & 0x3); i++) {
                str[k+i] = '=';
            }
        }
    }
    else if (32 == base) {
        size_t k = 0;
        std::vector<uint8_t> block;
        base32_gen_blocks(block, number.get_limbs().data(), number.sizeinbase(2));

        for (size_t j=0; j < block.size(); j++, k++) {
            str[k] = block[j];
        }

        if (0 != (k & 0x7)) {
            for (size_t i = 0; i < 8 - (k & 0x7); i++) {
                str[k+i] = '=';
            }
        }
    }
    else if (10 == base) {
        mpz<T> temp = number;
        if (number.is_negative()) {
            temp = temp.negate();
        }

        // Calculate the number of digits rounded up
        size_t str_len = temp.sizeinbase(10);
        if (0 == str_len) {
            str[0] = '0';
        }
        else {
            for (size_t k=str_len; k-->0; ) {
                mpz<T> q, r;
                T v = mpz<T>::fdiv_qr_ui(q, r, temp, T(10));
                temp.swap(q);
                str[k] = v + 48;
            }

            // Count the number of leading zeros
            size_t zero_count = 0;
            while ('0' == str[zero_count]) {
                zero_count++;
                if (str_len == zero_count) {
                    break;
                }
            }
            for (size_t i=0; i < str_len-zero_count; i++) {
                str[i] = str[i + zero_count];
            }
            str[str_len-zero_count] = '\0';
        }
    }
    else {
        const char ascii_lower[] = "0123456789abcdefghijklmnopqrstuvwxyz";
        const char ascii_upper[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const char* ascii = uppercase? ascii_upper : ascii_lower;

        size_t bitsize = (2 == base)? 1 : (8 == base)? 3 : 4;
        uint8_t mask = (1 << bitsize) - 1;

        // Calculate the number of digits rounded up
        size_t str_len = (used * std::numeric_limits<T>::digits + bitsize - 1 - n_used) / bitsize;

        // Iterate through all the digits from the least significant, writing to the most
        // significant characters of the output
        if (0 == str_len) {
            str[0] = ascii[0];
        }
        else {
            for (size_t j=0, k=str_len, shift=0; k-->0;) {
                uint8_t c = number[j] >> shift;
                shift += bitsize;
                if (shift >= std::numeric_limits<T>::digits && ++j < used) {
                    shift -= std::numeric_limits<T>::digits;
                    c     |= number[j] << (bitsize - shift);
                }
                str[k] = ascii[static_cast<uint8_t>(mask & c)];
            }

            // Count the number of leading zeros
            size_t zero_count = 0;
            while ('0' == str[zero_count]) {
                zero_count++;
                if (str_len == zero_count) {
                    break;
                }
            }
            for (size_t i=0; i < str_len-zero_count; i++) {
                str[i] = str[i + zero_count];
            }
            str[str_len-zero_count] = '\0';
        }
    }

    std::string response(vecstr.data());
    return response;
}

/**
 * Convert a string to a vector of T limbs
 * @param limbs Output vector of T limbs
 * @param sign The sign of the out vector of T limbs
 * @param str The string to be converted
 * @param base Base number of the input string
 */
template<typename T>
void limbstring<T>::set_str(phantom_vector<T>& limbs, bool& sign, const char* str, size_t base)
{
    size_t base_code = (2  == base)? 0 :
                        (8  == base)? 1 :
                        (16 == base)? 2 :
                        (32 == base)? 3 :
                        (64 == base)? 4 :
                        (10 == base)? 5 :
                                        6;
    if (6 == base_code) {
        throw std::runtime_error("base is invalid");
    }

    const typename limbstring<T>::mpz_base_coding* base_coding;
    switch (std::numeric_limits<T>::digits)
    {
        case 64: base_coding = limbstring<T>::base_coding_64; break;
        case 32: base_coding = limbstring<T>::base_coding_32; break;
        case 16: base_coding = limbstring<T>::base_coding_16; break;
        default: base_coding = limbstring<T>::base_coding_8;
    }

    // Detect minus and advance the string pointer
    sign = false;
    if ('-' == *str) {
        str++;
        sign = true;
    }

    // Detect and remove prefix characters
    if (16 == base && '0' == str[0] && ('x' == str[1] || 'X' == str[1])) {
        str += 2;
    }
    if (10 == base && '0' == str[0] && ('d' == str[1] || 'D' == str[1])) {
        str += 2;
    }
    if (8 == base && '0' == str[0] && ('o' == str[1] || 'O' == str[1])) {
        str += 2;
    }
    if (2 == base && '0' == str[0] && ('b' == str[1] || 'B' == str[1])) {
        str += 2;
    }

    // Detect and remove leading zeros
    // NOTE: must protect base64 from corruption here as '0' is a valid encoded symbol
    if (64 != base) {
        while ('0' == *str) {
            str++;
        }
    }

    // Perform base-specific decoding
    if (64 == base) {
        init_basex_string(limbs, &base_coding[4], str, _base64_to_u8, 64);
    }
    else if (32 == base) {
        init_basex_string(limbs, &base_coding[3], str, _base32_to_u8, 32);
    }
    else if (10 == base) {
        init_decimal_string(limbs, str);
    }
    else {
        init_power_2_string(limbs, base_coding, str, base, base_code);
    }

    // Remove significant words that are equal to zero
    size_t used = limbs.size();
    while (used) {
        if (limbs[--used]) {
            used++;
            break;
        }
    }
    limbs.resize(used);
}


// Forward declaration of common type declarations
/// @{
template class limbstring<uint8_t>;
template class limbstring<uint16_t>;
template class limbstring<uint32_t>;
#if defined(IS_64BIT)
template class limbstring<uint64_t>;
#endif
/// @}

}  // namespace core
}  // namespace phantom
