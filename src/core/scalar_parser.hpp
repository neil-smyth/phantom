/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
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
#include <vector>

#include "core/mpz.hpp"
#include "core/bit_manipulation.hpp"
#include "core/template_helpers.hpp"


namespace phantom {
namespace core {

/// Bit coding format
/// @{
#define SCALAR_IS_LOW         256
#define SCALAR_IS_HIGH        1
#define SCALAR_IS_SUBTRACT    512
/// @}

#define SCALAR_CODING_PRE_BIT         0x40
#define SCALAR_CODING_PRE_BIT_SHIFT   6
#define SCALAR_CODING_NAF_BIT         0x80
#define SCALAR_CODING_NAF_BIT_SHIFT   7
#define SCALAR_CODING_BINARY_DUAL     0xC0

/// An enumerated type describing the coding of scalar numbers
enum scalar_coding_e {
    ECC_BINARY           = 0,
    ECC_MONT_LADDER      = 1,
    ECC_PRE_2            = SCALAR_CODING_PRE_BIT + 2,
    ECC_PRE_3            = SCALAR_CODING_PRE_BIT + 3,
    ECC_PRE_4            = SCALAR_CODING_PRE_BIT + 4,
    ECC_PRE_5            = SCALAR_CODING_PRE_BIT + 5,
    ECC_PRE_6            = SCALAR_CODING_PRE_BIT + 6,
    ECC_PRE_7            = SCALAR_CODING_PRE_BIT + 7,
    ECC_PRE_8            = SCALAR_CODING_PRE_BIT + 8,
    ECC_NAF_2            = SCALAR_CODING_NAF_BIT + 2,
    ECC_NAF_3            = SCALAR_CODING_NAF_BIT + 3,
    ECC_NAF_4            = SCALAR_CODING_NAF_BIT + 4,
    ECC_NAF_5            = SCALAR_CODING_NAF_BIT + 5,
    ECC_NAF_6            = SCALAR_CODING_NAF_BIT + 6,
    ECC_NAF_7            = SCALAR_CODING_NAF_BIT + 7,
    ECC_BINARY_DUAL      = SCALAR_CODING_BINARY_DUAL + 2,
};

/** 
 * @brief Parsing and recoding of scalar numbers
 * 
 * Supports binary, non-adjacent form, pre-computation and Montgomery ladder recoding
 */
class scalar_parser
{
private:
    const uint8_t* m_secret1;
    const uint8_t* m_secret2;
    phantom_vector<uint8_t> m_recoded;
    size_t m_max;
    size_t m_shift;
    int32_t m_index;
    scalar_coding_e m_coding;

    /**
     * @brief Recode a vector of bytes using windowing
     * 
     * @param recoded The recoded values
     * @param secret The secret value to be recoded
     * @param w Window size in bits
     * @return size_t Number of windows
     */
    static size_t window(phantom_vector<uint8_t>& recoded, const phantom_vector<uint8_t>& secret, size_t w);

    /**
     * @brief Recode a vector of bytes using Non-adjacent form
     * 
     * @param recoded The recoded values
     * @param secret The secret value to be recoded
     * @param w Window size in bits
     * @return size_t Number of windows
     */
    static size_t naf(phantom_vector<uint8_t>& recoded, const mpz<uint32_t>& secret, size_t w);

    /**
     * @brief Recode a vector of bytes for use with binary dual encoding
     * 
     * @param recoded The recoded values
     * @param secret The secret value to be recoded
     * @return size_t Number of windows
     */
    static size_t binary_dual(phantom_vector<uint8_t>& recoded, const phantom_vector<uint8_t>& secret);
    uint16_t peek() const;

    /// Return the next encoded symbol for Non-adjacent form encoding
    uint32_t pull_naf();

    /// Return the next encoded symbol for Window encoding
    uint32_t pull_window();

    /// Return the next encoded symbol for binary encoding
    uint32_t pull_binary();

    /// Return the next encoded symbol for binary dual encoding
    uint32_t pull_binary_dual();

public:
    /**
     * @brief Construct a new scalar parser object
     * 
     * @param coding Type of coding to use
     * @param secret Secret scalar value to be recoded
     */
    scalar_parser(scalar_coding_e coding, const phantom_vector<uint8_t>& secret);

    /// Return the maximum number of encoded symbols
    size_t num_symbols();

    /// Return the current window index
    size_t get_window();

    /// Pull the next encoded symbol
    uint32_t pull();
};

}  // namespace core
}  // namespace phantom
