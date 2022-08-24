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
#include <limits>
#include <memory>
#include <string>
#include <vector>

#include "core/template_helpers.hpp"
#include "./phantom_memory.hpp"
#include "core/mpbase_defines.hpp"

namespace phantom {
namespace core {

/// An enumerated type for arithmetic rounding control
enum class mp_round_e {
    MP_ROUND_ZERO,
    MP_ROUND_TRUNC,
    MP_ROUND_FLOOR,
    MP_ROUND_CEIL
};

/** 
 * @brief Interface class for multiple-precision arithmetic
 * 
 * Pure virtual methods describing an interface for MP arithmetic
 */
template<typename T>
class mp
{
    using S = signed_type_t<T>;

public:
    virtual ~mp() {}

    /**
     * @brief Check if mp-based number is zero
     * @return bool True if zero, false otherwise 
     */
    virtual bool is_zero() const = 0;

    /**
     * @brief Check if mp-based number is one
     * @return bool True if one, false otherwise 
     */
    virtual bool is_one() const = 0;

    /**
     * @brief Check if mp-based number is negative
     * @return bool True if -ve, false otherwise 
     */
    virtual bool is_negative() const = 0;

    /**
     * @brief Set the negative sign of the mp-based number
     * @param sign True if -ve, false if +ve
     */
    virtual void set_sign(bool sign) = 0;

    /**
     * @brief Allocate memory and set to zero
     * @param n Number of limbs to set to allocate and zero
     */
    virtual void zero_init(size_t n) = 0;

    /**
     * @brief Determine the integer size in bits in the selected base
     * @param base Base number system
     * @return size_t Number of bits
     */
    virtual size_t sizeinbase(size_t base) const = 0;

    /**
     * @brief Swap the current mp object for the referenced mp object
     * @param in The mp object to be swapped
     */
    virtual void swap(mp& in) = 0;  // NOLINT

    /**
     * @brief Get the bytes vector associated with the limbs of the mp object
     * @param bytes A vector of output bytes
     * @param little_endian Endianness of the bytes (default: false)
     */
    virtual void get_bytes(phantom_vector<uint8_t>& bytes, bool little_endian = false) const = 0;

    /**
     * @brief Set the limbs of the mp object using a bytes vector
     * @param bytes A vector of input bytes
     * @param little_endian Endianness of the bytes (default: false)
     */
    virtual void set_bytes(const phantom_vector<uint8_t>& bytes, bool little_endian = false) = 0;

    /**
     * @brief Get a string in the selected base that represents the mp object
     * @param base Base number system
     * @param uppercase Optional selection of uppercase characters (default: false)
     * @return std::string A string representation of the mp object
     */
    virtual std::string get_str(size_t base, bool uppercase = false) const = 0;

    /**
     * @brief Get a const reference of the vector of limbs used to represent the mp object
     * @return const phantom_vector<T>& Vector of limbs
     */
    virtual const phantom_vector<T>& get_limbs() const = 0;

    /**
     * @brief Get a reference of the vector of limbs used to represent the mp object
     * @return phantom_vector<T>& Vector of limbs
     */
    virtual phantom_vector<T>& get_limbs() = 0;

    /**
     * @brief Get the number of limbs used to represent the mp object
     * @return size_t Number of limbs
     */
    virtual size_t get_limbsize() const = 0;

    /**
     * @brief Compare this mp object with another
     * @param in mp object to compare
     * @return int32_t -1 if smaller, 0 if equal, 1 if larger
     */
    virtual int32_t cmp(const mp& in) const = 0;

    /**
     * @brief Compare this mp object with an unsigned limb
     * @param in unsigned limb to compare
     * @return int32_t -1 if smaller, 0 if equal, 1 if larger
     */
    virtual int32_t cmp_ui(T in) const = 0;

    /**
     * @brief Compare this mp object with a signed limb
     * @param in signed limb to compare
     * @return int32_t -1 if smaller, 0 if equal, 1 if larger
     */
    virtual int32_t cmp_si(S in) const = 0;

    /**
     * @brief Compare the absolute difference between this mp object and another
     * @param in mp object to compare
     * @return int32_t -1 if smaller, 0 if equal, 1 if larger
     */
    virtual int32_t cmpabs(const mp& in) const = 0;
};

}  // namespace core
}  // namespace phantom
