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
#include <cstring>
#include <vector>

#include "./phantom_memory.hpp"


namespace phantom {
namespace crypto {

/**
 * @defgroup hashing Hashing functions
 * 
 * Hash and Extensible Output Function (XOF) classes, structs, types,etc.
 */

/**
 * @ingroup hashing
 * @brief Hash interface
 * 
 * Abstract base class to define a common interface for all hash algorithms.
 */
class hash : public aligned_base<DEFAULT_MEM_ALIGNMENT>
{
public:
    virtual ~hash() {}

    virtual size_t get_length() const = 0;
    virtual hash* get_copy() = 0;
    virtual bool init(size_t len) = 0;
    virtual void update(const uint8_t *data, size_t len) = 0;
    virtual void final(uint8_t *data) = 0;
};

}  // namespace crypto
}  // namespace phantom
