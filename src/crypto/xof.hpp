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


namespace phantom {
namespace crypto {

/**
 * @ingroup hashing
 * @brief XOF interface
 * 
 * Base class for Extensible Output Functions
 */
class xof
{
public:
    virtual ~xof() {}

    virtual size_t get_length() const = 0;
    virtual xof* get_copy() = 0;
    virtual bool init(size_t len) = 0;
    virtual void absorb(const uint8_t *data, size_t len) = 0;
    virtual void final() = 0;
    virtual void squeeze(uint8_t *data, size_t len) = 0;
};

}  // namespace crypto
}  // namespace phantom
