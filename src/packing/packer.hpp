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
#include <memory>
#include <vector>

#include "./phantom_memory.hpp"


namespace phantom {
namespace packing {


enum pack_e : uint8_t;

class stream;

/// A class used to write and encode packed streams
class packer
{
public:
    explicit packer(size_t max_bits);
    ~packer();

    void write_signed(int32_t data, size_t bits, pack_e type);
    void write_unsigned(uint32_t data, size_t bits, pack_e type);
    void flush();

    const phantom_vector<uint8_t>& get();
    const phantom_vector<uint8_t>& serialize();

private:
    const std::unique_ptr<stream> m_stream;
};

}  // namespace packing
}  // namespace phantom
