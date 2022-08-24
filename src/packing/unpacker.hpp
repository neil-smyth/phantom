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

/// A class used to read and decode packed streams
class unpacker
{
public:
    unpacker();
    explicit unpacker(const phantom_vector<uint8_t>& bytes);
    ~unpacker();

    void append_stream(const phantom_vector<uint8_t>& bytes);
    size_t get_stream_size() const;

    bool is_data_available() const;

    int32_t read_signed(size_t bits, pack_e type);
    uint32_t read_unsigned(size_t bits, pack_e type);

private:
    const std::unique_ptr<stream> m_stream;
};

}  // namespace packing
}  // namespace phantom
