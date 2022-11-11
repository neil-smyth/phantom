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

/// Stream encoding types
enum pack_e : uint8_t {
    RAW,
    HUFFMAN,
};

/// A class that implements the core stream processing functionality
class stream
{
#if defined(__x86_64__)
    using buf_t = uint64_t;
#else
    using buf_t = uint32_t;
#endif

public:
    explicit stream(size_t max_bytes);
    explicit stream(const phantom_vector<uint8_t>& bytes);
    ~stream();

    uint32_t read(size_t bits);  // flawfinder: ignore
    void write(uint32_t data, size_t bits);
    void flush();
    const phantom_vector<uint8_t>& get() const;

private:
    phantom_vector<uint8_t> m_vec_buffer;
    uint8_t *m_buffer;
    size_t   m_bits;
    size_t   m_bits_left;
    buf_t    m_scratch;
    size_t   m_head;
    size_t   m_tail;
};

}  // namespace packing
}  // namespace phantom
