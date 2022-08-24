/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "packing/packer.hpp"
#include "packing/stream.hpp"

namespace phantom {
namespace packing {


packer::packer(size_t max_bits) : m_stream(std::unique_ptr<stream>(new stream((max_bits+7) >> 3)))
{
}

packer::~packer()
{
}

void packer::write_signed(int32_t data, size_t bits, pack_e type)
{
    // Modify data and bits according to type
    uint32_t coded = static_cast<uint32_t>(data);

    m_stream->write(coded, bits);
}

void packer::write_unsigned(uint32_t data, size_t bits, pack_e type)
{
    m_stream->write(data, bits);
}

void packer::flush(size_t alignment)
{
    m_stream->flush(alignment);
}

const phantom_vector<uint8_t>& packer::get()
{
    return m_stream->get();
}

const phantom_vector<uint8_t>& packer::serialize(size_t alignment)
{
    m_stream->flush(alignment);
    return m_stream->get();
}

}  // namespace packing
}  // namespace phantom
