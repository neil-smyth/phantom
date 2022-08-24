/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "packing/unpacker.hpp"
#include "packing/stream.hpp"

namespace phantom {
namespace packing {


unpacker::unpacker() : m_stream(std::unique_ptr<stream>(new stream(phantom_vector<uint8_t>())))
{
}

unpacker::unpacker(const phantom_vector<uint8_t>& bytes) : m_stream(std::unique_ptr<stream>(new stream(bytes)))
{
}

unpacker::~unpacker()
{
}

void unpacker::append_stream(const phantom_vector<uint8_t>& bytes)
{
    m_stream->append_stream(bytes);
}

size_t unpacker::get_stream_size() const
{
    return m_stream->get().size();
}

bool unpacker::is_data_available() const
{
    return m_stream->get().size() > 0;
}

int32_t unpacker::read_signed(size_t bits, pack_e type)
{
    uint32_t coded          = m_stream->read(bits);  // flawfinder: ignore
    uint32_t sign           = 1 << (bits - 1);
    uint32_t sign_extension = ((1 << (32 - bits)) - 1) << bits;

    return (coded & sign)? sign_extension | coded : coded;
}

uint32_t unpacker::read_unsigned(size_t bits, pack_e type)
{
    uint32_t coded = m_stream->read(bits);  // flawfinder: ignore

    return coded;
}

}  // namespace packing
}  // namespace phantom
