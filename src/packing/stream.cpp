/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "packing/stream.hpp"

#include <algorithm>
#include <stdexcept>


namespace phantom {
namespace packing {


#if defined(__linux__)
#include <arpa/inet.h>
#else

uint32_t htonl(uint32_t hostlong)
{
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    return hostlong;
#else
    return ((hostlong & 0x000000ffUL) << 24) |
           ((hostlong & 0x0000ff00UL) <<  8) |
           ((hostlong & 0x00ff0000UL) >>  8) |
           ((hostlong & 0xff000000UL) >> 24);
#endif
}

uint32_t ntohl(uint32_t netlong)
{
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    return netlong;
#else
    return ((netlong & 0x000000ffUL) << 24) |
           ((netlong & 0x0000ff00UL) <<  8) |
           ((netlong & 0x00ff0000UL) >>  8) |
           ((netlong & 0xff000000UL) >> 24);
#endif
}

uint64_t htobe64(uint64_t hostlong)
{
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    return hostlong;
#else
    return ((hostlong & 0x00000000000000ffUL) << 56) |
           ((hostlong & 0x000000000000ff00UL) << 40) |
           ((hostlong & 0x0000000000ff0000UL) << 24) |
           ((hostlong & 0x00000000ff000000UL) <<  8) |
           ((hostlong & 0x000000ff00000000UL) >>  8) |
           ((hostlong & 0x0000ff0000000000UL) >> 24) |
           ((hostlong & 0x00ff000000000000UL) >> 40) |
           ((hostlong & 0xff00000000000000UL) >> 56);
#endif
}

uint64_t be64toh(uint64_t netlong)
{
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    return netlong;
#else
    return ((netlong & 0x00000000000000ffUL) << 56) |
           ((netlong & 0x000000000000ff00UL) << 40) |
           ((netlong & 0x0000000000ff0000UL) << 24) |
           ((netlong & 0x00000000ff000000UL) <<  8) |
           ((netlong & 0x000000ff00000000UL) >>  8) |
           ((netlong & 0x0000ff0000000000UL) >> 24) |
           ((netlong & 0x00ff000000000000UL) >> 40) |
           ((netlong & 0xff00000000000000UL) >> 56);
#endif
}

#endif


#if defined(__x86_64__)

#define HOST_PACKER_BITS          64
#define HOST_PACKER_BYTES         8
#define HOST_PACKER_BYTES_SHIFT   3

static inline uint64_t u8_to_host(void *network)
{
    uint8_t *unaligned = reinterpret_cast<uint8_t*>(network);
    uint64_t tmp;

    tmp  = static_cast<uint64_t>(unaligned[7]) << 56;
    tmp |= static_cast<uint64_t>(unaligned[6]) << 48;
    tmp |= static_cast<uint64_t>(unaligned[5]) << 40;
    tmp |= static_cast<uint64_t>(unaligned[4]) << 32;
    tmp |= static_cast<uint64_t>(unaligned[3]) << 24;
    tmp |= static_cast<uint64_t>(unaligned[2]) << 16;
    tmp |= static_cast<uint64_t>(unaligned[1]) << 8;
    tmp |= static_cast<uint64_t>(unaligned[0]);
    return be64toh(tmp);
}

static inline void host_to_u8(void *network, uint64_t host)
{
    uint8_t *unaligned = reinterpret_cast<uint8_t*>(network);

    host = htobe64(host);
    unaligned[7] = static_cast<uint8_t>(host >> 56);
    unaligned[6] = static_cast<uint8_t>(host >> 48);
    unaligned[5] = static_cast<uint8_t>(host >> 40);
    unaligned[4] = static_cast<uint8_t>(host >> 32);
    unaligned[3] = static_cast<uint8_t>(host >> 24);
    unaligned[2] = static_cast<uint8_t>(host >> 16);
    unaligned[1] = static_cast<uint8_t>(host >> 8);
    unaligned[0] = static_cast<uint8_t>(host);
}

#else

#define HOST_PACKER_BITS          32
#define HOST_PACKER_BYTES         4
#define HOST_PACKER_BYTES_SHIFT   2

static inline uint32_t u8_to_host(void *network)
{
    uint8_t *unaligned = reinterpret_cast<uint8_t*>(network);
    uint32_t tmp;

    tmp  = static_cast<uint32_t>(unaligned[3]) << 24;
    tmp |= static_cast<uint32_t>(unaligned[2]) << 16;
    tmp |= static_cast<uint32_t>(unaligned[1]) << 8;
    tmp |= static_cast<uint32_t>(unaligned[0]);
    return ntohl(tmp);
}

static inline void host_to_u8(void *network, uint32_t host)
{
    uint8_t *unaligned = reinterpret_cast<uint8_t*>(network);

    host = htonl(host);
    unaligned[3] = static_cast<uint8_t>(host >> 24);
    unaligned[2] = static_cast<uint8_t>(host >> 16);
    unaligned[1] = static_cast<uint8_t>(host >> 8);
    unaligned[0] = static_cast<uint8_t>(host);
}

#endif



stream::stream(size_t max_bytes)
{
    max_bytes    = ((max_bytes + HOST_PACKER_BYTES - 1) >> HOST_PACKER_BYTES_SHIFT) << HOST_PACKER_BYTES_SHIFT;

    m_bits       = max_bytes << 3;
    m_bits_left  = HOST_PACKER_BITS;  // i.e. 32/64 bits left to fill
    m_scratch    = 0;
    m_head       = 0;
    m_tail       = 0;

    m_vec_buffer = phantom_vector<uint8_t>(max_bytes);
    m_buffer     = m_vec_buffer.data();
}

stream::stream(const phantom_vector<uint8_t>& bytes)
{
    size_t max_bytes = ((bytes.size() + HOST_PACKER_BYTES - 1) >> HOST_PACKER_BYTES_SHIFT) << HOST_PACKER_BYTES_SHIFT;

    m_bits       = max_bytes << 3;
    m_bits_left  = 0;                // i.e. empty
    m_scratch    = 0;
    m_head       = max_bytes;
    m_tail       = 0;

    m_vec_buffer = bytes;
    m_buffer     = m_vec_buffer.data();
}

stream::~stream()
{

}

uint32_t stream::read(size_t bits)  // flawfinder: ignore
{
    if (0 == bits) {
        throw std::invalid_argument("Trying to read 0 bits");
    }

    uint32_t value = 0;
    while (1) {
        if (0 == m_bits_left) {
            if (m_tail > (m_bits >> 3)) {
                throw std::runtime_error("Packer has too few bits available for read");
            }
            else if (m_tail > ((m_bits >> 3) - HOST_PACKER_BYTES)) {
                uint8_t temp[HOST_PACKER_BYTES];
                std::copy(m_buffer + m_tail, m_buffer + m_head, temp);
                m_scratch = u8_to_host(temp);
                m_tail      += m_head - m_tail;
                m_head      -= m_head - m_tail;
                m_bits_left  = (m_head - m_tail) << 3;
            }
            else {
                m_scratch    = u8_to_host(m_buffer + m_tail);
                m_tail      += HOST_PACKER_BYTES;
                m_head      -= HOST_PACKER_BYTES;
                m_bits_left  = HOST_PACKER_BITS;
            }
        }

        if (bits <= m_bits_left) {
            value |= m_scratch >> (m_bits_left - bits);
            m_scratch &= (1L << (m_bits_left - bits)) - 1;
            m_bits_left -= bits;
            return value;
        }

        value |= m_scratch << (bits - m_bits_left);
        bits -= m_bits_left;
        m_bits_left = 0;
    }
}

void stream::write(uint32_t data, size_t bits)
{
    // Verify that there is sufficient space in the output buffer to continue
    if (m_head > ((m_bits >> 3) - HOST_PACKER_BYTES)) {
        throw std::runtime_error("Packer has too few bits available for write");
    }

    // Mask the value to exclude unwanted bits
    data &= 0xFFFFFFFF >> (32 - bits);

    m_bits += bits;

    // If the number of bits to be written is less than that available in the
    // scratch buffer then write the data and return
    if (bits <= m_bits_left) {
        m_scratch   |= static_cast<buf_t>(data) << (m_bits_left - bits);
        m_bits_left -= bits;
        return;
    }

    // Update the scratch buffer to fill it and update the input data
    m_scratch |= data >> (bits - m_bits_left);

    // Copy the 32/64-bit scratch buffer contents to the output buffer
    host_to_u8(m_buffer + m_head, m_scratch);
    m_head      += HOST_PACKER_BYTES;
    bits         = HOST_PACKER_BITS - bits + m_bits_left;
    m_scratch    = static_cast<buf_t>(data) << bits;
    m_bits_left  = bits;
    return;
}

void stream::flush(size_t alignment)
{
    // Flush any outstanding bits in the scratch buffer to the output buffer
    if (m_bits_left < HOST_PACKER_BITS) {
        size_t num_bytes = (HOST_PACKER_BITS - m_bits_left + 7) >> 3;

        if (m_head > ((m_bits >> 3) - num_bytes)) {
            throw std::runtime_error("Packer has too few bits available for flush");
        }

        host_to_u8(m_buffer + m_head, m_scratch);
        m_head      += num_bytes;
        m_scratch    = 0;
        m_bits_left  = HOST_PACKER_BITS;
    }
}

const phantom_vector<uint8_t>& stream::get() const
{
    return m_vec_buffer;
}

}  // namespace packing
}  // namespace phantom
