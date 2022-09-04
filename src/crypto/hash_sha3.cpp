/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "crypto/hash_sha3.hpp"
#include <algorithm>


namespace phantom {
namespace crypto {

hash_sha3::hash_sha3() : m_rounds(24)
{
}

hash_sha3::~hash_sha3()
{
}

size_t hash_sha3::get_length() const
{
    return m_mdlen;
}

hash* hash_sha3::get_copy()
{
    hash_sha3* obj = new hash_sha3();
    obj->m_st      = m_st;
    obj->m_pt      = m_pt;
    obj->m_rsiz    = m_rsiz;
    obj->m_mdlen   = m_mdlen;
    return obj;
}

bool hash_sha3::init(size_t len)
{
    switch (len)
    {
        case  28:
        case 224: len = 28; break;
        case  32:
        case 256: len = 32; break;
        case  48:
        case 384: len = 48; break;
        case  64:
        case 512: len = 64; break;
        default: return false;
    }

    std::fill(m_st.q, m_st.q + 25, 0);
    m_mdlen = len;
    m_rsiz  = 200 - 2 * len;
    m_pt    = 0;

    return true;
}

void hash_sha3::update(const uint8_t *data, size_t len)
{
    size_t i, j;

    j = m_pt;
    for (i = len; i--;) {
        m_st.b[j++] ^= *data++;
        if (j >= m_rsiz) {
            keccak::core(m_st.q, m_rounds);
            j = 0;
        }
    }
    m_pt = j;
}

void hash_sha3::final(uint8_t *data)
{
    m_st.b[m_pt]       ^= 0x06;
    m_st.b[m_rsiz - 1] ^= 0x80;
    keccak::core(m_st.q, m_rounds);

    std::copy(m_st.b, m_st.b + m_mdlen, data);
}

}  // namespace crypto
}  // namespace phantom
