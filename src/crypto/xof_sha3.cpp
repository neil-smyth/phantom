/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "crypto/xof_sha3.hpp"


namespace phantom {
namespace crypto {


xof_sha3::xof_sha3() : m_rounds(24)
{
}

xof_sha3::~xof_sha3()
{
}

size_t xof_sha3::get_length() const
{
    return m_mdlen;
}

xof* xof_sha3::get_copy()
{
    xof_sha3* copy = new xof_sha3();
    copy->m_st = m_st;
    copy->m_pt = m_pt;
    copy->m_rsiz = m_rsiz;
    copy->m_mdlen = m_mdlen;
    return copy;
}

bool xof_sha3::init(size_t len)
{
    if (16 != len && 32 != len) {
        return false;
    }

    for (size_t i = 25; i--;) {
        m_st.q[i] = 0;
    }
    m_mdlen = len;
    m_rsiz  = 200 - 2 * len;
    m_pt    = 0;

    return true;
}

void xof_sha3::absorb(const uint8_t *data, size_t len)
{
    if (nullptr == data) {
        return;
    }

#if 1
    size_t j = m_pt;

    // If there is sufficient data we will process Keccak blocks
    if ((len + j) >= m_rsiz) {
        // Process the first block which may be incomplete
        for (size_t i = m_rsiz - j; i--;) {
            m_st.b[j++] ^= *data++;
            if (j >= m_rsiz) {
                keccak::core(m_st.q, m_rounds);
                j = 0;
                len -= m_rsiz - m_pt;
            }
        }

        // Process all subsequent blocks
        if (0 == j) {
            while (len >= m_rsiz) {
                for (size_t i = m_rsiz; i--;) {
                    m_st.b[j++] ^= *data++;
                }
                keccak::core(m_st.q, m_rounds);
                j = 0;
                len -= m_rsiz;
            }
        }
    }

    // Update the state with any remaining bytes
    for (size_t i = len; i--;) {
        m_st.b[j++] ^= *data++;
    }
#else
    size_t j = m_pt;
    for (size_t i = len; i--;) {
        m_st.b[j++] ^= *data++;
        if (j >= m_rsiz) {
            keccak::core(m_st.q, m_rounds);
            j = 0;
        }
    }
#endif
    m_pt = j;
}

void xof_sha3::final()
{
    m_st.b[m_pt] ^= 0x1F;
    m_st.b[m_rsiz - 1] ^= 0x80;
    keccak::core(m_st.q, m_rounds);
    m_pt = 0;
}

void xof_sha3::squeeze(uint8_t *data, size_t len)
{
    if (nullptr == data) {
        return;
    }

    size_t j = m_pt;

    for (size_t i = 0; i < len; i++) {
        if (j >= m_rsiz) {
            keccak::core(m_st.q, m_rounds);
            j = 0;
        }
        data[i] = m_st.b[j++];
    }

    m_pt = j;
}

}  // namespace crypto
}  // namespace phantom
