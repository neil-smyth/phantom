/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "crypto/aes_ccm.hpp"
#include <cassert>
#include <iostream>
#include <memory>

namespace phantom {
namespace crypto {


aes_ccm::aes_ccm(aes_keylen_e key_len)
{
    m_aes = std::unique_ptr<aes_encrypt>(aes_encrypt::make(key_len));
}

aes_ccm::~aes_ccm() {}

aes_ccm* aes_ccm::make(aes_keylen_e key_len)
{
    return new aes_ccm(key_len);
}

int32_t aes_ccm::set_key(const uint8_t *key, size_t key_len)
{
    if (16 == key_len) {
        return m_aes->set_key(key, aes_keylen_e::AES_128);
    }
    else if (24 == key_len) {
        return m_aes->set_key(key, aes_keylen_e::AES_192);
    }
    else if (32 == key_len) {
        return m_aes->set_key(key, aes_keylen_e::AES_256);
    }
    return EXIT_FAILURE;
}

int32_t aes_ccm::encrypt_start(const uint8_t *iv, size_t iv_len,
    const uint8_t *aad, size_t aad_len)
{
    const uint8_t t = 8;
    m_q      = 15 - iv_len;
    m_iv_len = iv_len;

    if (iv_len <= sizeof(m_ctr)) {
        m_b[0]   = ((aad_len > 0) << 6) | ((t - 2) >> 1) | (m_q - 1);  // Flag octet
        for (size_t i=1; i < iv_len+1; i++) {
            m_b[i] = iv[i];
        }
        for (size_t i=iv_len+1; i < 16; i++) {
            m_b[i] = (m_q >> 8*(15 - i));
        }

        // Encrypt the B0 block
        phantom_vector<uint8_t> auth_block(16);
        m_aes->encrypt(auth_block.data(), m_b);

        for (size_t i=0; i < 2; i++) {
            m_b[i] = auth_block[i] ^ (aad_len >> 8*(1-i));
        }
        for (size_t i=0; i < aad_len; i++) {
            m_b[2+i] = auth_block[2+i] ^ aad[i];
        }
        for (size_t i=2+aad_len; i < 16; i++) {
            m_b[i] = auth_block[i];
        }

        // Encrypt the B1 block
        m_aes->encrypt(auth_block.data(), m_b);

        for (size_t i=0; i < 16; i++) {
            m_b[i] = auth_block[i];
        }

        m_ctr[0] = (m_q - 1);  // Flag octet
        for (size_t i=0; i < iv_len; i++) {
            m_ctr[i] = iv[i];
        }
        for (size_t i=iv_len; i < 16; i++) {
            m_ctr[i] = 0;
        }

        // Encrypt the CTR block toform S0
        m_aes->encrypt(m_S0, m_ctr);

        // Increment the counter
        size_t idx = 15;
        m_ctr[idx]++;
        while (0 == m_ctr[idx]) {
            idx--;
            m_ctr[idx]++;
        }

        return EXIT_SUCCESS;
    }
    else {
        return EXIT_FAILURE;
    }
}

int32_t aes_ccm::encrypt_update(uint8_t *out, const uint8_t *in, size_t len)
{
    phantom_vector<uint8_t> block(16);
    phantom_vector<uint8_t> auth_block(16);

    while (len > 0) {

        size_t use_len = (len < 16) ? len : 16;

        // Encrypt the B block
        for (size_t i=0; i < use_len; i++) {
            m_b[i] ^= in[i];
        }
        m_aes->encrypt(auth_block.data(), m_b);
        for (size_t i=0; i < use_len; i++) {
            m_b[i] = auth_block[i];
        }

        // Encrypt the CTR block
        m_aes->encrypt(block.data(), m_ctr);

        // Increment the counter
        size_t idx = 15;
        m_ctr[idx]++;
        while (0 == m_ctr[idx]) {
            idx--;
            m_ctr[idx]++;
        }

        // XOR with input
        if (use_len == 16) {
            out[ 0] = block[ 0] ^ in[ 0];
            out[ 1] = block[ 1] ^ in[ 1];
            out[ 2] = block[ 2] ^ in[ 2];
            out[ 3] = block[ 3] ^ in[ 3];
            out[ 4] = block[ 4] ^ in[ 4];
            out[ 5] = block[ 5] ^ in[ 5];
            out[ 6] = block[ 6] ^ in[ 6];
            out[ 7] = block[ 7] ^ in[ 7];
            out[ 8] = block[ 8] ^ in[ 8];
            out[ 9] = block[ 9] ^ in[ 9];
            out[10] = block[10] ^ in[10];
            out[11] = block[11] ^ in[11];
            out[12] = block[12] ^ in[12];
            out[13] = block[13] ^ in[13];
            out[14] = block[14] ^ in[14];
            out[15] = block[15] ^ in[15];
        }
        else {
            for (size_t i=0; i < use_len; i++) {
                out[i] = block[i] ^ in[i];
            }
        }

        len -= use_len;
        in  += 16;
        out += 16;
    }

    return EXIT_SUCCESS;
}

int32_t aes_ccm::encrypt_finish(uint8_t *tag, size_t tag_len)
{
    if (0 != tag_len) {
        for (size_t i=0; i < tag_len; i++) {
            tag[i] = m_b[i] ^ m_S0[i];
        }
    }

    return EXIT_SUCCESS;
}

int32_t aes_ccm::decrypt_start(const uint8_t *iv, size_t iv_len,
    const uint8_t *aad, size_t aad_len)
{
    return encrypt_start(iv, iv_len, aad, aad_len);
}

int32_t aes_ccm::decrypt_update(uint8_t *out, const uint8_t *in, size_t len)
{
    return encrypt_update(out, in, len);
}

int32_t aes_ccm::decrypt_finish(uint8_t *tag, size_t tag_len)
{
    return encrypt_finish(tag, tag_len);
}

}  // namespace crypto
}  // namespace phantom
