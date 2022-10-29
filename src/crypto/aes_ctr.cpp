/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "crypto/aes_ctr.hpp"
#include <cassert>
#include <iostream>
#include <memory>

namespace phantom {
namespace crypto {


aes_ctr::aes_ctr(aes_keylen_e key_len)
{
    m_aes = std::unique_ptr<aes_encrypt>(aes_encrypt::make(key_len));
}

aes_ctr::~aes_ctr() {}

aes_ctr* aes_ctr::make(aes_keylen_e key_len)
{
    return new aes_ctr(key_len);
}

symmetric_key_ctx* aes_ctr::get_enc()
{
    return m_aes.get();
}

symmetric_key_ctx* aes_ctr::get_dec()
{
    return nullptr;
}

uint8_t* aes_ctr::get_ctr()
{
    return m_iv.data;
}

int32_t aes_ctr::set_key(const uint8_t *key, size_t key_len)
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

int32_t aes_ctr::encrypt_start(const uint8_t *iv, size_t iv_len)
{
    if (iv_len <= sizeof(m_iv.data)) {
        for (size_t i=0; i < iv_len; i++) {
            m_iv.data[i] = iv[i];
        }
        for (size_t i=iv_len; i < 16; i++) {
            m_iv.data[i] = 0;
        }
        return EXIT_SUCCESS;
    }
    else {
        return EXIT_FAILURE;
    }
}

int32_t aes_ctr::encrypt_update(uint8_t *out, const uint8_t *in, size_t len)
{
    phantom_vector<uint8_t> block(16);

    while (len > 0) {

        size_t use_len = (len < 16) ? len : 16;

        // Encrypt the IV
        m_aes->encrypt(block.data(), m_iv.data);

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

        // Increment the counter
        size_t idx = 15;
        m_iv.data[idx]++;
        while (0 == m_iv.data[idx]) {
            idx--;
            m_iv.data[idx]++;
        }

        len -= use_len;
        in  += 16;
        out += 16;
    }

    return EXIT_SUCCESS;
}

int32_t aes_ctr::encrypt_finish(uint8_t *out, const uint8_t *in, size_t len)
{
    (void) out;
    (void) in;
    (void) len;
    return EXIT_FAILURE;
}

int32_t aes_ctr::decrypt_start(const uint8_t *iv, size_t iv_len)
{
    return encrypt_start(iv, iv_len);
}

int32_t aes_ctr::decrypt_update(uint8_t *out, const uint8_t *in, size_t len)
{
    return encrypt_update(out, in, len);
}

int32_t aes_ctr::decrypt_finish(uint8_t *out, const uint8_t *in, size_t len)
{
    (void) out;
    (void) in;
    (void) len;
    return EXIT_FAILURE;
}

}  // namespace crypto
}  // namespace phantom
