/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "crypto/aes_gcm.hpp"
#include <algorithm>
#include <memory>
#include "crypto/aes_ctr.hpp"
#include "core/mp_gf2n.hpp"


namespace phantom {
namespace crypto {


alignas(DEFAULT_MEM_ALIGNMENT) const uint64_t aes_gcm::m_last4[16] = {
    0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
    0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0
};


aes_gcm::aes_gcm(aes_keylen_e key_len)
{
    // Create an AES encryption object to be used internally
    m_aes = std::unique_ptr<aes_encrypt>(aes_encrypt::make(key_len));
}

aes_gcm::~aes_gcm()
{
    // Erase all intermediate values
    memset(m_hh, 0, sizeof(m_hh));
    memset(m_hl, 0, sizeof(m_hl));
    memset(m_iv_enc, 0, sizeof(m_iv_enc));
    memset(m_authbuf, 0, sizeof(m_authbuf));

    // NOTE: m_iv is NOT erased as it is public data
}

aes_gcm* aes_gcm::make(aes_keylen_e key_len)
{
    return new aes_gcm(key_len);
}

int32_t aes_gcm::set_key(const uint8_t *key, size_t key_len)
{
    int32_t retval = EXIT_FAILURE;

    switch (key_len)
    {
        case 16: retval = m_aes->set_key(key, aes_keylen_e::AES_128); break;
        case 24: retval = m_aes->set_key(key, aes_keylen_e::AES_192); break;
        case 32: retval = m_aes->set_key(key, aes_keylen_e::AES_256); break;
        default: {}
    }

    if (EXIT_FAILURE == retval) {
        return EXIT_FAILURE;
    }

    // Encryption of a null block of all zero bytes
    phantom_vector<uint8_t> temp_storage(16);
    uint8_t *h  = temp_storage.data();
    uint64_t vh;
    uint64_t vl;
    m_aes->encrypt(h, h);

    GET_UINT64_BE(vh, h, 0);
    GET_UINT64_BE(vl, h, 8);
    memset(m_hh, 0, sizeof(m_hh));
    memset(m_hl, 0, sizeof(m_hl));
    m_hh[8] = vh;
    m_hl[8] = vl;

    for (size_t i = 4; i > 0; i >>= 1) {
        uint32_t T = (uint32_t)(vl & 1) * 0xe1000000U;
        vl  = (vh << 63) | (vl >> 1);
        vh  = (vh >> 1) ^ ( (uint64_t) T << 32);
        m_hl[i] = vl;
        m_hh[i] = vh;
    }
    for (size_t i = 2; i < 16; i <<= 1) {
        uint64_t *HiL = m_hl + i, *HiH = m_hh + i;
        vh = *HiH;
        vl = *HiL;
        for (size_t j = 1; j < i; j++) {
            HiH[j] = vh ^ m_hh[j];
            HiL[j] = vl ^ m_hl[j];
        }
    }

    return EXIT_SUCCESS;
}

void aes_gcm::gcm_mult(uint8_t* out, const uint8_t* in)
{
    uint8_t  lo = static_cast<uint8_t>(in[15] & 0x0f);
    uint8_t  hi = static_cast<uint8_t>(in[15] >> 4);
    uint64_t zh = m_hh[lo];
    uint64_t zl = m_hl[lo];

    uint8_t rem;
    for (int i = 15; i >= 0; i--) {
        lo = static_cast<uint8_t>(in[i] & 0x0f);
        hi = static_cast<uint8_t>(in[i] >> 4);

        if (i != 15) {
            rem = static_cast<uint8_t>(zl & 0x0f);
            zl = (zh << 60) | (zl >> 4);
            zh = (zh >> 4);
            zh ^= m_last4[rem] << 48;
            zh ^= m_hh[lo];
            zl ^= m_hl[lo];
        }

        rem = static_cast<uint8_t>(zl & 0x0f);
        zl = (zh << 60) | (zl >> 4);
        zh = (zh >> 4);
        zh ^= m_last4[rem] << 48;
        zh ^= m_hh[hi];
        zl ^= m_hl[hi];
    }

    PUT_UINT32_BE(zh >> 32, out, 0);
    PUT_UINT32_BE(zh, out, 4);
    PUT_UINT32_BE(zl >> 32, out, 8);
    PUT_UINT32_BE(zl, out, 12);
}

void aes_gcm::xor_block_16(uint8_t *out, const uint8_t *in1, const uint8_t *in2)
{
    out[0] = in1[0] ^ in2[0];
    out[1] = in1[1] ^ in2[1];
    out[2] = in1[2] ^ in2[2];
    out[3] = in1[3] ^ in2[3];
    out[4] = in1[4] ^ in2[4];
    out[5] = in1[5] ^ in2[5];
    out[6] = in1[6] ^ in2[6];
    out[7] = in1[7] ^ in2[7];
    out[8] = in1[8] ^ in2[8];
    out[9] = in1[9] ^ in2[9];
    out[10] = in1[10] ^ in2[10];
    out[11] = in1[11] ^ in2[11];
    out[12] = in1[12] ^ in2[12];
    out[13] = in1[13] ^ in2[13];
    out[14] = in1[14] ^ in2[14];
    out[15] = in1[15] ^ in2[15];
}

void aes_gcm::xor_block(uint8_t *out, const uint8_t *in1, const uint8_t *in2, size_t n)
{
    if (16 == n) {
        xor_block_16(out, in1, in2);
    }
    else {
        for (size_t i=0; i < n; i++) {
            out[i] = in1[i] ^ in2[i];
        }
    }
}

int32_t aes_gcm::encrypt_start(const uint8_t *iv, size_t iv_len,
    const uint8_t *aad, size_t aad_len)
{
    const uint8_t *p;
    alignas(DEFAULT_MEM_ALIGNMENT) uint8_t work_buf[16];
    memset(m_iv, 0x00, sizeof(m_iv) );
    memset(m_authbuf, 0x00, sizeof(m_authbuf) );

    m_length = 0;

    if (12 == iv_len) {
        std::copy(iv, iv + iv_len, m_iv);
        m_iv[15] = 1;
    }
    else {
        memset(work_buf, 0x00, 16);
        PUT_UINT32_BE(iv_len * 8, work_buf, 12);

        p = iv;
        while (iv_len > 0) {
            size_t use_len = (iv_len < 16) ? iv_len : 16;
            xor_block(m_iv, m_iv, p, use_len);
            gcm_mult(m_iv, m_iv);
            iv_len -= use_len;
            p += use_len;
        }

        xor_block_16(m_iv, m_iv, work_buf);
        gcm_mult(m_iv, m_iv);
    }

    // Encrypt the IV, encrypt the counter block and XOR with the input
    // block to form the output ciphertext
    m_aes->encrypt(m_iv_enc, m_iv);

    m_aad_len = aad_len;
    p = aad;
    while (aad_len > 0) {
        size_t use_len = (aad_len < 16) ? aad_len : 16;
        xor_block(m_authbuf, m_authbuf, p, use_len);
        gcm_mult(m_authbuf, m_authbuf);
        aad_len -= use_len;
        p += use_len;
    }

    return EXIT_SUCCESS;
}

int32_t aes_gcm::update(uint8_t *out, const uint8_t *in, size_t len, bool encrypt_flag)
{
    if (m_length & 0xf) {
        // Update cannot be called more than once for a length that is not
        // an integer number of blocks
        return EXIT_FAILURE;
    }

    // Increment the number of plaintext bytes consumed
    m_length += len;

    // Process each AES block sequentially
    while (len > 0) {
        size_t use_len = (len < 16) ? len : 16;

        if (!encrypt_flag) {
            // Update the authentication tag
            xor_block(m_authbuf, m_authbuf, in, use_len);
        }

        // Encrypt the IV, increment the counter block and XOR with the input
        // block to form the output ciphertext
        phantom_vector<uint8_t> block(16);

        // Increment the counter
        size_t idx = 15;
        m_iv[idx]++;
        while (0 == m_iv[idx]) {
            idx--;
            m_iv[idx]++;
        }

        // Encrypt the IV
        m_aes->encrypt(block.data(), m_iv);

        // XOR with input
        xor_block(out, block.data(), in, use_len);

        if (encrypt_flag) {
            // Update the authentication tag
            xor_block(m_authbuf, m_authbuf, out, use_len);
        }

        // GHASH
        gcm_mult(m_authbuf, m_authbuf);

        // Update the length and the I/O pointers
        len -= use_len;
        in  += use_len;
        out += use_len;
    }

    return EXIT_SUCCESS;
}

int32_t aes_gcm::encrypt_update(uint8_t *out, const uint8_t *in, size_t len)
{
    return update(out, in, len, true);
}

int32_t aes_gcm::encrypt_finish(uint8_t *tag, size_t tag_len)
{
    phantom_vector<uint8_t> work_buf(16);  // Cleared upon initialization
    uint64_t orig_len     = m_length * 8;
    uint64_t orig_aad_len = m_aad_len * 8;

    if (0 != tag_len) {
        // Copy the requisite number of tag bytes to the output
        std::copy(m_iv_enc, m_iv_enc + tag_len, tag);
    }

    if (orig_len || orig_aad_len) {
        // Inject the 64-bit length variables into the 128-bit working buffer
        // with big-endian ordering
        PUT_UINT32_BE((orig_aad_len >> 32), work_buf, 0);
        PUT_UINT32_BE((orig_aad_len),       work_buf, 4);
        PUT_UINT32_BE((orig_len     >> 32), work_buf, 8);
        PUT_UINT32_BE((orig_len),           work_buf, 12);

        // Add the working buffer to the accumulated authentication buffer, perform
        // GCM multiplication and then add to the output tag
        xor_block_16(m_authbuf, m_authbuf, work_buf.data());

        gcm_mult(m_authbuf, m_authbuf);
        xor_block(tag, tag, m_authbuf, tag_len);
    }

    return EXIT_SUCCESS;
}

int32_t aes_gcm::decrypt_start(const uint8_t *iv, size_t iv_len,
    const uint8_t *aad, size_t aad_len)
{
    return encrypt_start(iv, iv_len, aad, aad_len);
}

int32_t aes_gcm::decrypt_update(uint8_t *out, const uint8_t *in, size_t len)
{
    return update(out, in, len, false);
}

int32_t aes_gcm::decrypt_finish(uint8_t *tag, size_t tag_len)
{
    return encrypt_finish(tag, tag_len);
}

}  // namespace crypto
}  // namespace phantom
