/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "crypto/hash_sha2.hpp"
#include <algorithm>
#include <climits>
#include "crypto/sha2_core_generic.hpp"
#include "crypto/sha2_core_ni.hpp"
#include "./phantom_memory.hpp"


namespace phantom {
namespace crypto {


void hash_sha2::byteswap(uint32_t* p, size_t n)
{
#if PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN
    while (n--) {
        p[n] = bswap_32(p[n]);
    }
#else
    (void) p;
    (void) n;
#endif
}

void hash_sha2::byteswap(uint64_t* p, size_t n)
{
#if PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN
    while (n--) {
        p[n] = bswap_64(p[n]);
    }
#else
    (void) p;
    (void) n;
#endif
}

void hash_sha2::sha256_hash(const uint8_t* data, size_t len, sha2_ctx<uint32_t>* ctx)
{
    size_t pos = (ctx->count[0] >> 3) & SHA256_MASK;
    const uint8_t *sp = data;
    uint8_t *w = reinterpret_cast<uint8_t*>(ctx->wbuf);

    if ((ctx->count[0] += 8 * len) < 8 * len) {
        ctx->count[1]++;
    }

    // Data is always byte aligned
    uint32_t space = SHA256_BLOCK_SIZE - pos;

    // Copy bytes into the working block and update the hash
    while (len >= space) {
        len -= space;
        std::copy(sp, sp + space, w + pos);
        sp += space;
        space = SHA256_BLOCK_SIZE;
        byteswap(reinterpret_cast<uint32_t*>(w), SHA256_BLOCK_SIZE >> 2);
        m_sha256_core_method(ctx);
        pos = 0;
    }

    // Copy any remaining bytes into the working buffer for later use
    std::copy(sp, sp + len, w + pos);
}

void hash_sha2::sha512_hash(const uint8_t* data, size_t len, sha2_ctx<uint64_t>* ctx)
{
    size_t pos = (ctx->count[0] >> 3) & SHA512_MASK;
    const uint8_t *sp = data;
    uint8_t *w = reinterpret_cast<uint8_t*>(ctx->wbuf);

    if ((ctx->count[0] += 8 * len) < 8 * len) {
        ctx->count[1]++;
    }

    // Data is always byte aligned
    uint32_t space = SHA512_BLOCK_SIZE - pos;

    // Copy bytes into the working block and update the hash
    while (static_cast<int>(len - space) >= 0) {
        len -= space;
        std::copy(sp, sp + space, w + pos);
        sp += space;
        space = SHA512_BLOCK_SIZE;
        byteswap(reinterpret_cast<uint64_t*>(w), SHA512_BLOCK_SIZE >> 3);
        sha2_core_generic::core<uint64_t, 80, k512>(ctx);
        pos = 0;
    }

    // Copy any remaining bytes into the working buffer for later use
    std::copy(sp, sp + len, w + pos);
}

void hash_sha2::sha256_end(uint8_t* hval, sha2_ctx<uint32_t>* ctx, size_t hlen)
{
    size_t i = static_cast<size_t>((ctx->count[0] >> 3) & SHA256_MASK);

    // Put bytes in the buffer in an order in which references to
    // 32-bit words will put bytes with lower addresses into the
    // top of 32 bit words on BOTH big and little endian machines
    byteswap(reinterpret_cast<uint32_t*>(ctx->wbuf), (i + 4) >> 2);

    // One-and-zeroes padding (always byte aligned)
    size_t shift = 8 * (~i & 3);
    ctx->wbuf[i >> 2] &= UINT32_C(0xffffff80) << shift;
    ctx->wbuf[i >> 2] |= UINT32_C(0x80) << shift;

    // 9 or more empty working positions are needed: the padding byte
    // and 8 length bytes. If not pad and empty the working buffer.
    if (i > (SHA256_BLOCK_SIZE - 9)) {
        if (i < 60) {
            ctx->wbuf[15] = 0;
        }
        m_sha256_core_method(ctx);
        i = 0;
    }
    else {
        // Set the working buffer index for the empty positions
        i = (i >> 2) + 1;
    }

    // Zero pad all but last two (32-bit) count positions
    while (i < 14) {
        ctx->wbuf[i++] = 0;
    }

    // NOTE: Little-endian words are corrected when used in sha_core
    ctx->wbuf[14] = ctx->count[1];
    ctx->wbuf[15] = ctx->count[0];
    m_sha256_core_method(ctx);

    // Extract the hash value as bytes in case of misalignment
    static const uint8_t shift_lut[4] = {24, 16, 8, 0};
    size_t j = 0;
    for (i = 0; i < hlen; i++) {
        hval[i] = ctx->hash[i >> 2] >> shift_lut[j];
        j++;
        j &= 0x3;
    }
}

void hash_sha2::sha512_end(uint8_t* hval, sha2_ctx<uint64_t>* ctx, size_t hlen)
{
    size_t i = static_cast<size_t>((ctx->count[0] >> 3) & SHA512_MASK);

    // Put bytes in the buffer in an order in which references to
    // 32-bit words will put bytes with lower addresses into the
    // top of 32 bit words on BOTH big and little endian machines
    byteswap(reinterpret_cast<uint64_t*>(ctx->wbuf), (i + 8) >> 3);

    // One-and-zeros padding (always byte aligned)
    size_t shift = 8 * (~i & 7);
    ctx->wbuf[i >> 3] &= UINT64_C(0xffffffffffffff80) << shift;
    ctx->wbuf[i >> 3] |= UINT64_C(0x80) << shift;

    // 17 or more empty working positions are needed: the padding byte
    // and 16 length bytes. If not pad and empty the working buffer.
    if (i > (SHA512_BLOCK_SIZE - 17)) {
        if (i < 120) {
            ctx->wbuf[15] = 0;
        }
        sha2_core_generic::core<uint64_t, 80, k512>(ctx);
        i = 0;
    }
    else {
        i = (i >> 3) + 1;
    }

    // Zero pad all but last two positions
    while (i < 14) {
        ctx->wbuf[i++] = 0;
    }

    // NOTE: Little-endian words are corrected when used in sha_core
    ctx->wbuf[14] = ctx->count[1];
    ctx->wbuf[15] = ctx->count[0];
    sha2_core_generic::core<uint64_t, 80, k512>(ctx);

    // Extract the hash value as bytes in case of misalignment
    static const uint8_t shift_lut[8] = {56, 48, 40, 32, 24, 16, 8, 0};
    size_t j = 0;
    for (i=0; i < hlen; i++) {
        hval[i] = ctx->hash[i >> 3] >> shift_lut[j];
        j++;
        j &= 0x7;
    }
}


hash_sha2::hash_sha2()
{
    if (sha2_core_ni::has_sha_ni()) {
        m_sha256_core_method = sha2_core_ni::core;
    }
    else {
        m_sha256_core_method = sha2_core_generic::core<uint32_t, 64, k256>;
    }
}

hash_sha2::~hash_sha2()
{
}

size_t hash_sha2::get_length() const
{
    return m_sha2_len;
}

hash* hash_sha2::get_copy()
{
    hash_sha2* copy = new hash_sha2();
    copy->m_ctx = m_ctx;
    copy->m_sha2_len = m_sha2_len;
    return copy;
}

bool hash_sha2::init(size_t len)
{
    switch (len)
    {
        case 224:
        case  28: m_ctx.ctx256.count[0] = m_ctx.ctx256.count[1] = 0;
                  std::copy(i224, i224 + 8, m_ctx.ctx256.hash);
                  m_sha2_len = 28;
                  return true;
        case 256:
        case  32: m_ctx.ctx256.count[0] = m_ctx.ctx256.count[1] = 0;
                  std::copy(i256, i256 + 8, m_ctx.ctx256.hash);
                  m_sha2_len = 32;
                  return true;
        case 384:
        case  48: m_ctx.ctx512.count[0] = m_ctx.ctx512.count[1] = 0;
                  std::copy(i384, i384 + 8, m_ctx.ctx512.hash);
                  m_sha2_len = 48;
                  return true;
        case 512:
        case  64: m_ctx.ctx512.count[0] = m_ctx.ctx512.count[1] = 0;
                  std::copy(i512, i512 + 8, m_ctx.ctx512.hash);
                  m_sha2_len = 64;
                  return true;
        default:  return false;
    }
}

void hash_sha2::update(const uint8_t *data, size_t len)
{
    switch (m_sha2_len)
    {
        case 28: sha256_hash(data, len, &m_ctx.ctx256); break;
        case 32: sha256_hash(data, len, &m_ctx.ctx256); break;
        case 48: sha512_hash(data, len, &m_ctx.ctx512); break;
        case 64: sha512_hash(data, len, &m_ctx.ctx512); break;
    }
}

void hash_sha2::final(uint8_t *data)
{
    switch (m_sha2_len)
    {
        case 28: sha256_end(data, &m_ctx.ctx256, SHA224_DIGEST_SIZE); break;
        case 32: sha256_end(data, &m_ctx.ctx256, SHA256_DIGEST_SIZE); break;
        case 48: sha512_end(data, &m_ctx.ctx512, SHA384_DIGEST_SIZE); break;
        case 64: sha512_end(data, &m_ctx.ctx512, SHA512_DIGEST_SIZE); break;
    }
}

}  // namespace crypto
}  // namespace phantom
