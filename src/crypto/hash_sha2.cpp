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
#include "./phantom_memory.hpp"


namespace phantom {
namespace crypto {


alignas(DEFAULT_MEM_ALIGNMENT) const uint32_t hash_sha2::k256[64] = {
    UINT32_C(0x428a2f98),
    UINT32_C(0x71374491),
    UINT32_C(0xb5c0fbcf),
    UINT32_C(0xe9b5dba5),
    UINT32_C(0x3956c25b),
    UINT32_C(0x59f111f1),
    UINT32_C(0x923f82a4),
    UINT32_C(0xab1c5ed5),
    UINT32_C(0xd807aa98),
    UINT32_C(0x12835b01),
    UINT32_C(0x243185be),
    UINT32_C(0x550c7dc3),
    UINT32_C(0x72be5d74),
    UINT32_C(0x80deb1fe),
    UINT32_C(0x9bdc06a7),
    UINT32_C(0xc19bf174),
    UINT32_C(0xe49b69c1),
    UINT32_C(0xefbe4786),
    UINT32_C(0x0fc19dc6),
    UINT32_C(0x240ca1cc),
    UINT32_C(0x2de92c6f),
    UINT32_C(0x4a7484aa),
    UINT32_C(0x5cb0a9dc),
    UINT32_C(0x76f988da),
    UINT32_C(0x983e5152),
    UINT32_C(0xa831c66d),
    UINT32_C(0xb00327c8),
    UINT32_C(0xbf597fc7),
    UINT32_C(0xc6e00bf3),
    UINT32_C(0xd5a79147),
    UINT32_C(0x06ca6351),
    UINT32_C(0x14292967),
    UINT32_C(0x27b70a85),
    UINT32_C(0x2e1b2138),
    UINT32_C(0x4d2c6dfc),
    UINT32_C(0x53380d13),
    UINT32_C(0x650a7354),
    UINT32_C(0x766a0abb),
    UINT32_C(0x81c2c92e),
    UINT32_C(0x92722c85),
    UINT32_C(0xa2bfe8a1),
    UINT32_C(0xa81a664b),
    UINT32_C(0xc24b8b70),
    UINT32_C(0xc76c51a3),
    UINT32_C(0xd192e819),
    UINT32_C(0xd6990624),
    UINT32_C(0xf40e3585),
    UINT32_C(0x106aa070),
    UINT32_C(0x19a4c116),
    UINT32_C(0x1e376c08),
    UINT32_C(0x2748774c),
    UINT32_C(0x34b0bcb5),
    UINT32_C(0x391c0cb3),
    UINT32_C(0x4ed8aa4a),
    UINT32_C(0x5b9cca4f),
    UINT32_C(0x682e6ff3),
    UINT32_C(0x748f82ee),
    UINT32_C(0x78a5636f),
    UINT32_C(0x84c87814),
    UINT32_C(0x8cc70208),
    UINT32_C(0x90befffa),
    UINT32_C(0xa4506ceb),
    UINT32_C(0xbef9a3f7),
    UINT32_C(0xc67178f2),
};

alignas(DEFAULT_MEM_ALIGNMENT) const uint64_t hash_sha2::k512[80] = {
    UINT64_C(0x428a2f98d728ae22),
    UINT64_C(0x7137449123ef65cd),
    UINT64_C(0xb5c0fbcfec4d3b2f),
    UINT64_C(0xe9b5dba58189dbbc),
    UINT64_C(0x3956c25bf348b538),
    UINT64_C(0x59f111f1b605d019),
    UINT64_C(0x923f82a4af194f9b),
    UINT64_C(0xab1c5ed5da6d8118),
    UINT64_C(0xd807aa98a3030242),
    UINT64_C(0x12835b0145706fbe),
    UINT64_C(0x243185be4ee4b28c),
    UINT64_C(0x550c7dc3d5ffb4e2),
    UINT64_C(0x72be5d74f27b896f),
    UINT64_C(0x80deb1fe3b1696b1),
    UINT64_C(0x9bdc06a725c71235),
    UINT64_C(0xc19bf174cf692694),
    UINT64_C(0xe49b69c19ef14ad2),
    UINT64_C(0xefbe4786384f25e3),
    UINT64_C(0x0fc19dc68b8cd5b5),
    UINT64_C(0x240ca1cc77ac9c65),
    UINT64_C(0x2de92c6f592b0275),
    UINT64_C(0x4a7484aa6ea6e483),
    UINT64_C(0x5cb0a9dcbd41fbd4),
    UINT64_C(0x76f988da831153b5),
    UINT64_C(0x983e5152ee66dfab),
    UINT64_C(0xa831c66d2db43210),
    UINT64_C(0xb00327c898fb213f),
    UINT64_C(0xbf597fc7beef0ee4),
    UINT64_C(0xc6e00bf33da88fc2),
    UINT64_C(0xd5a79147930aa725),
    UINT64_C(0x06ca6351e003826f),
    UINT64_C(0x142929670a0e6e70),
    UINT64_C(0x27b70a8546d22ffc),
    UINT64_C(0x2e1b21385c26c926),
    UINT64_C(0x4d2c6dfc5ac42aed),
    UINT64_C(0x53380d139d95b3df),
    UINT64_C(0x650a73548baf63de),
    UINT64_C(0x766a0abb3c77b2a8),
    UINT64_C(0x81c2c92e47edaee6),
    UINT64_C(0x92722c851482353b),
    UINT64_C(0xa2bfe8a14cf10364),
    UINT64_C(0xa81a664bbc423001),
    UINT64_C(0xc24b8b70d0f89791),
    UINT64_C(0xc76c51a30654be30),
    UINT64_C(0xd192e819d6ef5218),
    UINT64_C(0xd69906245565a910),
    UINT64_C(0xf40e35855771202a),
    UINT64_C(0x106aa07032bbd1b8),
    UINT64_C(0x19a4c116b8d2d0c8),
    UINT64_C(0x1e376c085141ab53),
    UINT64_C(0x2748774cdf8eeb99),
    UINT64_C(0x34b0bcb5e19b48a8),
    UINT64_C(0x391c0cb3c5c95a63),
    UINT64_C(0x4ed8aa4ae3418acb),
    UINT64_C(0x5b9cca4f7763e373),
    UINT64_C(0x682e6ff3d6b2b8a3),
    UINT64_C(0x748f82ee5defb2fc),
    UINT64_C(0x78a5636f43172f60),
    UINT64_C(0x84c87814a1f0ab72),
    UINT64_C(0x8cc702081a6439ec),
    UINT64_C(0x90befffa23631e28),
    UINT64_C(0xa4506cebde82bde9),
    UINT64_C(0xbef9a3f7b2c67915),
    UINT64_C(0xc67178f2e372532b),
    UINT64_C(0xca273eceea26619c),
    UINT64_C(0xd186b8c721c0c207),
    UINT64_C(0xeada7dd6cde0eb1e),
    UINT64_C(0xf57d4f7fee6ed178),
    UINT64_C(0x06f067aa72176fba),
    UINT64_C(0x0a637dc5a2c898a6),
    UINT64_C(0x113f9804bef90dae),
    UINT64_C(0x1b710b35131c471b),
    UINT64_C(0x28db77f523047d84),
    UINT64_C(0x32caab7b40c72493),
    UINT64_C(0x3c9ebe0a15c9bebc),
    UINT64_C(0x431d67c49c100d4c),
    UINT64_C(0x4cc5d4becb3e42b6),
    UINT64_C(0x597f299cfc657e2a),
    UINT64_C(0x5fcb6fab3ad6faec),
    UINT64_C(0x6c44198c4a475817)
};

alignas(DEFAULT_MEM_ALIGNMENT) const uint64_t i512[8] = {
    UINT64_C(0x6a09e667f3bcc908),
    UINT64_C(0xbb67ae8584caa73b),
    UINT64_C(0x3c6ef372fe94f82b),
    UINT64_C(0xa54ff53a5f1d36f1),
    UINT64_C(0x510e527fade682d1),
    UINT64_C(0x9b05688c2b3e6c1f),
    UINT64_C(0x1f83d9abfb41bd6b),
    UINT64_C(0x5be0cd19137e2179)
};

alignas(DEFAULT_MEM_ALIGNMENT) const uint64_t i384[8] = {
    UINT64_C(0xcbbb9d5dc1059ed8),
    UINT64_C(0x629a292a367cd507),
    UINT64_C(0x9159015a3070dd17),
    UINT64_C(0x152fecd8f70e5939),
    UINT64_C(0x67332667ffc00b31),
    UINT64_C(0x8eb44a8768581511),
    UINT64_C(0xdb0c2e0d64f98fa7),
    UINT64_C(0x47b5481dbefa4fa4)
};

alignas(DEFAULT_MEM_ALIGNMENT) const uint32_t i256[8] = {
    UINT32_C(0x6a09e667),
    UINT32_C(0xbb67ae85),
    UINT32_C(0x3c6ef372),
    UINT32_C(0xa54ff53a),
    UINT32_C(0x510e527f),
    UINT32_C(0x9b05688c),
    UINT32_C(0x1f83d9ab),
    UINT32_C(0x5be0cd19)
};

alignas(DEFAULT_MEM_ALIGNMENT) const uint32_t i224[8] = {
    UINT32_C(0xc1059ed8),
    UINT32_C(0x367cd507),
    UINT32_C(0x3070dd17),
    UINT32_C(0xf70e5939),
    UINT32_C(0xffc00b31),
    UINT32_C(0x68581511),
    UINT32_C(0x64f98fa7),
    UINT32_C(0xbefa4fa4)
};


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
        sha_core<uint32_t, 64, k256>(ctx);
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
        sha_core<uint64_t, 80, k512>(ctx);
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
        sha_core<uint32_t, 64, k256>(ctx);
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
    sha_core<uint32_t, 64, k256>(ctx);

    // Extract the hash value as bytes in case of misalignment
    static const uint8_t shift_lut[4] = {24, 16, 8, 0};
    size_t j = 0;
    for (i = 0; i < hlen; i++) {
        hval[i] = static_cast<uint8_t>(ctx->hash[i >> 2] >> shift_lut[j]);
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
        sha_core<uint64_t, 80, k512>(ctx);
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
    sha_core<uint64_t, 80, k512>(ctx);

    // Extract the hash value as bytes in case of misalignment
    static const uint8_t shift_lut[8] = {56, 48, 40, 32, 24, 16, 8, 0};
    size_t j = 0;
    for (i=0; i < hlen; i++) {
        hval[i] = static_cast<uint8_t>(ctx->hash[i >> 3] >> shift_lut[j]);
        j++;
        j &= 0x7;
    }
}


hash_sha2::hash_sha2()
{
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
