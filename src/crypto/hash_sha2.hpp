/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include "crypto/hash.hpp"
#include <limits>


namespace phantom {
namespace crypto {

#define SHA224_DIGEST_SIZE      28
#define SHA224_BLOCK_SIZE       64
#define SHA256_DIGEST_SIZE      32
#define SHA256_BLOCK_SIZE       64
#define SHA384_DIGEST_SIZE      48
#define SHA384_BLOCK_SIZE       128
#define SHA512_DIGEST_SIZE      64
#define SHA512_BLOCK_SIZE       128
#define SHA2_MAX_DIGEST_SIZE    SHA512_DIGEST_SIZE

#define SHA256_MASK             (SHA256_BLOCK_SIZE - 1)
#define SHA512_MASK             (SHA512_BLOCK_SIZE - 1)


/**
 * @ingroup hashing
 * @brief SHA-2 context
 * 
 * @tparam T A 32-bit (SHA2-224/256) or 64-bit (SHA2-384/512) unsigned integer type
 */
template<typename T>
struct sha2_ctx
{
    T count[2];
    T hash[8];
    T wbuf[16];
};

/**
 * @ingroup hashing
 * @brief NIST SHA-2.
 * Derived from the hash base class, supports SHA-224, SHA-256, SHA-384 and SHA-512.
 */
class hash_sha2 : public hash
{
public:
    hash_sha2();
    virtual ~hash_sha2();

    size_t get_length() const override;
    hash* get_copy() override;
    bool init(size_t len) override;
    void update(const uint8_t *data, size_t len) override;
    void final(uint8_t *data) override;

private:
    template<typename T>
    static inline T rotr(T x, size_t n) { return (x >> n) | (x << (std::numeric_limits<T>::digits - n)); }

    template<typename T>
    static inline T ch(T x, T y, T z) { return z ^ (x & (y ^ z)); }
    template<typename T>
    static inline T maj(T x, T y, T z) { return (x & y) | (z & (x ^ y)); }

    static inline void byteswap(uint32_t* p, size_t n);
    static inline void byteswap(uint64_t* p, size_t n);

    static inline uint32_t s_0(uint32_t x) { return (rotr(x,  2) ^ rotr(x, 13) ^ rotr(x, 22)); }
    static inline uint32_t s_1(uint32_t x) { return (rotr(x,  6) ^ rotr(x, 11) ^ rotr(x, 25)); }
    static inline uint32_t g_0(uint32_t x) { return (rotr(x,  7) ^ rotr(x, 18) ^ (x >>  3)); }
    static inline uint32_t g_1(uint32_t x) { return (rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)); }

    static inline uint64_t s_0(uint64_t x) { return (rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39)); }
    static inline uint64_t s_1(uint64_t x) { return (rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41)); }
    static inline uint64_t g_0(uint64_t x) { return (rotr(x,  1) ^ rotr(x,  8) ^ (x >>  7)); }
    static inline uint64_t g_1(uint64_t x) { return (rotr(x, 19) ^ rotr(x, 61) ^ (x >>  6)); }

    template<typename T>
    static inline T hf(size_t i, T* p) {
        return p[i & 15] += g_1(p[(i + 14) & 15]) + p[(i + 9) & 15] + g_0(p[(i + 1) & 15]);
    }

    template<typename T, const T* k, size_t i>
    static inline void v_cycle_0(T* p, T* v)
    {
        v[(7 - i) & 7] += p[i] + k[i] + s_1(v[(4 - i) & 7]) + ch(v[(4 - i) & 7], v[(5 - i) & 7], v[(6 - i) & 7]);
        v[(3 - i) & 7] += v[(7 - i) & 7];
        v[(7 - i) & 7] += s_0(v[(0 - i) & 7])+ maj(v[(0 - i) & 7], v[(1 - i) & 7], v[(2 - i) & 7]);
    }

    template<typename T, const T* k, size_t i>
    static inline void v_cycle(size_t j, T* p, T* v)
    {
        v[(7 - i) & 7] += hf(i, p) + k[i+j] + s_1(v[(4 - i) & 7]) + ch(v[(4 - i) & 7], v[(5 - i) & 7], v[(6 - i) & 7]);
        v[(3 - i) & 7] += v[(7 - i) & 7];
        v[(7 - i) & 7] += s_0(v[(0 - i) & 7])+ maj(v[(0 - i) & 7], v[(1 - i) & 7], v[(2 - i) & 7]);
    }

    template<typename T, size_t M, const T* k>
    static inline void sha_core(sha2_ctx<T>* ctx)
    {
        T *p = ctx->wbuf;
        alignas(DEFAULT_MEM_ALIGNMENT) T v[8];

        v[0] = ctx->hash[0];
        v[1] = ctx->hash[1];
        v[2] = ctx->hash[2];
        v[3] = ctx->hash[3];
        v[4] = ctx->hash[4];
        v[5] = ctx->hash[5];
        v[6] = ctx->hash[6];
        v[7] = ctx->hash[7];

        v_cycle_0<T, k,  0>(p, v);
        v_cycle_0<T, k,  1>(p, v);
        v_cycle_0<T, k,  2>(p, v);
        v_cycle_0<T, k,  3>(p, v);
        v_cycle_0<T, k,  4>(p, v);
        v_cycle_0<T, k,  5>(p, v);
        v_cycle_0<T, k,  6>(p, v);
        v_cycle_0<T, k,  7>(p, v);
        v_cycle_0<T, k,  8>(p, v);
        v_cycle_0<T, k,  9>(p, v);
        v_cycle_0<T, k, 10>(p, v);
        v_cycle_0<T, k, 11>(p, v);
        v_cycle_0<T, k, 12>(p, v);
        v_cycle_0<T, k, 13>(p, v);
        v_cycle_0<T, k, 14>(p, v);
        v_cycle_0<T, k, 15>(p, v);
        for (size_t i=16; i < M; i+=16) {
            v_cycle<T, k,  0>(i, p, v);
            v_cycle<T, k,  1>(i, p, v);
            v_cycle<T, k,  2>(i, p, v);
            v_cycle<T, k,  3>(i, p, v);
            v_cycle<T, k,  4>(i, p, v);
            v_cycle<T, k,  5>(i, p, v);
            v_cycle<T, k,  6>(i, p, v);
            v_cycle<T, k,  7>(i, p, v);
            v_cycle<T, k,  8>(i, p, v);
            v_cycle<T, k,  9>(i, p, v);
            v_cycle<T, k, 10>(i, p, v);
            v_cycle<T, k, 11>(i, p, v);
            v_cycle<T, k, 12>(i, p, v);
            v_cycle<T, k, 13>(i, p, v);
            v_cycle<T, k, 14>(i, p, v);
            v_cycle<T, k, 15>(i, p, v);
        }

        ctx->hash[0] += v[0];
        ctx->hash[1] += v[1];
        ctx->hash[2] += v[2];
        ctx->hash[3] += v[3];
        ctx->hash[4] += v[4];
        ctx->hash[5] += v[5];
        ctx->hash[6] += v[6];
        ctx->hash[7] += v[7];
    }

    void sha256_hash(const uint8_t* data, size_t len, sha2_ctx<uint32_t>* ctx);
    void sha512_hash(const uint8_t* data, size_t len, sha2_ctx<uint64_t>* ctx);
    void sha256_end(uint8_t* hval, sha2_ctx<uint32_t>* ctx, size_t hlen);
    void sha512_end(uint8_t* hval, sha2_ctx<uint64_t>* ctx, size_t hlen);

    alignas(DEFAULT_MEM_ALIGNMENT) union {
        sha2_ctx<uint32_t> ctx256;
        sha2_ctx<uint64_t> ctx512;
    } m_ctx;
    size_t m_sha2_len;

    alignas(DEFAULT_MEM_ALIGNMENT) static const uint32_t k256[64];
    alignas(DEFAULT_MEM_ALIGNMENT) static const uint64_t k512[80];
};

}  // namespace crypto
}  // namespace phantom
