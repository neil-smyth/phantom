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
#include "crypto/sha2.hpp"


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
    static inline void byteswap(uint32_t* p, size_t n);
    static inline void byteswap(uint64_t* p, size_t n);

    void sha256_hash(const uint8_t* data, size_t len, sha2_ctx<uint32_t>* ctx);
    void sha512_hash(const uint8_t* data, size_t len, sha2_ctx<uint64_t>* ctx);
    void sha256_end(uint8_t* hval, sha2_ctx<uint32_t>* ctx, size_t hlen);
    void sha512_end(uint8_t* hval, sha2_ctx<uint64_t>* ctx, size_t hlen);

    alignas(DEFAULT_MEM_ALIGNMENT) union {
        sha2_ctx<uint32_t> ctx256;
        sha2_ctx<uint64_t> ctx512;
    } m_ctx;
    size_t m_sha2_len;

    using sha256_core_method = void (*)(sha2_ctx<uint32_t>*);
    sha256_core_method m_sha256_core_method;
};

}  // namespace crypto
}  // namespace phantom
