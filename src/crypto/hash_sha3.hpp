/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include "crypto/keccak.hpp"
#include "crypto/hash.hpp"


namespace phantom {
namespace crypto {

/**
 * @ingroup hashing
 * @brief NIST SHA-3
 * 
 * Derived from the hash base class, supports SHA3-224, SHA3-256, SHA3-384 and SHA3-512.
 */
class hash_sha3 : public hash, keccak
{
public:
    hash_sha3();
    virtual ~hash_sha3();

    size_t get_length() const override;
    hash* get_copy() override;
    bool init(size_t len) override;
    void update(const uint8_t *data, size_t len) override;
    void final(uint8_t *data) override;

private:
    const size_t m_rounds;
    union {
        uint8_t b[200];   ///< 8-bit bytes
        uint64_t q[25];   ///< 64-bit words
    } m_st;
    size_t m_pt;          ///< Byte pointer (modulo m_rsiz)
    size_t m_rsiz;        ///< State byte size
    size_t m_mdlen;       ///< Message digest length
};

}  // namespace crypto
}  // namespace phantom
