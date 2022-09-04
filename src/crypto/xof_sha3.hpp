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
#include "crypto/xof.hpp"


namespace phantom {
namespace crypto {

/**
 * @ingroup hashing
 * @brief SHA-3 XOF
 * 
 * SHAKE-128 and SHAKE-256
 */
class xof_sha3 : public xof, keccak
{
public:
    xof_sha3();
    virtual ~xof_sha3();

    size_t get_length() const override;
    xof* get_copy() override;
    bool init(size_t len) override;
    void absorb(const uint8_t *data, size_t len) override;
    void final() override;
    void squeeze(uint8_t *data, size_t len) override;

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
