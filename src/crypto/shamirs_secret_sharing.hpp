/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <vector>
#include <cstdint>
#include <memory>
#include "crypto/csprng.hpp"
#include "./phantom_memory.hpp"

namespace phantom
{
/** 
 * @brief Shamir's Secret Sharing
 * 
 * Key sharing that divides a secret into n shares, reconstruction of the secret
 * requires k or more shares
 */
class shamirs_secret_sharing : public key_sharing
{
public:
    static const size_t key_bits = 256;
    static const size_t wordsize = 32;
    static const size_t key_words = key_bits / wordsize;
    static const size_t key_bytes = key_bits / 8;
    static const size_t shard_length = key_bytes + 1;

    explicit shamirs_secret_sharing(const std::shared_ptr<csprng>& prng);
    virtual ~shamirs_secret_sharing();

    virtual key_sharing_type_e get_keylen() {
        return KEY_SHARING_SHAMIRS;
    }

    virtual int32_t create(phantom_vector<uint8_t> *out, const uint8_t* key, size_t n, size_t k);
    virtual int32_t combine(uint8_t* key, const phantom_vector<uint8_t> *shares, size_t k);

private:
    static void bitslice(uint32_t r[key_words], const uint8_t x[key_bytes]);
    static void unbitslice(uint8_t r[key_bytes], const uint32_t x[key_words]);
    static void bitslice_single(uint32_t r[8], const uint8_t x);

    std::shared_ptr<csprng> m_prng;
};

}  // namespace phantom
