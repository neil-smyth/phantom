/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <memory>
#include "./phantom_types.hpp"
#include "crypto/aes.hpp"
#include "crypto/symmetric_key_enc.hpp"


namespace phantom {
namespace crypto {

/**
 * @ingroup symmetric
 * @brief AES Counter Mode encryption
 */
class aes_ctr : public symmetric_key_enc
{
public:
    virtual ~aes_ctr();

    static aes_ctr* make(aes_keylen_e key_len);

    /// Return the underlying block cipher encryption object
    virtual symmetric_key_ctx* get_enc();

    /// Return the underlying block cipher decryption object
    virtual symmetric_key_ctx* get_dec();

    /// Return the counter value
    virtual uint8_t* get_ctr();

    /// A method to configure the keyspace
    virtual int32_t set_key(const uint8_t *key, size_t key_len);

    /// Encrypt an array of data using the specified symmetric cipher context
    /// {@
    virtual int32_t encrypt_start(const uint8_t *iv, size_t iv_len);
    virtual int32_t encrypt_update(uint8_t *out, const uint8_t *in, size_t len);
    virtual int32_t encrypt_finish(uint8_t *out, const uint8_t *in, size_t len);
    /// @}

    /// Decrypt an array of data using the specified symmetric cipher context
    /// {@
    virtual int32_t decrypt_start(const uint8_t *iv, size_t iv_len);
    virtual int32_t decrypt_update(uint8_t *out, const uint8_t *in, size_t len);
    virtual int32_t decrypt_finish(uint8_t *out, const uint8_t *in, size_t len);
    /// @}

protected:
    explicit aes_ctr(aes_keylen_e key_len);

    /// A nonce struct for AES-CTR
    struct taes_ctr_nonce_ctr {
        uint8_t m_nonce[4];
        uint8_t m_iv[8];
        uint8_t m_ctr[4];
    };

    /// A union for an AES-CTR
    union taes_ctr_iv {
        taes_ctr_nonce_ctr components;
        uint8_t            data[16];
    };

    /// A union for access to bytes within a 32-bit word
    union u {
        uint8_t b[4];
        uint32_t w;
    };

    std::unique_ptr<aes_encrypt> m_aes;
    taes_ctr_iv m_iv;
};

}  // namespace crypto
}  // namespace phantom
