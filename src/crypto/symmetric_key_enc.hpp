/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include "./phantom.hpp"


namespace phantom {

/**
 * @defgroup symmetric Symmetric key encryption
 * 
 * All classes, types, etc. within this group are focused on symmetric key encryption.
 */


/**
 * @ingroup symmetric
 * @brief Symmetric Key Authenticated Encryption
 */
class symmetric_key_enc : public symmetric_key_ctx
{
public:
    virtual ~symmetric_key_enc() {}

    /// Return the underlying block cipher encryption object
    virtual symmetric_key_ctx* get_enc() = 0;

    /// Return the underlying block cipher decryption object
    virtual symmetric_key_ctx* get_dec() = 0;

    /// Return the counter value
    virtual uint8_t* get_ctr() = 0;

    /// A method to configure the keyspace
    virtual int32_t set_key(const uint8_t *key, size_t key_len) = 0;

    /// Encrypt an array of data using the specified symmetric cipher context
    /// {@
    virtual int32_t encrypt_start(const uint8_t *iv, size_t iv_len) = 0;
    virtual int32_t encrypt_update(uint8_t *out, const uint8_t *in, size_t len) = 0;
    virtual int32_t encrypt_finish(uint8_t *out, const uint8_t *in, size_t len) = 0;
    /// @}

    /// Decrypt an array of data using the specified symmetric cipher context
    /// {@
    virtual int32_t decrypt_start(const uint8_t *iv, size_t iv_len) = 0;
    virtual int32_t decrypt_update(uint8_t *out, const uint8_t *in, size_t len) = 0;
    virtual int32_t decrypt_finish(uint8_t *out, const uint8_t *in, size_t len) = 0;
    /// @}

};

}  // namespace phantom
