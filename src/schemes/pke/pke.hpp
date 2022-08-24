/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include "./phantom.hpp"
#include "schemes/scheme.hpp"


namespace phantom {

/**
 * @brief A pure abstract base class for Public Key Encryption
 */
class pke : public scheme
{
public:
    virtual ~pke() {}

    /// @brief Encryption of a message
    /// @param ctx The user context containing the key
    /// @param pt The input plaintext message to be encrypted
    /// @param ct The output ciphertext message
    /// @return True on success, false otherwise
    virtual bool encrypt(const std::unique_ptr<user_ctx>& ctx,
                         const phantom_vector<uint8_t> pt,
                         phantom_vector<uint8_t>& ct) = 0;

    /// @brief Decryption of a message
    /// @param ctx The user context containing the key
    /// @param ct The input ciphertext message to be decrypted
    /// @param pt The output plaintext message
    /// @return True on success, false otherwise
    virtual bool decrypt(const std::unique_ptr<user_ctx>& ctx,
                         const phantom_vector<uint8_t> ct,
                         phantom_vector<uint8_t>& pt) = 0;
};

}  // namespace phantom
