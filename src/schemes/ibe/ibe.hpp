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
 * @brief A pure abstract base class for Identity Based Encryption
 */
class ibe : public scheme
{
public:
    virtual ~ibe() {}

    /// @brief Load an IBE User Key
    /// @param ctx The user context containing the key
    /// @param id The ID of the user for which a User Key is being extracted
    /// @param key The output User Key
    /// @return True on success, false otherwise
    virtual bool load_user_key(std::unique_ptr<user_ctx>& ctx,
                               const phantom_vector<uint8_t>& id,
                               const phantom_vector<uint8_t>& key) = 0;

    /// @brief Extract an IBE User Key
    /// @param ctx The user context containing the key
    /// @param id The ID of the user for which a User Key is being extracted
    /// @param key The output User Key
    /// @return True on success, false otherwise
    virtual bool extract(std::unique_ptr<user_ctx>& ctx,
                         const phantom_vector<uint8_t>& id,
                         phantom_vector<uint8_t>& key) = 0;

    /// @brief Use a public key to encapsulate the ciphertext message c and output a shared key
    /// @param ctx The user context containing the key
    /// @param id The ID of the user for which a message will be encrypted
    /// @param m The message to be encrypted
    /// @param c The output ciphertext message to be exchanged
    /// @return True on success, false otherwise
    virtual bool encrypt(std::unique_ptr<user_ctx>& ctx,
                         const phantom_vector<uint8_t>& id,
                         const phantom_vector<uint8_t>& m,
                         phantom_vector<uint8_t>& c) = 0;

    /// @brief Use a private key to decapsulate the ciphertext message c and output a shared key
    /// @param ctx The user context containing the key
    /// @param c The input ciphertext message that is exchanged
    /// @param m The output received message
    /// @return True on success, false otherwise
    virtual bool decrypt(std::unique_ptr<user_ctx>& ctx,
                         const phantom_vector<uint8_t> c,
                         phantom_vector<uint8_t>& m) = 0;

    /// @brief Sign a message using the user's secret key
    /// @param ctx The user context containing the key
    /// @param m The input message
    /// @param s The output signature
    /// @return True on success, false otherwise
    virtual bool sign(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t> m,
        phantom_vector<uint8_t>& s) = 0;

    /// @brief Verify a signature and its associated message
    /// @param ctx The user context containing the key
    /// @param id The public identity to use in verification
    /// @param m The input message
    /// @param s The input signature
    /// @return True on success, false otherwise
    virtual bool verify(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& id,
        const phantom_vector<uint8_t> m, const phantom_vector<uint8_t> s) = 0;
};

}  // namespace phantom
