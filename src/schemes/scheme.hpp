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


namespace phantom {

/**
 * @brief A pure abstract base class for all public key cryptography schemes
 */
class scheme
{
public:
    virtual ~scheme() {}

    /// Create a context for the pkc instance based on the required security strength
    virtual std::unique_ptr<user_ctx> create_ctx(security_strength_e strength, cpu_word_size_e size_hint) const = 0;

    /// Create a context for the pkc instance based on a specific parameter set
    virtual std::unique_ptr<user_ctx> create_ctx(size_t set, cpu_word_size_e size_hint) const = 0;

    /// @brief Key generation - creates a public/private key pair
    /// @param ctx The user context containing the key
    /// @return True on success, false otherwise
    virtual bool keygen(std::unique_ptr<user_ctx>& ctx) = 0;

    /// @brief Load an encoded public key into the specified user context
    /// @param ctx The user context containing the key
    /// @param k The input public key
    /// @return True on success, false otherwise
    virtual bool set_public_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k) = 0;

    /// @brief Retrieve a public key as an encoded byte array
    /// @param ctx The user context containing the key
    /// @param k The output public key
    /// @return True on success, false otherwise
    virtual bool get_public_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k) = 0;

    /// @brief Load an encoded private key into the specified user context
    /// @param ctx The user context containing the key
    /// @param k The input private key
    /// @return True on success, false otherwise
    virtual bool set_private_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k) = 0;

    /// @brief Retrieve a private key as an encoded byte array
    /// @param ctx The user context containing the key
    /// @param k The output private key
    /// @return True on success, false otherwise
    virtual bool get_private_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k) = 0;

    /// @brief Get the message length associated with the cryptosystem
    /// @param ctx The user context containing the key
    /// @return Message length
    virtual size_t get_msg_len(const std::unique_ptr<user_ctx>& ctx) const = 0;
};

}  // namespace phantom


