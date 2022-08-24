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
#include "./phantom_memory.hpp"
#include "schemes/scheme.hpp"


namespace phantom
{

/**
 * @brief A pure abstract base class for Key Exchange
 */
class key_exchange : public scheme
{
public:
    virtual ~key_exchange() {}

    /// @brief Perform all setup and precomputation for the base point
    /// @param ctx The user context containing the key
    /// @return True on success, false otherwise
    virtual bool key_exchange_setup(std::unique_ptr<user_ctx>& ctx) = 0;

    /// @brief Generate a random key pair and exchange the public key
    /// @param ctx The user context containing the key
    /// @param m The output message containing the public key to be exchanged
    /// @return True on success, false otherwise
    virtual bool key_exchange_init(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& m) = 0;

    /// @brief Generate a shared key using the key pair and the recipient's public key
    /// @param ctx The user context containing the random key pair
    /// @param m The input message containing the receipient's public key to be exchanged
    /// @param shared_key The output shared key
    /// @return True on success, false otherwise
    virtual bool key_exchange_final(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& m,
        phantom_vector<uint8_t>& shared_key) = 0;
};

}  // namespace phantom
