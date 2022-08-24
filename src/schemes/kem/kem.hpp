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
 * @brief A pure abstract base class for Key Encapsulation Mechanisms
 */
class kem : public scheme
{
public:
    virtual ~kem() {}

    /// @brief Use a public key to encapsulate the ciphertext message c and output a shared key
    /// @param ctx The user context containing the key
    /// @param pk The public key associated with the other party
    /// @param c The output ciphertext message to be exchanged
    /// @param key The output shared key
    /// @return True on success, false otherwise
    virtual bool encapsulate(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& pk,
        phantom_vector<uint8_t>& c, phantom_vector<uint8_t>& key) = 0;

    /// @brief Use a private key to decapsulate the ciphertext message c and output a shared key
    /// @param ctx The user context containing the key
    /// @param c The input ciphertext message to be exchanged
    /// @param key The output shared key
    /// @return True on success, false otherwise
    virtual bool decapsulate(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& c,
        phantom_vector<uint8_t>& key) = 0;
};

}  // namespace phantom
