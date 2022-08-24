/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <memory>

#include "schemes/key_exchange/key_exchange.hpp"
#include "schemes/key_exchange/ecdh/ctx_ecdh.hpp"
#include "crypto/csprng.hpp"
#include "core/reduction_montgomery.hpp"
#include "./phantom.hpp"


namespace phantom {
namespace schemes {

/// A class providing a ECDH implementation
class ecdh_key_exchange : public key_exchange
{
public:
    /// Class constructor
    ecdh_key_exchange();

    /// Class destructor
    virtual ~ecdh_key_exchange();

    /// Create a context for the pkc instance based on the required security strength
    std::unique_ptr<user_ctx> create_ctx(security_strength_e strength, cpu_word_size_e size_hint) const override;

    /// Create a context for the pkc instance based on the parameter set
    std::unique_ptr<user_ctx> create_ctx(size_t set, cpu_word_size_e size_hint) const override;

    /// Key manipulation methods
    /// @{
    bool keygen(std::unique_ptr<user_ctx>& ctx) override;
    bool set_public_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k) override;
    bool get_public_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k) override;
    bool set_private_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k) override;
    bool get_private_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k) override;
    /// @}

    /// @brief Get the message length associated with the cryptosystem
    /// @param ctx The user context containing the key
    size_t get_msg_len(const std::unique_ptr<user_ctx>& ctx) const override;

    /// @brief Perform all setup and precomputation for the base point
    /// @param ctx The user context containing the key
    /// @return True on success, false otherwise
    bool key_exchange_setup(std::unique_ptr<user_ctx>& ctx) override;

    /// @brief Generate a random key pair and exchange the public key
    /// @param ctx The user context containing the key
    /// @param m The output message containing the public key to be exchanged
    /// @return True on success, false otherwise
    bool key_exchange_init(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& m) override;

    /// @brief Generate a shared key using the key pair and the recipient's public key
    /// @param ctx The user context containing the random key pair
    /// @param m The input message containing the receipient's public key to be exchanged
    /// @param shared_key The output shared key
    /// @return True on success, false otherwise
    bool key_exchange_final(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& m,
        phantom_vector<uint8_t>& shared_key) override;

private:
    static size_t bits_2_set(security_strength_e bits);

    std::shared_ptr<csprng>   m_prng;
};

}  // namespace schemes
}  // namespace phantom
