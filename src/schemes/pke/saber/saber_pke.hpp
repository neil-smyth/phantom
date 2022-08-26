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

#include "schemes/pke/pke.hpp"
#include "schemes/kem/saber/saber_indcpa.hpp"
#include "./phantom.hpp"


namespace phantom {
namespace schemes {

/// A class providing a saber implementation
class saber_pke : public pke
{
public:
    /// Class constructor
    saber_pke();

    /// Class destructor
    virtual ~saber_pke();

    /// Create a context for the pkc instance based on the required security strength
    std::unique_ptr<user_ctx> create_ctx(security_strength_e strength,
                                         cpu_word_size_e size_hint,
                                         bool masking = true) const override;

    /// Create a context for the pkc instance based on the parameter set
    std::unique_ptr<user_ctx> create_ctx(size_t set,
                                         cpu_word_size_e size_hint,
                                         bool masking = true) const override;


    /// Key manipulation methods
    /// @{
    bool keygen(std::unique_ptr<user_ctx>& ctx) override;
    bool set_public_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k) override;
    bool get_public_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k) override;
    bool set_private_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k) override;
    bool get_private_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k) override;
    /// @}

    /// @brief Encryption of a message
    /// @param ctx The user context containing the key
    /// @param pt The input plaintext message to be encrypted
    /// @param ct The output ciphertext message
    /// @return True on success, false otherwise
    bool encrypt(const std::unique_ptr<user_ctx>& ctx,
                 const phantom_vector<uint8_t> pt,
                 phantom_vector<uint8_t>& ct) override;

    /// @brief Decryption of a message
    /// @param ctx The user context containing the key
    /// @param ct The input ciphertext message to be decrypted
    /// @param pt The output plaintext message
    /// @return True on success, false otherwise
    bool decrypt(const std::unique_ptr<user_ctx>& ctx,
                 const phantom_vector<uint8_t> ct,
                 phantom_vector<uint8_t>& pt) override;

    /// @brief Get the message length associated with the cryptosystem
    /// @param ctx The user context containing the key
    size_t get_msg_len(const std::unique_ptr<user_ctx>& ctx) const override;
};

}  // namespace schemes
}  // namespace phantom
