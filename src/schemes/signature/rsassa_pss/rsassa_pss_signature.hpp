/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <memory>

#include "schemes/signature/signature.hpp"
#include "rsa/rsa_cryptosystem_rsassa_pss.hpp"
#include "./phantom.hpp"


namespace phantom {
namespace schemes {

/// A class providing a RSASSA-PSS implementation
class rsassa_pss_signature : public signature
{
public:
    /// Class constructor
    rsassa_pss_signature();

    /// Class destructor
    virtual ~rsassa_pss_signature();

    /// Create a context for the pkc instance based on the required security strength
    std::unique_ptr<user_ctx> create_ctx(security_strength_e strength,
                                         cpu_word_size_e size_hint) const override;

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

    /// @brief Signing of a message
    /// @param ctx The user context containing the key
    /// @param m The input message to be signed
    /// @param s The output signature
    /// @return True on success, false otherwise
    bool sign(const std::unique_ptr<user_ctx>& ctx,
              const phantom_vector<uint8_t>& m,
              phantom_vector<uint8_t>& s) override;

    /// @brief Verification of a message
    /// @param ctx The user context containing the key
    /// @param m The input message to be signed
    /// @param s The input signature
    /// @return True on success, false otherwise
    bool verify(const std::unique_ptr<user_ctx>& ctx,
                const phantom_vector<uint8_t>& m,
                const phantom_vector<uint8_t>& s) override;

    /// @brief Get the message length associated with the cryptosystem
    /// @param ctx The user context containing the key
    size_t get_msg_len(const std::unique_ptr<user_ctx>& ctx) const override;

private:
    using signature::sign;
    using signature::verify;

    /// Convert security bits to a parameter set
    static size_t bits_2_set(security_strength_e bits);

    /// RSA parameter sets
    static const phantom::rsa::rsa_set_t m_params[17];
};

}  // namespace schemes
}  // namespace phantom
