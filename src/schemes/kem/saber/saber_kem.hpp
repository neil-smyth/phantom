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

#include "schemes/kem/kem.hpp"
#include "schemes/kem/saber/ctx_saber.hpp"
#include "schemes/kem/saber/saber_indcpa.hpp"
#include "crypto/csprng.hpp"
#include "core/reduction_montgomery.hpp"
#include "core/ntt_binary.hpp"
#include "sampling/gaussian_cdf.hpp"
#include "crypto/xof_sha3.hpp"
#include "crypto/hash.hpp"
#include "./phantom.hpp"


namespace phantom {
namespace schemes {

/// A class providing a Sabre implementation
class saber_kem : public kem
{
public:
    /// Class constructor
    saber_kem();

    /// Class destructor
    virtual ~saber_kem();

    /// Create a context for the pkc instance based on the required security strength
    std::unique_ptr<user_ctx> create_ctx(security_strength_e strength,
                                         cpu_word_size_e size_hint,
                                         bool masking = true) const override;

    /// Create a context for the pkc instance based on the parameter set
    std::unique_ptr<user_ctx> create_ctx(size_t set,
                                         cpu_word_size_e size_hint,
                                         bool masking = true) const override;

    /// @brief Set the logging level
    /// @param logging The enumerated log level value
    void set_logging(log_level_e logging) override;

    /// Key manipulation methods
    /// @{
    bool keygen(std::unique_ptr<user_ctx>& ctx) override;
    bool set_public_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k) override;
    bool get_public_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k) override;
    bool set_private_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k) override;
    bool get_private_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k) override;
    /// @}

    /// @brief Use a public key to encapsulate the ciphertext message c and output a shared key
    /// @param ctx The user context containing the key
    /// @param pk The public key associated with the other party
    /// @param c The output ciphertext message to be exchanged
    /// @param key The output shared key
    /// @return True on success, false otherwise
    bool encapsulate(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& pk,
        phantom_vector<uint8_t>& c, phantom_vector<uint8_t>& key) override;

    /// @brief Use a private key to decapsulate the ciphertext message c and output a shared key
    /// @param ctx The user context containing the key
    /// @param c The input ciphertext message to be exchanged
    /// @param key The output shared key
    /// @return True on success, false otherwise
    bool decapsulate(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& c,
        phantom_vector<uint8_t>& key) override;

    /// @brief Get the message length associated with the cryptosystem
    /// @param ctx The user context containing the key
    size_t get_msg_len(const std::unique_ptr<user_ctx>& ctx) const override;
};

}  // namespace schemes
}  // namespace phantom
