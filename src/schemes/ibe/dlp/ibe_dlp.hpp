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
#include <string>

#include "schemes/ibe/ibe.hpp"
#include "schemes/ibe/dlp/ctx_ibe_dlp.hpp"
#include "crypto/csprng.hpp"
#include "core/reduction_montgomery.hpp"
#include "core/ntt_binary.hpp"
#include "crypto/xof_sha3.hpp"
#include "sampling/gaussian_cdf.hpp"


namespace phantom {
namespace schemes {

/// A class providing a DLP IBE implementation
class ibe_dlp : public ibe
{
public:
    /// Class constructor#
    ibe_dlp();

    /// Class destructor
    virtual ~ibe_dlp();

    /// Create a context for the pkc instance based on the required security strength
    std::unique_ptr<user_ctx> create_ctx(security_strength_e bits,
                                         cpu_word_size_e size_hint,
                                         bool masking = true) const override;

    /// Create a context for the pkc instance based on the parameter set
    std::unique_ptr<user_ctx> create_ctx(size_t set,
                                         cpu_word_size_e size_hint,
                                         bool masking = true) const override;


    /// Key manipulation methods
    /// @{
    bool keygen(std::unique_ptr<user_ctx>& ctx) override;
    bool set_public_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& key) override;
    bool get_public_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& key) override;
    bool set_private_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& key) override;
    bool get_private_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& key) override;
    /// @}

    /// @brief Load an IBE User Key
    /// @param ctx The user context containing the key
    /// @param id The ID of the user
    /// @param key The output User Key
    /// @return True on success, false otherwise
    bool load_user_key(std::unique_ptr<user_ctx>& ctx,
                       const phantom_vector<uint8_t>& id,
                       const phantom_vector<uint8_t>& key) override;

    /// @brief Extract an IBE User Key
    /// @param ctx The user context containing the key
    /// @param id The ID of the user for which a User Key is being extracted
    /// @param key The output User Key
    /// @return True on success, false otherwise
    bool extract(std::unique_ptr<user_ctx>& ctx,
                 const phantom_vector<uint8_t>& id,
                 phantom_vector<uint8_t>& key) override;

    /// @brief Use a public key to encapsulate the ciphertext message c and output a shared key
    /// @param ctx The user context containing the key
    /// @param id The ID of the user for which a message will be encrypted
    /// @param m The message to be encrypted
    /// @param c The output ciphertext message to be exchanged
    /// @return True on success, false otherwise
    bool encrypt(std::unique_ptr<user_ctx>& ctx,
                 const phantom_vector<uint8_t>& id,
                 const phantom_vector<uint8_t>& from,
                 phantom_vector<uint8_t>& to) override;

    /// @brief Use a private key to decapsulate the ciphertext message c and output a shared key
    /// @param ctx The user context containing the key
    /// @param c The input ciphertext message that is exchanged
    /// @param m The output received message
    /// @return True on success, false otherwise
    bool decrypt(std::unique_ptr<user_ctx>& ctx,
                 const phantom_vector<uint8_t> from,
                 phantom_vector<uint8_t>& to) override;

    /// @brief Sign a message using the user's secret key
    /// @param ctx The user context containing the key
    /// @param m The input message
    /// @param s The output signature
    /// @return True on success, false otherwise
    bool sign(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t> m,
        phantom_vector<uint8_t>& s) override;

    /// @brief Verify a signature and its associated message
    /// @param ctx The user context containing the key
    /// @param id The public identity to use in verification
    /// @param m The input message
    /// @param s The input signature
    /// @return True on success, false otherwise
    bool verify(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& id,
        const phantom_vector<uint8_t> m, const phantom_vector<uint8_t> s) override;

    /// @brief Get the message length associated with the cryptosystem
    /// @param ctx The user context containing the key
    size_t get_msg_len(const std::unique_ptr<user_ctx>& ctx) const override;

private:
    /// Generate the key pair (f,g,F,G) and h
    static int32_t gen_keypair(std::unique_ptr<user_ctx>& ctx, int32_t* f, int32_t* g,
        int32_t* F, int32_t* G, int32_t* h, uint32_t* h_ntt);

    /// Convert a security strength to a parameter set
    static size_t bits_2_set(security_strength_e bits);

    static void id_function(crypto::xof_sha3 *xof, const uint8_t *id, size_t id_len,
        size_t logn, uint32_t q, int32_t *c);
    static void sign_h_function(crypto::xof_sha3 *xof, int32_t *a, const int32_t* x,
        const phantom_vector<uint8_t> m, size_t n);

    static void k_function(crypto::xof_sha3 *xof, uint8_t *k, size_t n);

    static void uniform_random_ring_q(crypto::xof_sha3 *xof, std::shared_ptr<csprng> prng, int32_t *a,
        size_t n, uint32_t q, size_t q_bits);
};

}  // namespace schemes
}  // namespace phantom
