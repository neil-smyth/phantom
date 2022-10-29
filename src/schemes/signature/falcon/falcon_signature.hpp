/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <string>
#include <memory>

#include "schemes/signature/signature.hpp"
#include "schemes/signature/falcon/ctx_falcon.hpp"
#include "crypto/csprng.hpp"
#include "core/reduction_montgomery.hpp"
#include "core/ntt_binary.hpp"
#include "crypto/xof_sha3.hpp"
#include "sampling/gaussian_cdf.hpp"


namespace phantom {
namespace schemes {

/// A class providing a Falcon implementation
class falcon_signature : public signature
{
    /// Falcon specific using's for improved readability
    /// @{
    using reducer_falcon   = core::montgomery<uint32_t>;
    using reduction_falcon = core::reduction_montgomery<uint32_t>;
    using ntt_falcon       = core::ntt_binary<reduction_falcon, uint32_t>;
    /// @}

public:
    /// Class constructor
    falcon_signature();

    /// Class destructor
    virtual ~falcon_signature();

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
    bool set_public_key(std::unique_ptr<user_ctx>&, const phantom_vector<uint8_t>& key) override;
    bool get_public_key(std::unique_ptr<user_ctx>&, phantom_vector<uint8_t>& key) override;
    bool set_private_key(std::unique_ptr<user_ctx>&, const phantom_vector<uint8_t>& key) override;
    bool get_private_key(std::unique_ptr<user_ctx>&, phantom_vector<uint8_t>& key) override;
    /// @}

    /// @brief Signing of a message
    /// @param ctx The user context containing the key
    /// @param m The input message to be signed
    /// @param s The output signature
    /// @return True on success, false otherwise
    bool sign(const std::unique_ptr<user_ctx>&,
              const phantom_vector<uint8_t>& m,
              phantom_vector<uint8_t>& s) override;

    /// @brief Verification of a message
    /// @param ctx The user context containing the key
    /// @param m The input message to be signed
    /// @param s The input signature
    /// @return True on success, false otherwise
    bool verify(const std::unique_ptr<user_ctx>&,
                const phantom_vector<uint8_t>& m,
                const phantom_vector<uint8_t>& s) override;

    /// @brief Get the message length associated with the cryptosystem
    /// @param ctx The user context containing the key
    size_t get_msg_len(const std::unique_ptr<user_ctx>& ctx) const override;

private:
    using signature::sign;
    using signature::verify;

    static size_t bits_2_set(security_strength_e bits);

    /// Generate the key pair (f,g,F,G) and h
    static int32_t gen_keypair(std::unique_ptr<user_ctx>& ctx, int32_t* f, int32_t* g, int32_t* F, int32_t* G,
        int32_t* h, uint32_t* h_ntt);

    static void id_function(crypto::xof_sha3 *xof, const uint8_t *id, size_t id_len,
        size_t logn, uint32_t q, int32_t *c);

    static void sign_h_function(crypto::xof_sha3 *xof, int32_t *a, const int32_t* x,
        const phantom_vector<uint8_t> m, size_t n);
};

}  // namespace schemes
}  // namespace phantom


