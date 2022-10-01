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

#include "schemes/signature/signature.hpp"
#include "schemes/signature/dilithium/dilithium.hpp"
#include "schemes/signature/dilithium/ctx_dilithium.hpp"
#include "crypto/csprng.hpp"
#include "core/reduction_montgomery.hpp"
#include "core/ntt_binary.hpp"
#include "crypto/xof_sha3.hpp"
#include "sampling/gaussian_cdf.hpp"


namespace phantom {
namespace schemes {

/// A class providing a Dilithium implementation
class dilithium_signature : public signature
{
    /// Dilithium specific using's for improved readability
    /// @{
    using reducer_dilithium   = core::montgomery<uint32_t>;
    using reduction_dilithium = core::reduction_montgomery<uint32_t>;
    using ntt_dilithium       = core::ntt_binary<reduction_dilithium, uint32_t>;
    /// @}

public:
    /// Class constructor
    dilithium_signature();

    /// Class destructor
    virtual ~dilithium_signature();

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

    /// Convert a security strength to a parameter set
    static size_t bits_2_set(security_strength_e bits);

    /// Generate a random sample with a uniform random distribution based on eta
    void uniform_rand_sample_small(dilithium *dil, const phantom_vector<uint8_t>& seed,
        uint32_t q, int32_t eta, size_t bits,
        int32_t *s, size_t n, size_t m, uint16_t nonce) const;

    /// Uniform random sampling of a ring of n elements
    void uniform_random_ring_q(dilithium* dil, uint8_t *seed,
                               uint16_t nonce, int32_t *a, size_t n, uint32_t q, uint32_t q_bits) const;

    /// Convert a polynomial ring to Montgomery representation
    void to_montgomery(ctx_dilithium& ctx, uint32_t *out, const int32_t *in, uint32_t q,
        size_t n, size_t offset) const;

    /// Convert a polynomial ring from Montgomery representation
    void from_montgomery(ctx_dilithium& ctx, int32_t *out, const uint32_t *in, uint32_t q,
        size_t n, size_t offset) const;

    /// Compute t = A * y, y is also translated to mod q+ (A is generated on-the-fly)
    void create_rand_product(ctx_dilithium& ctx, uint8_t *seed, uint32_t q, uint32_t q_bits,
        uint32_t *t, int32_t *y, size_t logn,
        size_t k, size_t l, uint32_t *c) const;

    /// Compute the product of the matrices A and y, where A has been precomputed
    void create_A_product(ctx_dilithium& ctx, uint32_t *w, int32_t *A, int32_t *y, uint32_t q,
        size_t n, size_t n_bits, size_t k, size_t l, uint32_t *c) const;

    /// Generate matrix A using rejection sampling
    void expand_A(ctx_dilithium& ctx, uint8_t *seed, uint32_t q, uint32_t q_bits, int32_t *A, size_t n,
        size_t k, size_t l) const;

    /// Check if the norm of v is greater than or equal to b, i.e. ||v|| >= b
    uint32_t check_norm_inf(const int32_t *v, size_t n, size_t l, uint32_t q, uint32_t b) const;
};

}  // namespace schemes
}  // namespace phantom


