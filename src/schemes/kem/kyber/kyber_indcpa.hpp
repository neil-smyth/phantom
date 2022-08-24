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
#include "crypto/csprng.hpp"
#include "core/reduction_montgomery.hpp"
#include "core/ntt_binary.hpp"
#include "sampling/gaussian_cdf.hpp"
#include "crypto/xof_sha3.hpp"
#include "./phantom.hpp"


namespace phantom {
namespace schemes {

/// Definitions for the Kyber parameters
struct kyber_set_t {
    uint16_t set;
    uint16_t q;
    uint16_t q_bits;
    uint16_t q_inv;
    uint16_t q_norm;
    uint16_t n;
    uint16_t n_bits;
    uint16_t k;
    uint16_t eta;
    uint16_t eta_bits;
    uint16_t d_u;
    uint16_t d_v;
    uint16_t d_t;
    uint16_t g;
    uint16_t inv_g;
    uint16_t R;
    uint16_t R2;
};

/// A class providing a Kyber IND-CPA PKE implementation
class kyber_indcpa
{
    using red_mont = core::reduction_montgomery<uint16_t>;
    using ntt_red_mont = core::ntt_binary<red_mont, uint16_t>;

public:
    /// Class constructor based on the required security strength
    explicit kyber_indcpa(security_strength_e bits);

    /// Class constructor based on the specified parameter set
    explicit kyber_indcpa(size_t set);

    /// Class destructor
    virtual ~kyber_indcpa();

    /// Kyber parameter sets
    static const kyber_set_t m_params[3];

    /// Convert security bits to a parameter set
    static size_t bits_2_set(security_strength_e bits);

    /// Key generation of the public key (rho,t) and the private key (s)
    void keygen(uint8_t* _RESTRICT_ rho, int16_t* _RESTRICT_ s, int16_t* _RESTRICT_ t);

    /// Public key encryption
    void enc(int16_t* _RESTRICT_ u, int16_t* _RESTRICT_ v, const uint16_t* _RESTRICT_ t_ntt,
        const uint8_t* _RESTRICT_ rho, size_t logn, size_t k, const uint8_t* _RESTRICT_ m);

    /// Public key decryption
    void dec(int16_t* _RESTRICT_ u, int16_t* _RESTRICT_ v,
        const uint16_t* _RESTRICT_ s, size_t logn, size_t key, uint8_t* _RESTRICT_ m);

    csprng* get_prng() { return m_prng.get(); }
    ntt_red_mont* get_ntt() { return m_ntt.get(); }
    crypto::xof_sha3* get_xof() { return m_xof.get(); }
    const core::reduction<red_mont, uint16_t>& get_reduction() { return m_reduction; }

private:
    // Initialize an instance of the PKE algorithm
    void init();

    void uniform_random_ring_q(size_t i, size_t j, const uint8_t* rho, uint16_t *a, size_t n,
        uint16_t q, size_t q_bits);
    void create_rand_product(uint16_t q, size_t q_bits, uint16_t * _RESTRICT_ t, int16_t * _RESTRICT_ y,
        size_t logn, size_t k, const uint8_t* rho, bool transposed);
    void binomial_rand_sample(uint16_t q, int16_t eta,
        int16_t *s, size_t n, size_t m);
    void binomial_rand_sample_shake128(uint16_t q, int16_t eta,
        int16_t *s, size_t n, size_t m);
    static void compress(int16_t *inout, size_t n, size_t k, size_t d,
        uint16_t q, uint16_t q_inv, uint16_t q_norm);
    static void decompress(int16_t *inout, size_t n, size_t k, size_t d, uint16_t q);
    static void map_message(int16_t* _RESTRICT_ v, const uint8_t* _RESTRICT_ m, size_t n, uint16_t q2);

    std::shared_ptr<csprng>           m_prng;
    std::unique_ptr<ntt_red_mont>     m_ntt;
    std::unique_ptr<crypto::xof_sha3> m_xof;

    const size_t m_set;
    const core::montgomery<uint16_t>          m_reduce;
    const core::reduction<red_mont, uint16_t> m_reduction;
};

}  // namespace schemes
}  // namespace phantom
