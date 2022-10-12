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
#include "crypto/hash_sha3.hpp"
#include "crypto/xof_sha3.hpp"
#include "./phantom.hpp"


#define KYBER_SYMBYTES     32


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
    uint16_t eta1;
    uint16_t eta1_bits;
    uint16_t eta2;
    uint16_t d_u;
    uint16_t d_v;
    uint16_t d_t;
    uint16_t mont_inv;
    uint16_t R;
    uint16_t R2;
};

/// A class providing a Kyber IND-CPA PKE implementation
class kyber_indcpa
{
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
    void enc(int16_t* _RESTRICT_ u, int16_t* _RESTRICT_ v, const int16_t* _RESTRICT_ pk_t_ntt,
        const uint8_t* _RESTRICT_ pk_rho, const uint8_t *coins, size_t k, const uint8_t* _RESTRICT_ m);

    /// Public key decryption
    void dec(int16_t* _RESTRICT_ u, int16_t* _RESTRICT_ v,
        const int16_t* _RESTRICT_ s, size_t key, uint8_t* _RESTRICT_ m);

    csprng* get_prng() { return m_prng.get(); }
    crypto::xof_sha3* get_xof() { return m_xof.get(); }

private:
    // Initialize an instance of the PKE algorithm
    void init();

    static void compress(int16_t *inout, size_t n, size_t k, size_t d,
        uint16_t q, uint16_t q_inv, uint16_t q_norm);
    static void decompress(int16_t *inout, size_t n, size_t k, size_t d, uint16_t q);

    size_t reject_uniform(int16_t *r, size_t len, uint16_t q, const uint8_t *buf, size_t buflen);
    void gen_matrix(int16_t *a, const uint8_t *seed, bool transposed);
    void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
    void kyber_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce);

    void binomial_getnoise(int16_t *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce,
                           const uint16_t eta, const size_t n, const size_t k);

    static uint32_t load32_littleendian(const uint8_t x[4]);
    static uint32_t load24_littleendian(const uint8_t x[3]);

    static void cbd2(int16_t *r, const uint8_t *buf, const size_t n);
    static void cbd3(int16_t *r, const uint8_t *buf, const size_t n);

    static void map_msg_to_poly(int16_t *r, const uint8_t *msg, const uint16_t q, const size_t n);
    static void map_poly_to_msg(uint8_t *msg, const int16_t *a, const uint16_t q,
        const uint16_t q_inv, const uint16_t q_norm, const size_t n);

    std::shared_ptr<csprng>            m_prng;
    std::unique_ptr<crypto::xof_sha3>  m_xof;
    std::unique_ptr<crypto::hash_sha3> m_sha3;

    const size_t m_set;
};

}  // namespace schemes
}  // namespace phantom
