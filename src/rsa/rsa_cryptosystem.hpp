/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <limits>
#include <memory>
#include <string>

#include "crypto/csprng.hpp"
#include "core/scalar_parser.hpp"
#include "rsa/ctx_rsa.hpp"
#include "./phantom.hpp"


namespace phantom {

namespace core {

template<typename T>
class mpz;

}  // namespace core

namespace rsa {


/// Definitions for the Kyber parameters
struct rsa_set_t {
    uint16_t set;
    uint16_t n_bits;
};

/// An enumerated type for RSA return codes
enum rsacode_e {
    RSA_OK = 0,
    RSA_ERROR,
    RSA_EXPONENT_IS_ZERO,
    RSA_RECODING_ERROR,
};

/**
 * @brief An RSA exponentiation base class
 * 
 * @tparam T Underlying data type
 */
template<typename T>
class rsa_cryptosystem
{
protected:
    static const size_t pre_width = 8;

    /// S ahred pointer to a CSPRNG
    std::shared_ptr<csprng> m_prng;

    /// 2^16 value used in an exponent range check by SP800 56B
    const core::mpz<T> m_e_2_16;

    /// 2^256 value used in an exponent range check by SP800 56B
    const core::mpz<T> m_e_2_256;

    /// 2^256/sqrt(2)
    const core::mpz<T> m_inv_sqrt2;

    /// The exponent recoding to be used
    const core::scalar_coding_e m_coding_type;

    /// A flag to indicate if square-and-multiply masking is required (default: true)
    const bool m_masking;

    /// Precomputed base values for use with exponent recoding
    std::unique_ptr<core::mpz<T>> m_base_pre[1 << pre_width];

public:
    /// Class constructor
    rsa_cryptosystem(core::scalar_coding_e coding = core::scalar_coding_e::SCALAR_BINARY,
                     bool masking = true);

    /// Class destructor
    virtual ~rsa_cryptosystem();

    /**
     * @brief Memory allocation for base values used with exponent recoding
     * 
     * @param cfg Modulus configuration and information for reduction
     */
    void precomputation_alloc(const core::mod_config<T>& cfg);

    /**
     * @brief Precomputation of values needed for suqre-and-multiply with exponent recoding
     * 
     * @param b Base value
     * @param cfg Modulus configuration and information for reduction
     * @return bool True on success, flaseon failure
     */
    bool precomputation(const core::mpz<T>& b, const core::mod_config<T>& cfg);

    /**
     * @brief Key generation for the given context
     * 
     * @param ctx RSA context
     * @return true Success
     * @return false Failure
     */
    virtual bool keygen(ctx_rsa_tmpl<T>& ctx);

    /**
     * @brief Set the public key and initialize reduction
     * 
     * The public key is stored internally as JSON n and e parameters.
     * 
     * @param ctx RSA context
     * @param k Public key
     * @return true Success
     * @return false Failure
     */
    virtual bool set_public_key(ctx_rsa_tmpl<T>& ctx, const phantom_vector<uint8_t>& k);

    /**
     * @brief Get the public key
     * 
     * @param ctx RSA context
     * @param k Key encoded
     * @return true Success
     * @return false Failure
     */
    virtual bool get_public_key(ctx_rsa_tmpl<T>& ctx, phantom_vector<uint8_t>& k);

    /**
     * @brief Set the private key (and public key) and initialize reduction
     * 
     * The private and public key are stored internally as JSON n, e, d, p, q, exp1, exp2and inv parameters.
     * 
     * @param ctx RSA context
     * @param k Private key
     * @return true Success
     * @return false Failure
     */
    virtual bool set_private_key(ctx_rsa_tmpl<T>& ctx, const phantom_vector<uint8_t>& k);

    /**
     * @brief Get the private key (and public key)
     * 
     * @param ctx RSA context
     * @param k Private key
     * @return true Success
     * @return false Failure
     */
    virtual bool get_private_key(ctx_rsa_tmpl<T>& ctx, phantom_vector<uint8_t>& k);

protected:

    /**
     * @brief Key generation as per SP800 56B
     * 
     * @param[out] p RSA secret prime p
     * @param[out] q RSA secret prime q with p < q
     * @param[in] e RSA public exponent e
     * @param nbits 
     * @return true Success
     * @return false Failure
     */
    virtual bool keygen_sp800_56b(core::mpz<T>& p, core::mpz<T>& q, const core::mpz<T>& e, size_t nbits);

    /**
     * @brief Mask generation function MGF1 from PKCS #1
     * 
     * @param[in] h Pointer to a suitable hash function
     * @param[out] mask The generated mask byte array
     * @param hblocklen The blocklength used by the hash function
     * @param hlen Hash length
     * @param[in] seed Seed bytes
     * @param masklen Mask length to be produced
     * @return true Success
     * @return false Failure
     */
    static bool mgf1(crypto::hash* h, phantom_vector<uint8_t>& mask, size_t hblocklen, size_t hlen,
        const phantom_vector<uint8_t>& seed, size_t masklen);

    /**
     * @brief Octet Stream to Integer Primitive from PKCS #11
     * 
     * @param i Integer represented as a multiple precision integer
     * @param os Octet stream represented as a byte vector
     */
    static void os2ip(core::mpz<T>& i, const phantom_vector<uint8_t>& os);

    /**
     * @brief Integer to Octet Stream Primitive from PKCS #1
     * 
     * @param os Octet stream represented as a byte vector
     * @param i Integer represented as a multiple precision integer
     * @param k Maximum byte length of the octet stream (i.e. the modulus length in bytes)
     */
    static void i2osp(phantom_vector<uint8_t>& os, const core::mpz<T>& i, size_t k);

    /**
     * @brief Low-level RSA exponentiation, r = b^e mod n
     * 
     * @param r Result
     * @param b Base
     * @param e Exponent
     * @param cfg Modulus configuration
     * @return rsacode_e Enumerated return code, RSA_OK indicates success
     */
    virtual rsacode_e exponentiation(core::mpz<T>& r, core::mpz<T>& b, const core::mpz<T>& e,
        const core::mod_config<T>& cfg);

    /**
     * @brief Unmasked square-and-multiply exponentiation
     * 
     * @param r Result
     * @param b Base
     * @param bitgen A reference to the scalar_parser object used to encode the exponent
     * @param num_bits The number of bits in the encoded scalar
     * @param w The window size
     * @param sub_offset An offset to negative pre-computed points
     * @param cfg Modulus configuration
     * @return rsacode_e Enumerated return code, RSA_OK indicates success
     */
    rsacode_e square_and_multiply(core::mpz<T>& r, const core::mpz<T>& b, core::scalar_parser& bitgen,
        size_t num_bits, size_t w, size_t sub_offset, const core::mod_config<T>& cfg);

    /**
     * @brief Constant-time swap of two pointers
     * @param swap Flag indicating if swap should occur
     * @param s Pointer to swap
     * @param r Pointer to swap
     */
    void cswap(bool swap, intptr_t& s, intptr_t& r);

    /**
     * @brief Montgomer ladder exponentiation
     * 
     * @param r Result
     * @param b Base
     * @param bitgen A reference to the scalar_parser object used to encode the exponent
     * @param num_bits The number of bits in the encoded scalar
     * @param w Unused
     * @param sub_offset Unused
     * @param cfg Modulus configuration
     * @return rsacode_e Enumerated return code, RSA_OK indicates success
     */
    rsacode_e montgomery_ladder(core::mpz<T>& r, const core::mpz<T>& b, core::scalar_parser& bitgen,
        size_t num_bits, size_t w, size_t sub_offset, const core::mod_config<T>& cfg);

    /**
     * @brief RSA public exponentiation, c = m^e mod n
     * 
     * @param ctx RSA context
     * @param m Message
     * @param c Ciphertext
     * @return true Success
     * @return false Failure
     */
    virtual bool rsa_public_exponentiation(ctx_rsa_tmpl<T>& ctx, core::mpz<T> m, core::mpz<T>& c);

    /**
     * @brief RSA private exponentiation, m = c^d mod n
     * 
     * @param ctx RSA context
     * @param c Ciphertext
     * @param m Message
     * @return true Success
     * @return false Failure
     */
    virtual bool rsa_private_exponentiation(ctx_rsa_tmpl<T>& ctx, core::mpz<T> c, core::mpz<T>& m);

    /**
     * @brief Verify that p - q is not too close
     * 
     * @param p RSA secret prime p
     * @param q RSA secret prime q with p < q
     * @param nbits Length of the modulus n in bits
     * @return true Success
     * @return false Failure
     */
    static bool check_pminusq_diff(const core::mpz<T>& p, const core::mpz<T>& q, int nbits);

    /**
     * @brief Generate a probable prime
     * 
     * @param[out] prime Prime number
     * @param[out] xpout Random number used in prime generation
     * @param[out] p1 Auxiliary prime 1
     * @param[out] p2 Auxiliary prime 2
     * @param e Auxiliary prime 2
     * @param nbits Length of the modulus n in bits
     * @return true Success
     * @return false Failure
     */
    virtual bool gen_probable_prime(core::mpz<T>& prime, core::mpz<T>& xpout, core::mpz<T>& p1, core::mpz<T>& p2,
        const core::mpz<T>& e, size_t nbits);

    /**
     * @brief Find an auxiliary probable prime from an array of random bits
     * 
     * @param[out] p1 Auxiliary prime
     * @param xp1 Random byte array
     */
    virtual void find_aux_prob_prime(core::mpz<T>& p1, const core::mpz<T>& xp1);

    /**
     * @brief Find an auxiliary probable prime from an array of random bits
     * 
     * @param[out] p1 Auxiliary prime
     * @param xp1 Random byte array
     */
    virtual bool derive_prime(core::mpz<T>& prime_factor, core::mpz<T>& rand_out,
        const core::mpz<T>& aux_prime_1, const core::mpz<T>& aux_prime_2, const core::mpz<T>& e, size_t nbits);

    /**
     * @brief Get the (Cryptographically Secure) PRNG
     * 
     * @return std::shared_ptr<csprng> CSPRNG
     */
    std::shared_ptr<csprng> get_prng();
};


// Forward declaration of common sizes
extern template class rsa_cryptosystem<uint8_t>;
extern template class rsa_cryptosystem<uint16_t>;
extern template class rsa_cryptosystem<uint32_t>;
#if defined(IS_64BIT)
extern template class rsa_cryptosystem<uint64_t>;
#endif

}  // namespace rsa
}  // namespace phantom
