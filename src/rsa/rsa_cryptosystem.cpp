/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include "rsa/rsa_cryptosystem.hpp"
#include <limits>
#include <memory>
#include <string>

#include <iostream>
#include <sstream>

#include "crypto/csprng.hpp"
#include "crypto/random_seed.hpp"
#include "core/scalar_parser.hpp"
#include "core/mpz.hpp"
#include "rsa/ctx_rsa.hpp"
#include "./phantom.hpp"
#include <nlohmann/json.hpp>


using json = nlohmann::json;


namespace phantom {
namespace rsa {


/// Class constructor
template<typename T>
rsa_cryptosystem<T>::rsa_cryptosystem(core::scalar_coding_e coding, bool masking)
    : m_e_2_16("10000", 16),
      m_e_2_256("100000000", 16),
      m_inv_sqrt2("b504f333f9df16e717f7ce02303e69cd2d040bb5b7bd8e638f26d2ef9cadb727", 16),
      m_coding_type(masking ? core::scalar_coding_e::SCALAR_MONT_LADDER : coding),
      m_masking(masking)
{
    m_prng = std::shared_ptr<csprng>(csprng::make(0x10000000, random_seed::seed_cb));
}

/// Class destructor
template<typename T>
rsa_cryptosystem<T>::~rsa_cryptosystem()
{
}

/**
 * @brief Memory allocation for base values used with exponent recoding
 * 
 * @param cfg Modulus configuration and information for reduction
 */
template<typename T>
void rsa_cryptosystem<T>::precomputation_alloc(const core::mod_config<T>& cfg)
{
    m_base_pre[0] = std::unique_ptr<core::mpz<T>>(new core::mpz<T>());

    switch (m_coding_type)
    {
        case core::scalar_coding_e::SCALAR_BINARY_DUAL:
        {
            m_base_pre[1] = std::unique_ptr<core::mpz<T>>(new core::mpz<T>());
            m_base_pre[2] = std::unique_ptr<core::mpz<T>>(new core::mpz<T>());
        } break;

        case core::scalar_coding_e::SCALAR_NAF_2:
        case core::scalar_coding_e::SCALAR_NAF_3:
        case core::scalar_coding_e::SCALAR_NAF_4:
        case core::scalar_coding_e::SCALAR_NAF_5:
        case core::scalar_coding_e::SCALAR_NAF_6:
        case core::scalar_coding_e::SCALAR_NAF_7:
        {
            size_t w = (1 << ((static_cast<size_t>(m_coding_type) ^ SCALAR_CODING_NAF_BIT) - 1)) - 1;

            for (size_t i=1; i < 2*w; i++) {
                m_base_pre[i] = std::unique_ptr<core::mpz<T>>(new core::mpz<T>());
            }
        } break;

        case core::scalar_coding_e::SCALAR_PRE_2:
        case core::scalar_coding_e::SCALAR_PRE_3:
        case core::scalar_coding_e::SCALAR_PRE_4:
        case core::scalar_coding_e::SCALAR_PRE_5:
        case core::scalar_coding_e::SCALAR_PRE_6:
        case core::scalar_coding_e::SCALAR_PRE_7:
        case core::scalar_coding_e::SCALAR_PRE_8:
        {
            size_t w = (1 << (static_cast<size_t>(m_coding_type) ^ SCALAR_CODING_PRE_BIT));

            for (size_t i=1; i < w; i++) {
                m_base_pre[i] = std::unique_ptr<core::mpz<T>>(new core::mpz<T>());
            }
        } break;

        default: {}
    }
}

/**
 * @brief Precomputation of values needed for suqre-and-multiply with exponent recoding
 * 
 * @param b Base value
 * @param cfg Modulus configuration and information for reduction
 * @return bool True on success, flaseon failure
 */
template<typename T>
bool rsa_cryptosystem<T>::precomputation(const core::mpz<T>& b, const core::mod_config<T>& cfg)
{
    m_base_pre[0]->set(b);

    // Transform base value to Montgomery domain
    if (core::REDUCTION_MONTGOMERY == cfg.reduction) {
        m_base_pre[0]->mul_mont(cfg.mont_R2, cfg);
    }

    switch (m_coding_type)
    {
        case core::scalar_coding_e::SCALAR_BINARY_DUAL: break;

        case core::scalar_coding_e::SCALAR_NAF_2:
        case core::scalar_coding_e::SCALAR_NAF_3:
        case core::scalar_coding_e::SCALAR_NAF_4:
        case core::scalar_coding_e::SCALAR_NAF_5:
        case core::scalar_coding_e::SCALAR_NAF_6:
        case core::scalar_coding_e::SCALAR_NAF_7:
        {
            size_t w = static_cast<size_t>(m_coding_type) ^ SCALAR_CODING_NAF_BIT;
            size_t r = (1 << (w - 1)) - 1;

            for (size_t i=1; i < r; i++) {
                m_base_pre[i]->set(*m_base_pre[i-1].get());
                m_base_pre[i]->mul_mod(*m_base_pre[0].get(), cfg);
            }

            // Calculate the inverse of b
            if (!core::mpz<T>::invert(*m_base_pre[r], b, cfg.mod)) {
                return false;
            }
            m_base_pre[r]->mul_mont(cfg.mont_R2, cfg);

            for (size_t i=r+1; i < r+r; i++) {
                m_base_pre[i]->set(*m_base_pre[i-1]);
                m_base_pre[i]->mul_mont(*m_base_pre[r], cfg);
            }
        } break;

        case core::scalar_coding_e::SCALAR_PRE_2:
        case core::scalar_coding_e::SCALAR_PRE_3:
        case core::scalar_coding_e::SCALAR_PRE_4:
        case core::scalar_coding_e::SCALAR_PRE_5:
        case core::scalar_coding_e::SCALAR_PRE_6:
        case core::scalar_coding_e::SCALAR_PRE_7:
        case core::scalar_coding_e::SCALAR_PRE_8:
        {
            size_t w = static_cast<size_t>(m_coding_type) ^ SCALAR_CODING_PRE_BIT;
            size_t r = 1 << w;

            m_base_pre[1]->set(*m_base_pre[0].get());
            m_base_pre[1]->square_mod(cfg, 1);

            for (size_t i=2; i < r; i++) {
                m_base_pre[i]->set(*m_base_pre[i-1].get());
                m_base_pre[i]->mul_mod(*m_base_pre[0].get(), cfg);
            }
        } break;

        default: {}
    }

    return true;
}

/**
 * @brief Key generation for the given context
 * 
 * @param ctx RSA context
 * @return true Success
 * @return false Failure
 */
template<typename T>
bool rsa_cryptosystem<T>::keygen(ctx_rsa_tmpl<T>& ctx)
{
    if (ctx.e().is_zero()) {
        ctx.e() = core::mpz<T>("65537", 10);
    }

    core::mpz<T> p, q;
    while (!keygen_sp800_56b(ctx.p(), ctx.q(), ctx.e(), ctx.get_mod_bits())) {
    }

    // Ensure that p > q
    if (ctx.p() < ctx.q()) {
        ctx.p().swap(ctx.q());
    }

    // n = p * q
    ctx.n() = ctx.p() * ctx.q();

    // theta(n) = (p-1) * (q-1)
    core::mpz<T> theta, p1, q1;
    p1    = ctx.p() - T(1);
    q1    = ctx.q() - T(1);
    theta = p1 * q1;

    // d = e^-1 mod theta(n)
    core::mpz<T> g, s, t, u, v;
    u = theta;
    v = ctx.e();
    core::mpz<T>::gcdext(g, s, t, u, v);
    if (g != T(1)) {
        return false;
    }
    if (t < T(0)) {
        t = t + theta;
    }
    ctx.d() = t;

    // dP = d * (p-1), dQ = d * (q-1)
    core::mpz<T> temp;
    temp = ctx.d();
    core::mpz<T>::div_r(ctx.exp1(), temp, p1, core::mp_round_e::MP_ROUND_FLOOR);
    temp = ctx.d();
    core::mpz<T>::div_r(ctx.exp2(), temp, q1, core::mp_round_e::MP_ROUND_FLOOR);

    // qInv = q^-1 mod p
    if (!core::mpz<T>::invert(ctx.inv(), ctx.q(), ctx.p())) {
        return false;
    }

    ctx.setup_mod();

    return true;
}

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
template<typename T>
bool rsa_cryptosystem<T>::set_public_key(ctx_rsa_tmpl<T>& ctx, const phantom_vector<uint8_t>& k)
{
    std::string json_str = std::string(k.begin(), k.end());
    auto j = json::parse(json_str);

    ctx.n() = core::mpz<T>(j["n"].get<std::string>().c_str(), 16);
    ctx.e() = core::mpz<T>(j["e"].get<std::string>().c_str(), 16);

    ctx.setup_mod();

    return true;
}

/**
 * @brief Get the public key
 * 
 * @param ctx RSA context
 * @param k Key encoded
 * @return true Success
 * @return false Failure
 */
template<typename T>
bool rsa_cryptosystem<T>::get_public_key(ctx_rsa_tmpl<T>& ctx, phantom_vector<uint8_t>& k)
{
    json pubkey = {
        {"n", ctx.n().get_str(16)},
        {"e", ctx.e().get_str(16)}
    };
    std::string j = pubkey.dump();
    k = phantom_vector<uint8_t>(j.c_str(), j.c_str() + j.length());

    return true;
}

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
template<typename T>
bool rsa_cryptosystem<T>::set_private_key(ctx_rsa_tmpl<T>& ctx, const phantom_vector<uint8_t>& k)
{
    std::string json_str = std::string(k.begin(), k.end());
    auto j = json::parse(json_str);

    ctx.n()    = core::mpz<T>(j["n"].get<std::string>().c_str(), 16);
    ctx.e()    = core::mpz<T>(j["e"].get<std::string>().c_str(), 16);
    ctx.d()    = core::mpz<T>(j["d"].get<std::string>().c_str(), 16);
    ctx.p()    = core::mpz<T>(j["p"].get<std::string>().c_str(), 16);
    ctx.q()    = core::mpz<T>(j["q"].get<std::string>().c_str(), 16);
    ctx.exp1() = core::mpz<T>(j["exp1"].get<std::string>().c_str(), 16);
    ctx.exp2() = core::mpz<T>(j["exp2"].get<std::string>().c_str(), 16);
    ctx.inv()  = core::mpz<T>(j["inv"].get<std::string>().c_str(), 16);

    ctx.setup_mod();

    return true;
}

/**
 * @brief Get the private key (and public key)
 * 
 * @param ctx RSA context
 * @param k Private key
 * @return true Success
 * @return false Failure
 */
template<typename T>
bool rsa_cryptosystem<T>::get_private_key(ctx_rsa_tmpl<T>& ctx, phantom_vector<uint8_t>& k)
{
    json privkey = {
        {"n", ctx.n().get_str(16)},
        {"e", ctx.e().get_str(16)},
        {"d", ctx.d().get_str(16)},
        {"p", ctx.p().get_str(16)},
        {"q", ctx.q().get_str(16)},
        {"exp1", ctx.exp1().get_str(16)},
        {"exp2", ctx.exp2().get_str(16)},
        {"inv", ctx.inv().get_str(16)}
    };
    std::string j = privkey.dump();
    k = phantom_vector<uint8_t>(j.c_str(), j.c_str() + j.length());

    return true;
}

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
template<typename T>
bool rsa_cryptosystem<T>::keygen_sp800_56b(core::mpz<T>& p, core::mpz<T>& q, const core::mpz<T>& e, size_t nbits)
{
    if (e.cmp(m_e_2_16) <= 0 || e.cmp(m_e_2_256) >= 0 || e.is_zero() || !(e[0] & 0x1)) {
        p = core::mpz<T>();
        q = core::mpz<T>();
        return false;
    }

    core::mpz<T> xp, p1, p2, xq, q1, q2;
    if (!gen_probable_prime(p, xp, p1, p2, e, nbits)) {
        return false;
    }
    for (;;) {
        if (!gen_probable_prime(q, xq, q1, q2, e, nbits)) {
            return false;
        }

        if (!check_pminusq_diff(xp, xq, nbits)) {
            continue;
        }

        if (!check_pminusq_diff(p, q, nbits)) {
            continue;
        }

        break;
    }

    return true;
}

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
template<typename T>
bool rsa_cryptosystem<T>::mgf1(crypto::hash* h, phantom_vector<uint8_t>& mask, size_t hblocklen, size_t hlen,
    const phantom_vector<uint8_t>& seed, size_t masklen)
{
    if (masklen > 0x100000000ULL) {
        return false;
    }

    mask.resize(0);

    phantom_vector<uint8_t> c, mgfhash;
    mgfhash.resize(hlen);
    for (uint32_t counter=0; counter < ((masklen + hlen - 1) / hlen) - 1; counter++) {

        uint8_t ctr[4] = { uint8_t((counter >>  0) & 0xff),
                            uint8_t((counter >>  8) & 0xff),
                            uint8_t((counter >> 16) & 0xff),
                            uint8_t((counter >> 24) & 0xff) };

        h->init(hblocklen);
        h->update(seed.data(), seed.size());
        h->update(ctr, 4);
        h->final(mgfhash.data());

        mask.insert(mask.end(), mgfhash.begin(), mgfhash.end());
    }

    mask.resize(masklen);

    return true;
}

/**
 * @brief Octet Stream to Integer Primitive from PKCS #11
 * 
 * @param i Integer represented as a multiple precision integer
 * @param os Octet stream represented as a byte vector
 */
template<typename T>
void rsa_cryptosystem<T>::os2ip(core::mpz<T>& i, const phantom_vector<uint8_t>& os)
{
    i.set_bytes(os, true);
}

/**
 * @brief Integer to Octet Stream Primitive from PKCS #1
 * 
 * @param os Octet stream represented as a byte vector
 * @param i Integer represented as a multiple precision integer
 * @param k Maximum byte length of the octet stream (i.e. the modulus length in bytes)
 */
template<typename T>
void rsa_cryptosystem<T>::i2osp(phantom_vector<uint8_t>& os, const core::mpz<T>& i, size_t k)
{
    i.get_bytes(os, true);
    while (os.size() != k) {
        os.insert(os.begin(), 0);
    }
}

/**
 * @brief Low-level RSA exponentiation, r = b^e mod n
 * 
 * @param r Result
 * @param b Base
 * @param e Exponent
 * @param cfg Modulus configuration
 * @return rsacode_e Enumerated return code, RSA_OK indicates success
 */
template<typename T>
rsacode_e rsa_cryptosystem<T>::exponentiation(core::mpz<T>& r, core::mpz<T>& b, const core::mpz<T>& e,
    const core::mod_config<T>& cfg)
{
    // Allocate memory for the base values if not already done so
    precomputation_alloc(cfg);

    // A flag to indicate if a windowed mode is to be used and the window size
    size_t w = 1;
    bool is_windowed = (m_coding_type & SCALAR_CODING_PRE_BIT);
    if (is_windowed) {
        w = static_cast<size_t>(m_coding_type & 0x3f);
    }

    size_t sub_offset = 0;
    if (core::scalar_coding_e::SCALAR_NAF_2 <= m_coding_type &&
        core::scalar_coding_e::SCALAR_NAF_7 >= m_coding_type) {
        sub_offset = (1 << ((static_cast<size_t>(m_coding_type) & 0x3f) - 1)) - 2;
    }

    // Convert the exponent to a byte array
    phantom_vector<uint8_t> e_bytes;
    e.get_bytes(e_bytes);

    // Use the scalar_parser to scan the bit sequence and perform recoding
    core::scalar_parser bitgen(m_coding_type, e_bytes);
    size_t num_bits = bitgen.num_symbols();
    if (0 == num_bits) {
        return RSA_EXPONENT_IS_ZERO;
    }

    // Precomputation for exponent recoding and conversion to Montgomery domain
    precomputation(b, cfg);

    // Square-and-multiply
    rsacode_e rsacode;
    /*if (core::SCALAR_MONT_LADDER == m_coding_type) {
        rsacode = montgomery_ladder(r, b, bitgen, num_bits, w, sub_offset, cfg);
    }
    else */{
        rsacode = square_and_multiply(r, b, bitgen, num_bits, w, sub_offset, cfg);
    }

    // If necessary convert result from Montgomery domain
    if (core::REDUCTION_MONTGOMERY == cfg.reduction) {
        r.reduce_mont(cfg);
    }

    return rsacode;
}

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
template<typename T>
rsacode_e rsa_cryptosystem<T>::square_and_multiply(core::mpz<T>& r, const core::mpz<T>& b, core::scalar_parser& bitgen,
    size_t num_bits, size_t w, size_t sub_offset, const core::mod_config<T>& cfg)
{
    // Pull the first encoded bit and ensure it is asserted
    uint32_t bit = bitgen.pull();
    num_bits--;
    if (SCALAR_IS_LOW == bit) {
        return RSA_RECODING_ERROR;
    }

    // Set the initial value according to the encoding - it is guaranteed to be positive non-zero
    r.set(*m_base_pre[(bit - 1) & ((1 << (static_cast<size_t>(m_coding_type) & 0x3f)) - 1)].get());

    while (num_bits--) {
        r.square_mod(cfg, w);

        // Obtain the next integer bit to be encoded
        bit = bitgen.pull();

        // Decode the bit to determine the operation to be performed
        bool subtract = bit & SCALAR_IS_SUBTRACT;
        bool is_zero  = bit == SCALAR_IS_LOW;

        if (!is_zero) {
            bit &= 0xff;
            T pre_idx  = subtract ? 0 : (bit - 1) & 0xff;
            T sub_idx  = (subtract ? bit & 0xff : 0) + sub_offset;

            // Determine the value to be multiplied
            core::mpz<T>* mpz_b = subtract ? m_base_pre[sub_idx].get()
                                            : m_base_pre[pre_idx].get();

            r.mul_mod(*mpz_b, cfg);
        }
    }

    return RSA_OK;
}

/**
 * @brief Constant-time swap of two pointers
 * @param swap Flag indicating if swap should occur
 * @param s Pointer to swap
 * @param r Pointer to swap
 */
template<typename T>
void rsa_cryptosystem<T>::cswap(bool swap, intptr_t& s, intptr_t& r)
{
    intptr_t dummy = -intptr_t(swap) & (s ^ r);
    s ^= dummy;
    r ^= dummy;
}

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
template<typename T>
rsacode_e rsa_cryptosystem<T>::montgomery_ladder(core::mpz<T>& r, const core::mpz<T>& b, core::scalar_parser& bitgen,
    size_t num_bits, size_t w, size_t sub_offset, const core::mod_config<T>& cfg)
{
    (void) w;
    (void) sub_offset;

    // Pull the first encoded bit and ensure it is asserted
    uint32_t bit = bitgen.pull();
    num_bits--;
    if (SCALAR_IS_LOW == bit) {
        return RSA_RECODING_ERROR;
    }

    // Set the initial value according to the encoding - it is guaranteed to be positive non-zero
    //r.set(*m_base_pre[(bit - 1) & ((1 << (static_cast<size_t>(m_coding_type) & 0x3f)) - 1)].get());

    if (core::REDUCTION_MONTGOMERY == cfg.reduction) {
        r = cfg.mont_R2;
    }
    else {
        r.set(T(1));
    }

    core::mpz<T> b1;
    b1.set(b);
    b1.square_mod(cfg);

    // Set pointers
    intptr_t r0 = intptr_t(&r);
    intptr_t r1 = intptr_t(&b1);

    bool swap = false;
    while (num_bits--) {
        // Obtain the next integer bit to be encoded
        bit = bitgen.pull();

        // Conditionally swap s and r
        swap ^= bit == SCALAR_IS_LOW;
        cswap(swap, r0, r1);
        swap = bit == SCALAR_IS_LOW;

        core::mpz<T>* mpz_r0 = reinterpret_cast<core::mpz<T>*>(r0);
        core::mpz<T>* mpz_r1 = reinterpret_cast<core::mpz<T>*>(r1);

        mpz_r0->mul_mod(*mpz_r1, cfg);
        mpz_r1->square_mod(cfg);
    }

    core::mpz<T>* res = reinterpret_cast<core::mpz<T>*>(r0);
    r.set(*res);

    return RSA_OK;
}

/**
 * @brief RSA public exponentiation, c = m^e mod n
 * 
 * @param ctx RSA context
 * @param m Message
 * @param c Ciphertext
 * @return true Success
 * @return false Failure
 */
template<typename T>
bool rsa_cryptosystem<T>::rsa_public_exponentiation(ctx_rsa_tmpl<T>& ctx, core::mpz<T> m, core::mpz<T>& c)
{
    rsacode_e code = exponentiation(c, m, ctx.e(), ctx.mod());

    return RSA_OK == code;
}

/**
 * @brief RSA private exponentiation, m = c^d mod n
 * 
 * @param ctx RSA context
 * @param c Ciphertext
 * @param m Message
 * @return true Success
 * @return false Failure
 */
template<typename T>
bool rsa_cryptosystem<T>::rsa_private_exponentiation(ctx_rsa_tmpl<T>& ctx, core::mpz<T> c, core::mpz<T>& m)
{
    if (false) {
        if (RSA_OK != exponentiation(m, c, ctx.d(), ctx.mod())) {
            return false;
        }
    }
    else {
        core::mpz<T> m_1, m_2, h, cp, cq;
        cp.set(c).barrett(ctx.pmod());
        cq.set(c).barrett(ctx.qmod());

        if (RSA_OK != exponentiation(m_1, cp, ctx.exp1(), ctx.pmod())) {
            return false;
        }

        if (RSA_OK != exponentiation(m_2, cq, ctx.exp2(), ctx.qmod())) {
            return false;
        }

        h = (ctx.inv() * (m_1 - m_2)).barrett(ctx.pmod());
        m = m_2 + h * ctx.q();
    }

    return true;
}

/**
 * @brief Verify that p - q is not too close
 * 
 * @param p RSA secret prime p
 * @param q RSA secret prime q with p < q
 * @param nbits Length of the modulus n in bits
 * @return true Success
 * @return false Failure
 */
template<typename T>
bool rsa_cryptosystem<T>::check_pminusq_diff(const core::mpz<T>& p, const core::mpz<T>& q, int nbits)
{
    assert(nbits >= 200);
    const size_t bitlen = (nbits >> 1) - 100;

    core::mpz<T> diff;
    diff = p - q;
    if (diff.is_zero()) {
        return false;
    }
    diff.set_sign(false);
    diff = diff - T(1);

    return diff.sizeinbase(2) > bitlen;
}

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
template<typename T>
bool rsa_cryptosystem<T>::gen_probable_prime(core::mpz<T>& prime, core::mpz<T>& xpout, core::mpz<T>& p1, core::mpz<T>& p2,
    const core::mpz<T>& e, size_t nbits)
{
    const size_t min_bitlen = nbits >=4096 ? 201 :
                                nbits >=3072 ? 171 :
                                nbits >=2048 ? 141 :
                                nbits >=1024 ? 101 :
                                                56;
    const size_t max_bitlen = nbits >=4096 ? 2030 :
                                nbits >=3072 ? 1518 :
                                nbits >=2048 ? 1007 :
                                nbits >=1024 ? 496 :
                                                246;

    // Generate odd integers Xp1 and Xp2 of length bitlen1 and bitlen2 respectively
    const size_t bitlen_bytes = (min_bitlen + 7) >> 3;
    phantom_vector<uint8_t> xp1_bytes(bitlen_bytes), xp2_bytes(bitlen_bytes);
    m_prng->get_mem(xp1_bytes.data(), bitlen_bytes);
    m_prng->get_mem(xp2_bytes.data(), bitlen_bytes);

    core::mpz<T> xp1, xp2;
    xp1.set_bytes(xp1_bytes);
    xp1.setbit(0);
    xp1.setbit(min_bitlen - 1);
    for (size_t i=min_bitlen; i < bitlen_bytes << 3; i++) {
        xp1.unsetbit(i);
    }
    xp2.set_bytes(xp2_bytes);
    xp2.setbit(0);
    xp2.setbit(min_bitlen - 1);
    for (size_t i=min_bitlen; i < bitlen_bytes << 3; i++) {
        xp2.unsetbit(i);
    }

    find_aux_prob_prime(p1, xp1);
    find_aux_prob_prime(p2, xp2);
    if ((p1.sizeinbase(2) + p2.sizeinbase(2)) >= max_bitlen) {
        return false;
    }

    return derive_prime(prime, xpout, p1, p2, e, nbits);
}

/**
 * @brief Find an auxiliary probable prime from an array of random bits
 * 
 * @param[out] p1 Auxiliary prime
 * @param xp1 Random byte array
 */
template<typename T>
void rsa_cryptosystem<T>::find_aux_prob_prime(core::mpz<T>& p1, const core::mpz<T>& xp1)
{
    p1.set(xp1);

    while (1) {
        if (core::mpz<T>::check_prime(*m_prng.get(), p1, p1.sizeinbase(2), true)) {
            break;
        }
        p1 += T(2);
    }
}

/**
 * @brief Find an auxiliary probable prime from an array of random bits
 * 
 * @param[out] p1 Auxiliary prime
 * @param xp1 Random byte array
 */
template<typename T>
bool rsa_cryptosystem<T>::derive_prime(core::mpz<T>& prime_factor, core::mpz<T>& rand_out,
    const core::mpz<T>& aux_prime_1, const core::mpz<T>& aux_prime_2, const core::mpz<T>& e, size_t nbits)
{
    const size_t bits = nbits >> 1;

    // 2^256/sqrt(2)
    const size_t inv_sqrt2_bits = m_inv_sqrt2.sizeinbase(2);

    if (bits < inv_sqrt2_bits) {
        return false;
    }
    const core::mpz<T> base  = m_inv_sqrt2 << int(bits - inv_sqrt2_bits);
    const core::mpz<T> range = (core::mpz<T>(T(1)) << static_cast<int>(bits)) - base;

    // Verify that 2gcd(*aux_prime_1, aux_prime_2) == 1
    const core::mpz<T> r1x2 = core::mpz<T>(aux_prime_1).add(aux_prime_1);
    core::mpz<T> g;
    g = r1x2.gcd(aux_prime_2);
    if (g != T(1)) {
        return false;
    }

    const core::mpz<T> r1r2x2 = r1x2 * aux_prime_2;

    // R = ((aux_prime_2^-1 mod 2*aux_prime_1) * aux_prime_2) -
    //     (((2*aux_prime_1)^-1 mod aux_prime_2)*(2*aux_prime_1))
    core::mpz<T> R, R2;
    if (!core::mpz<T>::invert(R, aux_prime_2, r1x2)) {
        return false;
    }
    R = R * aux_prime_2;
    if (!core::mpz<T>::invert(R2, r1x2, aux_prime_2)) {
        return false;
    }
    R2 = R2 * r1x2;
    R  = R - R2;

    // If -ve we correct R by adding the modulus r1r2x2 = aux_prime_1 * aux_prime_2 * aux_prime_2
    if (R.is_negative()) {
        R = R + r1r2x2;
    }

    // Configure the modulus struct prior to calculating modulus inverse
    core::mod_config<T> cfg;
    cfg.mod       = r1r2x2;
    cfg.mod_bits  = r1r2x2.sizeinbase(2);
    cfg.blog2     = std::numeric_limits<T>::digits;
    cfg.k         = (r1r2x2.sizeinbase(2) + std::numeric_limits<T>::digits - 1) >> core::bits_log2<T>::value();
    cfg.reduction = core::REDUCTION_BARRETT;

    // Calculate the modular inverse of r1r2x2 by dividing r1r2x2 by 2^(log2(B) + k)
    core::mpz<T> temp;
    temp.setbit(cfg.blog2 * cfg.k * 2);
    core::mpz<T>::tdiv_q(cfg.mod_inv, temp, r1r2x2);

    size_t num_rand_bytes = (bits + 7) >> 3;
    phantom_vector<uint8_t> X_bytes(num_rand_bytes);
    for (;;) {
        // Choose X such that 1/sqrt(2) * 2^(nbits/2) <= X < (2^(nbits/2))
        m_prng->get_mem(X_bytes.data(), num_rand_bytes);

        rand_out.set_bytes(X_bytes);
        while (rand_out >= range) rand_out >>= 1;
        rand_out = rand_out + base;

        // prime_factor = X + ((R - X) mod 2r1r2)
        prime_factor = rand_out + (R - rand_out).mod(cfg);

        core::mpz<T> ym1;
        for (size_t i = 0;;) {
            if (prime_factor.sizeinbase(2) > bits) {
                break;
            }

            ym1 = prime_factor - T(1);

            // If the gcd(prime_factor-1, e) == 1 then prime_factor is probably prime
            g = ym1.gcd(e);
            if (g == T(1)) {
                if (core::mpz<T>::check_prime(*m_prng.get(), prime_factor, nbits, true)) {
                    return true;
                }
            }

            if (++i >= 5 * bits) {
                return false;
            }

            prime_factor = prime_factor + r1r2x2;
        }
    }
}

/**
 * @brief Get the (Cryptographically Secure) PRNG
 * 
 * @return std::shared_ptr<csprng> CSPRNG
 */
template<typename T>
std::shared_ptr<csprng> rsa_cryptosystem<T>::get_prng();



// Forward declaration of common type declarations
/// @{
template class rsa_cryptosystem<uint8_t>;
template class rsa_cryptosystem<uint16_t>;
template class rsa_cryptosystem<uint32_t>;
#if defined(IS_64BIT)
template class rsa_cryptosystem<uint64_t>;
#endif
/// @}

}  // namespace rsa
}  // namespace phantom
