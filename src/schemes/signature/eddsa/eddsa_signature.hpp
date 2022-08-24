/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <algorithm>
#include <memory>
#include <string>

#include "schemes/signature/signature.hpp"
#include "schemes/signature/eddsa/ctx_eddsa.hpp"
#include "crypto/hash_sha2.hpp"
#include "crypto/xof_sha3.hpp"
#include "crypto/csprng.hpp"
#include "packing/packer.hpp"
#include "packing/unpacker.hpp"
#include "packing/stream.hpp"


namespace phantom {
namespace schemes {


/// A class providing a EdDSA implementation
class eddsa_signature : public signature
{
public:
    /// Class constructor
    eddsa_signature();

    /// Class destructor
    virtual ~eddsa_signature();

    /// Create a context for the pkc instance based on the required security strength
    std::unique_ptr<user_ctx> create_ctx(security_strength_e strength, cpu_word_size_e size_hint) const override;

    /// Create a context for the pkc instance based on the parameter set
    std::unique_ptr<user_ctx> create_ctx(size_t set, cpu_word_size_e size_hint) const override;

    /// Key manipulation methods
    /// @{
    bool keygen(std::unique_ptr<user_ctx>& ctx) override;

    template<typename T>
    bool keygen_tmpl(ctx_eddsa_tmpl<T>& myctx)
    {
        size_t n = (myctx.get_curve_bits() + 7 + 1) >> 3;

        myctx.sk() = phantom_vector<uint8_t>(n);
        m_prng->get_mem(myctx.sk().data(), n);

        secret_expand(myctx, myctx.sk());

        return true;
    }

    template<typename T>
    bool secret_expand(ctx_eddsa_tmpl<T>& myctx, const phantom_vector<uint8_t>& sk)
    {
        auto buffer = phantom_vector<uint8_t>();

        if (myctx.get_set() < 3) {  // Ed25519

            if (sk.size() != 32) return false;

            buffer.resize(64);

            m_hash->init(64);
            m_hash->update(sk.data(), 32);
            m_hash->final(buffer.data());

            myctx.set_prefix(buffer.data() + 32, 32);

            buffer.resize(32);
            buffer[0]  &= 248;
            buffer[31] &= 127;
            buffer[31] |= 64;
        }
        else if (myctx.get_set() >= 3) {  // Ed448

            if (sk.size() != 57) return false;

            buffer.resize(114);

            m_xof->init(32);
            m_xof->absorb(sk.data(), 57);
            m_xof->final();
            m_xof->squeeze(buffer.data(), 114);

            myctx.set_prefix(buffer.data() + 57, 57);

            buffer.resize(57);
            buffer[0]  &= 252;
            buffer[55] |= 128;
            buffer[56]  = 0;
        }

        myctx.set_s(buffer);

        // Initialize scalar point multiplication from the base point using the private key
        myctx.setup();
        if (elliptic::POINT_OK != myctx.scalar_point_mul(buffer)) {
            return false;
        }

        const elliptic::prime_point<T>& p = static_cast<const elliptic::prime_point<T>&>(myctx.get_result_point());
        myctx.set_pk(new elliptic::edwards_prime_affine<T>(p));

        core::mpz<T> x, y;
        p.convert_from(myctx.get_configuration(), &x, &y);

        phantom_vector<uint8_t> A;
        compression<T>(myctx.get_configuration(), x, y, A);

        myctx.setup_pk(*myctx.get_pk());
        myctx.set_A(A);

        return true;
    }

    template<typename T>
    bool set_public_key_tmpl(ctx_eddsa_tmpl<T>& ctx, const phantom_vector<uint8_t>& key)
    {
        core::mpz<T> x, y;
        decompression<T>(ctx.get_configuration(), x, y, key);
        ctx.set_pk(new elliptic::edwards_prime_affine<T>(ctx.get_configuration(), x, y));
        ctx.set_A(key);

        return true;
    }

    bool set_public_key(std::unique_ptr<user_ctx>&, const phantom_vector<uint8_t>& key) override;
    bool get_public_key(std::unique_ptr<user_ctx>&, phantom_vector<uint8_t>& key) override;
    bool set_private_key(std::unique_ptr<user_ctx>&, const phantom_vector<uint8_t>& key) override;
    bool get_private_key(std::unique_ptr<user_ctx>&, phantom_vector<uint8_t>& key) override;
    /// @}

    /// @brief Get the message length associated with the cryptosystem
    /// @param ctx The user context containing the key
    size_t get_msg_len(const std::unique_ptr<user_ctx>& ctx) const override;

    /// @brief Signing of a message
    /// @param ctx The user context containing the key
    /// @param m The input message to be signed
    /// @param s The output signature
    /// @return True on success, false otherwise
    bool sign(const std::unique_ptr<user_ctx>&, const phantom_vector<uint8_t>& m, phantom_vector<uint8_t>& s) override;
    bool sign(const std::unique_ptr<user_ctx>&, const phantom_vector<uint8_t>& m, phantom_vector<uint8_t>& s,
        const phantom_vector<uint8_t>& c) override;

    /// @brief Verification of a message
    /// @param ctx The user context containing the key
    /// @param m The input message to be signed
    /// @param s The input signature
    /// @return True on success, false otherwise
    bool verify(const std::unique_ptr<user_ctx>&,
                const phantom_vector<uint8_t>& m,
                const phantom_vector<uint8_t>& s) override;
    bool verify(const std::unique_ptr<user_ctx>&, const phantom_vector<uint8_t>& m, const phantom_vector<uint8_t>& s,
        const phantom_vector<uint8_t>& c) override;

    template<typename T>
    static void compression(const elliptic::ecc_config<T>& config,
                            const core::mpz<T>& x,
                            const core::mpz<T>& y,
                            phantom_vector<uint8_t>& s)
    {
        size_t n = (config.mod.mod_bits + 7 + 1) >> 3;
        y.get_bytes(s);
        s.resize(n);
        s[n-1] |= (x[0] & 0x1) << 7;
    }

    template<typename T>
    static void decompression(const elliptic::ecc_config<T>& config,
                              core::mpz<T>& x,
                              core::mpz<T>& y,
                              const phantom_vector<uint8_t>& s)
    {
        phantom_vector<uint8_t> encoded = s;
        uint8_t xbit = encoded[encoded.size() - 1] >> 7;
        encoded[encoded.size() - 1] &= 0x7f;

        y.set_bytes(encoded);
        x = recover_x(config, y, xbit);
    }

private:
    static size_t bits_2_set(security_strength_e bits);

    std::shared_ptr<csprng> m_prng;

    std::unique_ptr<crypto::hash> m_hash;
    std::unique_ptr<crypto::xof_sha3> m_xof;

    void gen_ph_hash(bool enable_sha512, phantom_vector<uint8_t>& out,
                     const phantom_vector<uint8_t>& m,
                     bool pure_eddsa);

    void gen_r_hash(bool enable_sha512, phantom_vector<uint8_t>& out, const phantom_vector<uint8_t>& dom,
        const phantom_vector<uint8_t>& prefix, const phantom_vector<uint8_t>& ph_m);

    void gen_k_hash(bool enable_sha512, phantom_vector<uint8_t>& out,
        const phantom_vector<uint8_t>& dom, const phantom_vector<uint8_t>& r,
        const phantom_vector<uint8_t>& a, const phantom_vector<uint8_t>& ph_m);

    static phantom_vector<uint8_t> dom(bool blank,
                                       bool ed448,
                                       const phantom_vector<uint8_t>& x,
                                       const phantom_vector<uint8_t>& y);

    static phantom_vector<uint8_t> gen_F(bool is_ed25519, bool phflag);

    template<typename T>
    static core::mpz<T> recover_x(const elliptic::ecc_config<T>& config, const core::mpz<T>& y, uint8_t xbit)
    {
        core::mpz<T> constant_d = dynamic_cast<core::mpz<T>&>(*config.d.get());
        if (core::REDUCTION_MONTGOMERY == config.mod.reduction) {
            constant_d.reduce_mont(config.mod);
        }

        core::mod_config<T> cfg;
        cfg.mod = config.mod.mod;
        cfg.mod_inv = config.mod.mod_inv;
        cfg.mod_bits = config.mod.mod_bits;
        cfg.k = config.mod.k;
        cfg.blog2 = config.mod.blog2;
        cfg.reduction = core::REDUCTION_BARRETT;

        core::mpz<T> yy, inv, x;
        yy.set(y).square_mod(cfg);
        constant_d.mul_mod(yy, cfg);
        if (config.a_is_minus_1) {
            constant_d.add_mod(T(1), cfg);
        }
        else {
            constant_d.sub_mod(T(1), cfg);
        }

        if (!core::mpz<T>::invert(inv, constant_d, cfg.mod)) {
            throw std::runtime_error("Cannot invert");
        }

        x.set(yy).sub_mod(T(1), cfg).mul_mod(inv, cfg).sqrt_mod(cfg);

        if (!x.is_zero() && (x[0] & 1) != xbit) {
            x.negate().add_mod(cfg.mod, cfg);
        }

        return x;
    }

    template<typename T>
    bool sign_calc(ctx_eddsa_tmpl<T>& myctx, const phantom_vector<uint8_t>& m,
        phantom_vector<uint8_t>& signature, const phantom_vector<uint8_t>& c)
    {
        size_t n = (myctx.get_curve_bits() + 7 + 1) >> 3;

        // Calculate the F octet stream and dom2/dom4
        phantom_vector<uint8_t> F = gen_F(myctx.get_set() == 0, myctx.get_set() == 1 || myctx.get_set() == 4);
        phantom_vector<uint8_t> d = dom(myctx.get_set() == 0, myctx.get_set() >= 3, F, c);

        // Hash the message if using Ed25519ph or Ed448ph, using SHA512 or SHAKE256 as appropriate, then
        // compute r = hash([dom2(F,C) | dom4(F,C)] | prefix | PH(m))
        phantom_vector<uint8_t> ph_m, r_hash;
        gen_ph_hash(myctx.get_set() < 3, ph_m, m, myctx.get_set() == 0 || myctx.get_set() == 2 || myctx.get_set() == 3);
        gen_r_hash(myctx.get_set() < 3, r_hash, d, myctx.prefix(), ph_m);

        // Reduce r modulo L
        phantom_vector<uint8_t> r_scalar;
        core::mpz<T> r;
        r.set_bytes(r_hash);
        r.reduce(myctx.get_n_mod());
        r.get_bytes(r_scalar);

        // Calculate the curve point R = r*G
        phantom_vector<uint8_t> Rs;
        if (elliptic::POINT_OK != myctx.scalar_point_mul(r_scalar)) {
            return false;
        }
        const elliptic::point<T>& R = myctx.get_result_point();
        core::mpz<T> Rx, Ry;
        R.convert_from(myctx.get_configuration(), &Rx, &Ry);
        compression<T>(myctx.get_configuration(), Rx, Ry, Rs);

        // Compute hash([dom2(F,C) | dom4(F,C)] || R || A || PH(M))
        phantom_vector<uint8_t> k_hash;
        gen_k_hash(myctx.get_set() < 3, k_hash, d, Rs, myctx.A(), ph_m);
        core::mpz<T> h;
        h.set_bytes(k_hash);
        h.reduce(myctx.get_n_mod());

        // Calculate s = (r + h * a) mod n
        core::mpz<T> s;
        s = r + h * myctx.s();
        s.reduce(myctx.get_n_mod());

        phantom_vector<uint8_t> s_bytes;
        s.get_bytes(s_bytes);
        s_bytes.resize(n);

        // Generate the hash
        signature = Rs;
        signature.resize(n);
        signature.insert(signature.end(), s_bytes.begin(), s_bytes.end());

        return true;
    }

    template<class T>
    bool verify_calc(ctx_eddsa_tmpl<T>& myctx, const phantom_vector<uint8_t> m,
        const phantom_vector<uint8_t> signature, const phantom_vector<uint8_t>& c)
    {
        // Obtain the common byte length
        size_t n = (myctx.get_curve_bits() + 7 + 1) >> 3;

        // If the signature length is not 64 or 114 bytes as appropriate return an error
        if (signature.size() != 2*n) {
            return false;
        }

        // Verify that r >= 1 and s is an integer in the range of [1, n-1]
        core::mpz<T> r, s;
        phantom_vector<uint8_t> R_bytes(signature.begin(), signature.begin() + n);
        phantom_vector<uint8_t> S_bytes(signature.begin() + n, signature.end());
        r.set_bytes(R_bytes);
        s.set_bytes(S_bytes);

        auto order_n = myctx.get_order_G();
        if (r < T(1) || s < T(1) || s >= order_n) {
            return false;
        }

        // Hash the message using a predefined hash algorithm, SHA512 or SHAKE256
        phantom_vector<uint8_t> ph_m;
        gen_ph_hash(myctx.get_set() < 3, ph_m, m, myctx.get_set() == 0 || myctx.get_set() == 2 || myctx.get_set() == 3);

        // Compute hash([dom2(F,C) | dom4(F,C)] || R || A || PH(M))
        phantom_vector<uint8_t> F = gen_F(myctx.get_set() == 0, myctx.get_set() == 1 || myctx.get_set() == 4);
        phantom_vector<uint8_t> k_hash, k_scalar, d = dom(myctx.get_set() == 0, myctx.get_set() >= 3, F, c);
        gen_k_hash(myctx.get_set() < 3, k_hash, d, R_bytes, myctx.A(), ph_m);
        core::mpz<T> k;
        k.set_bytes(k_hash);
        k.reduce(myctx.get_n_mod());
        k.get_bytes(k_scalar);

        // Compute k*A
        if (elliptic::POINT_OK != myctx.scalar_point_mul_pk(k_scalar)) {
            return false;
        }

        core::mpz<T> Rx, Ry;
        decompression<T>(myctx.get_configuration(), Rx, Ry, R_bytes);
        elliptic::edwards_prime_projective<T> R(myctx.get_configuration(), Rx, Ry);
        R.addition(myctx.get_configuration(), myctx.get_result_point_pk());
        R.convert_from(myctx.get_configuration(), &Rx, &Ry);

        myctx.setup();
        if (elliptic::POINT_OK != myctx.scalar_point_mul(S_bytes)) {
            return false;
        }
        const elliptic::point<T>& sB = myctx.get_result_point();

        core::mpz<T> sBx, sBy;
        sB.convert_from(myctx.get_configuration(), &sBx, &sBy);

        return sBx.cmp(Rx) == 0 && sBy.cmp(Ry) == 0;
    }
};

}  // namespace schemes
}  // namespace phantom


