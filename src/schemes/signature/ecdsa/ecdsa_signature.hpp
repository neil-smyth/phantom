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
#include "schemes/signature/ecdsa/ctx_ecdsa.hpp"
#include "crypto/hash_sha2.hpp"
#include "crypto/csprng.hpp"
#include "packing/packer.hpp"
#include "packing/unpacker.hpp"
#include "packing/stream.hpp"


namespace phantom {
namespace schemes {

/// A class providing a ECDSA implementation
class ecdsa_signature : public signature
{
public:
    /// Class constructor
    ecdsa_signature();

    /// Class destructor
    virtual ~ecdsa_signature();

    /// Create a context for the pkc instance based on the required security strength
    std::unique_ptr<user_ctx> create_ctx(security_strength_e bits,
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

    template<typename T>
    bool keygen_tmpl(ctx_ecdsa_tmpl<T>& myctx)
    {
        size_t num_bits  = myctx.get_order_G_bits();
        size_t num_bytes = (num_bits + 7) >> 3;

        core::mpz<T> sk;
        do {
            myctx.sk() = phantom_vector<uint8_t>(num_bytes);
            m_prng->get_mem(myctx.sk().data(), num_bytes);
            myctx.sk()[num_bytes-1] &= ~uint8_t(0) >> (num_bytes*8 - num_bits);

            sk.set_bytes(myctx.sk());
        } while (sk >= myctx.get_order_G() || sk < T(1));

        // Initialize scalar point multiplication from the base point using the private key
        if (elliptic::POINT_OK != myctx.scalar_point_mul(myctx.sk())) {
            return false;
        }

        const elliptic::point<T>& result_point = myctx.get_result_point();
        if (elliptic::field_e::WEIERSTRASS_PRIME_FIELD == myctx.field()) {
            myctx.set_pk(new elliptic::weierstrass_prime_affine<T>(
                static_cast<const elliptic::prime_point<T>&>(result_point)));
        }
        else {
            myctx.set_pk(new elliptic::weierstrass_binary_affine<T>(
                static_cast<const elliptic::binary_point<T>&>(result_point)));
        }

        myctx.setup_pk(*myctx.get_pk());

        return true;
    }

    template<typename T>
    bool set_public_key_tmpl(ctx_ecdsa_tmpl<T>& ctx, const phantom_vector<uint8_t>& key)
    {
        size_t n = ctx.n();

        phantom_vector<uint8_t> x, y;
        packing::unpacker up(key);
        for (size_t i = 0; i < n; i++) {
            x[i] = up.read_unsigned(8, packing::RAW);
        }
        for (size_t i = 0; i < n; i++) {
            y[i] = up.read_unsigned(8, packing::RAW);
        }

        core::mpz<T> mpz_x, mpz_y;
        mpz_x.set_bytes(x);
        mpz_y.set_bytes(y);
        ctx.get_pk()->convert_to(ctx.get_configuration(), mpz_x, mpz_y);

        return true;
    }

    template<typename T>
    bool get_public_key_tmpl(ctx_ecdsa_tmpl<T>& ctx, phantom_vector<uint8_t>& key)
    {
        size_t n = ctx.n();

        core::mpz<T> mpz_x, mpz_y;
        ctx.get_pk()->convert_to(ctx.get_configuration(), mpz_x, mpz_y);

        phantom_vector<uint8_t> x, y;
        mpz_x.get_bytes(x);
        mpz_y.get_bytes(y);

        key.clear();

        x.resize(n);
        y.resize(n);

        packing::packer pack(2 * 8 * n);
        for (size_t i = 0; i < n; i++) {
            pack.write_unsigned(x[i], 8, packing::RAW);
        }
        for (size_t i = 0; i < n; i++) {
            pack.write_unsigned(y[i], 8, packing::RAW);
        }

        pack.flush();
        key = pack.get();

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

private:
    using signature::sign;
    using signature::verify;

    static size_t bits_2_set(security_strength_e bits);

    std::shared_ptr<csprng>   m_prng;

    static void gen_hash(phantom_vector<uint8_t>& out, size_t n, const phantom_vector<uint8_t>& m)
    {
        size_t hash_bytes = (n > 384)? 64 : (n > 256)? 48 : 32;
        out.resize(hash_bytes);
        std::unique_ptr<crypto::hash> h = std::unique_ptr<crypto::hash>(new crypto::hash_sha2());
        h->init(hash_bytes);
        h->update(m.data(), m.size());
        h->final(out.data());
        out.resize((n + 7) >> 3);
        if (n < (((n + 7) >> 3) << 3)) {
            out[((n + 7) >> 3) - 1] &= (1 << (n - ((n >> 3) << 3))) - 1;
        }
    }

    template<typename T>
    bool sign_calc(ctx_ecdsa_tmpl<T>& myctx, const phantom_vector<uint8_t>& m, phantom_vector<uint8_t>& s)
    {
        auto order_n = myctx.get_order_G();
        size_t n = myctx.get_order_G_bits();

        // 1. Hash the message using a predefined hash algorithm, e = HASH(m)
        phantom_vector<uint8_t> ehash;
        gen_hash(ehash, n, m);

        // 2. Generate a cryptographically secure random integer, k from [1, n-1]
        size_t bytes_upper = (n + 7) >> 3;
        size_t bytes_lower = n >> 3;
        phantom_vector<uint8_t> k_bytes((n + 7) >> 3);
restart:
        m_prng->get_mem(k_bytes.data(), bytes_upper);
        if (n < (bytes_upper << 3)) {
            k_bytes[bytes_upper - 1] &= (1 << (n - (bytes_lower << 3))) - 1;
        }

        core::mpz<T> k;
        k.set_bytes(k_bytes);
        k.reduce(myctx.get_n_mod());
        k.get_bytes(k_bytes);

        // 3. Calculate the curve point (x1, y1) = k*G
        if (elliptic::POINT_OK != myctx.scalar_point_mul(k_bytes)) {
            goto restart;
        }
        const elliptic::point<T>& result_point = myctx.get_result_point();

        // 4. Calculate r = x1 mod n, return to step 2 if r = 0
        core::mpz<T> mpz_r;
        if (elliptic::field_e::WEIERSTRASS_PRIME_FIELD == myctx.field()) {
            if (core::REDUCTION_MONTGOMERY == myctx.get_configuration().mod.reduction) {
                mpz_r = static_cast<core::mpz<T>>(result_point.x()).reduce_mont(myctx.get_configuration().mod);
            }
            else {
                mpz_r = static_cast<core::mpz<T>>(result_point.x());
            }
        }
        else {
            const core::mp_gf2n<T>& mp_gf2n_r = static_cast<const core::mp_gf2n<T>&>(result_point.x());
            mpz_r.set_words(mp_gf2n_r.get_limbs());
        }
        mpz_r.reduce(myctx.get_n_mod());
        if (mpz_r.is_zero()) {
            goto restart;
        }

        // 5. Calculate s = 1/k * (z + r * dA) mod n, return to step 2 if s = 0
        core::mpz<T> mpz_s, z, dA;
        z.set_bytes(ehash);
        dA.set_bytes(myctx.sk());
        if (!core::mpz<T>::invert(mpz_s, k, order_n)) {
            goto restart;
        }

        mpz_s.mul_mod(dA.mul_mod(mpz_r, myctx.get_n_mod()).add_mod(z, myctx.get_n_mod()), myctx.get_n_mod());
        if (mpz_s.is_zero()) {
            goto restart;
        }

        phantom_vector<uint8_t> s_bytes;
        mpz_s.get_bytes(s_bytes);

        // Obtain common array lengths
        mpz_r.get_bytes(s);
        s.resize(bytes_upper);
        s.insert(s.end(), s_bytes.begin(), s_bytes.end());

        return true;
    }

    template<class T>
    static bool verify_calc(ctx_ecdsa_tmpl<T>& myctx,
                            const phantom_vector<uint8_t> m,
                            const phantom_vector<uint8_t> signature)
    {
        // Obtain common array lengths
        size_t num_bits  = myctx.get_order_G_bits();
        size_t num_bytes = (num_bits + 7) >> 3;

        // Verify that r and s are integers in range of [1, n-1]
        core::mpz<T> r, s;
        phantom_vector<uint8_t> r_bytes(signature.begin(), signature.begin() + num_bytes);
        phantom_vector<uint8_t> s_bytes(signature.begin() + num_bytes, signature.end());
        r.set_bytes(r_bytes);
        s.set_bytes(s_bytes);

        auto order_n = myctx.get_order_G();
        if (r < T(1) || r >= order_n || s < T(1) || s >= order_n) {
            return false;
        }

        // 1. Hash the message using a predefined hash algorithm, e = HASH(m)
        phantom_vector<uint8_t> ehash;
        gen_hash(ehash, num_bits, m);

        core::mpz<T> inv_s, z, u1, u2;
        z.set_bytes(ehash);
        if (!core::mpz<T>::invert(inv_s, s, order_n)) {
            return false;
        }

        u1.set(z).mul_mod(inv_s, myctx.get_n_mod());
        u2.set(r).mul_mod(inv_s, myctx.get_n_mod());

        phantom_vector<uint8_t> u1_bytes, u2_bytes;
        u1.get_bytes(u1_bytes);
        u2.get_bytes(u2_bytes);

        if (elliptic::POINT_OK != myctx.scalar_point_mul(u1_bytes)) {
            return false;
        }

        std::unique_ptr<elliptic::point<T>> u1_point;
        if (elliptic::field_e::WEIERSTRASS_PRIME_FIELD == myctx.field()) {
            const elliptic::prime_point<T>& p =
                reinterpret_cast<const elliptic::prime_point<T>&>(myctx.get_result_point());
            switch (myctx.get_result_point().type())
            {
            case elliptic::POINT_COORD_AFFINE:
                u1_point = std::unique_ptr<elliptic::point<T>>(new elliptic::weierstrass_prime_affine<T>(p));
                break;
            case elliptic::POINT_COORD_PROJECTIVE:
                u1_point = std::unique_ptr<elliptic::point<T>>(new elliptic::weierstrass_prime_projective<T>(p));
                break;
            case elliptic::POINT_COORD_JACOBIAN:
                u1_point = std::unique_ptr<elliptic::point<T>>(new elliptic::weierstrass_prime_jacobian<T>(p));
                break;
            default: {}
            }
        }
        else {
            const elliptic::binary_point<T>& p =
                reinterpret_cast<const elliptic::binary_point<T>&>(myctx.get_result_point());
            switch (myctx.get_result_point().type())
            {
            case elliptic::POINT_COORD_AFFINE:
                u1_point = std::unique_ptr<elliptic::point<T>>(new elliptic::weierstrass_binary_affine<T>(p));
                break;
            case elliptic::POINT_COORD_PROJECTIVE:
                u1_point = std::unique_ptr<elliptic::point<T>>(new elliptic::weierstrass_binary_projective<T>(p));
                break;
            case elliptic::POINT_COORD_JACOBIAN:
                u1_point = std::unique_ptr<elliptic::point<T>>(new elliptic::weierstrass_binary_jacobian<T>(p));
                break;
            default: {}
            }
        }

        if (elliptic::POINT_OK != myctx.scalar_point_mul_pk(u2_bytes)) {
            return false;
        }

        const elliptic::point<T>& u2_point = myctx.get_result_point_pk();

        u1_point->addition(myctx.get_configuration(), u2_point);

        core::mpz<T> x;
        if (elliptic::field_e::WEIERSTRASS_PRIME_FIELD == myctx.field()) {
            core::mpz<T> y1;
            u1_point->convert_from(myctx.get_configuration(), &x, &y1);
        }
        else {
            core::mp_gf2n<T> x1, y1;
            u1_point->convert_from(myctx.get_configuration(), &x1, &y1);
            x.set_words(x1.get_limbs());
        }
        x.reduce(myctx.get_n_mod());

        if (x != r) {
            return false;
        }

        return true;
    }
};

}  // namespace schemes
}  // namespace phantom


