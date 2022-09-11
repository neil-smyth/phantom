/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
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

#include "./phantom.hpp"
#include "./phantom_memory.hpp"
#include "core/mpz.hpp"
#include "core/mp_gf2n.hpp"
#include "ecc/curves.hpp"
#include "ecc/ecc.hpp"


namespace phantom {
namespace schemes {

/// Definitions for the ECDSA parameter sets
template<class T>
struct ecdsa_set_t
{
    uint16_t                            set;
    elliptic::field_e                   field;
    size_t                              n;           ///< Length of the ring polynomial
    const elliptic::ec_params_t*        curve;
    elliptic::ecc_config<T>             cfg;
    std::unique_ptr<elliptic::point<T>> base;
    std::unique_ptr<elliptic::point<T>> base_dual;
    core::mod_config<T>                 n_mod;

    ecdsa_set_t() {}
    virtual ~ecdsa_set_t() {}
    ecdsa_set_t(ecdsa_set_t&&) = default;
};

/**
 * @brief An ECDSA context class used to store key, curve and algorithm specific parameters
 */
class ctx_ecdsa : public user_ctx
{
public:
    virtual ~ctx_ecdsa() {}

    virtual elliptic::field_e field() = 0;

    virtual size_t get_wordsize() = 0;
    virtual size_t get_log2_wordsize() = 0;
    virtual phantom_vector<uint8_t>& sk() = 0;
    virtual size_t n() = 0;
    virtual size_t get_curve_bits() = 0;
    virtual size_t get_curve_bytes() = 0;
    virtual const char* get_modulus() const = 0;
    virtual size_t get_order_G_bits() = 0;
};

/// A class describing the ECDSA user context
template<class T>
class ctx_ecdsa_tmpl : public ctx_ecdsa
{
public:
    explicit ctx_ecdsa_tmpl(size_t set) : m_scheme(PKC_SIG_ECDSA), m_set(set)
    {
        m_params.set = set;
        switch (set)
        {
            case 0:  m_params.curve = &elliptic::curves::param_ec_secp192r1;
                     m_params.field = elliptic::field_e::WEIERSTRASS_PRIME_FIELD;
                     break;
            case 1:  m_params.curve = &elliptic::curves::param_ec_secp224r1;
                     m_params.field = elliptic::field_e::WEIERSTRASS_PRIME_FIELD;
                     break;
            case 2:  m_params.curve = &elliptic::curves::param_ec_secp256r1;
                     m_params.field = elliptic::field_e::WEIERSTRASS_PRIME_FIELD;
                     break;
            case 3:  m_params.curve = &elliptic::curves::param_ec_secp384r1;
                     m_params.field = elliptic::field_e::WEIERSTRASS_PRIME_FIELD;
                     break;
            case 4:  m_params.curve = &elliptic::curves::param_ec_secp521r1;
                     m_params.field = elliptic::field_e::WEIERSTRASS_PRIME_FIELD;
                     break;

            case 5:  m_params.curve = &elliptic::curves::param_ec_sect163r2;
                     m_params.field = elliptic::field_e::WEIERSTRASS_BINARY_FIELD;
                     break;
            case 6:  m_params.curve = &elliptic::curves::param_ec_sect233r1;
                     m_params.field = elliptic::field_e::WEIERSTRASS_BINARY_FIELD;
                     break;
            case 7:  m_params.curve = &elliptic::curves::param_ec_sect283r1;
                     m_params.field = elliptic::field_e::WEIERSTRASS_BINARY_FIELD;
                     break;
            case 8:  m_params.curve = &elliptic::curves::param_ec_sect409r1;
                     m_params.field = elliptic::field_e::WEIERSTRASS_BINARY_FIELD;
                     break;
            case 9:  m_params.curve = &elliptic::curves::param_ec_sect571r1;
                     m_params.field = elliptic::field_e::WEIERSTRASS_BINARY_FIELD;
                     break;

            case 10: m_params.curve = &elliptic::curves::param_ec_sect163k1;
                     m_params.field = elliptic::field_e::WEIERSTRASS_BINARY_FIELD;
                     break;
            case 11: m_params.curve = &elliptic::curves::param_ec_sect233k1;
                     m_params.field = elliptic::field_e::WEIERSTRASS_BINARY_FIELD;
                     break;
            case 12: m_params.curve = &elliptic::curves::param_ec_sect283k1;
                     m_params.field = elliptic::field_e::WEIERSTRASS_BINARY_FIELD;
                     break;
            case 13: m_params.curve = &elliptic::curves::param_ec_sect409k1;
                     m_params.field = elliptic::field_e::WEIERSTRASS_BINARY_FIELD;
                     break;
            case 14: m_params.curve = &elliptic::curves::param_ec_sect571k1;
                     m_params.field = elliptic::field_e::WEIERSTRASS_BINARY_FIELD;
                     break;

            default: {}
        }

        switch (m_params.field)
        {
            case elliptic::field_e::WEIERSTRASS_PRIME_FIELD:  prime_setup();  break;
            case elliptic::field_e::WEIERSTRASS_BINARY_FIELD: binary_setup(); break;
            default: {}
        }

        m_order_G = core::mpz<T>(m_params.curve->order_m, 16);
    }

    virtual ~ctx_ecdsa_tmpl() {}

    ctx_ecdsa_tmpl(const ctx_ecdsa_tmpl&) = delete;

    virtual elliptic::field_e field()
    {
        return m_params.field;
    }

    virtual size_t get_wordsize()
    {
        return std::numeric_limits<T>::digits;
    }

    virtual size_t get_log2_wordsize()
    {
        return core::bits_log2<T>::value();
    }

    pkc_e get_scheme() override { return m_scheme;}
    size_t get_set() override { return m_set; }
    const std::string& get_set_name() override { return m_sets[m_set]; }
    const phantom_vector<std::string>& get_set_names() { return m_sets; }

    virtual phantom_vector<uint8_t>& sk() { return m_sk; }
    virtual phantom_vector<uint8_t>& pk() { return m_pk; }
    virtual size_t n() { return m_params.n; }
    virtual size_t get_curve_bits() { return m_params.curve->num_bits; }
    virtual size_t get_curve_bytes() { return m_params.curve->num_bytes; }
    virtual const char* get_modulus() const { return m_params.curve->p; }

    core::mod_config<T>& get_n_mod()
    {
        return m_params.n_mod;
    }

    void setup(const elliptic::point<T>& p_base)
    {
        m_ecdsa->setup(p_base);
    }

    void setup_pk(const elliptic::point<T>& p_base)
    {
        m_ecdsa_pk->setup(p_base);
    }

    elliptic::retcode_e scalar_point_mul(const phantom_vector<uint8_t>& secret)
    {
        return m_ecdsa->scalar_point_mul(secret);
    }

    elliptic::retcode_e scalar_point_mul_pk(const phantom_vector<uint8_t>& secret)
    {
        return m_ecdsa_pk->scalar_point_mul(secret);
    }

    const elliptic::point<T>& get_result_point()
    {
        auto p = const_cast<elliptic::point<T>*>(m_ecdsa->get_point());
        p->convert_to_mixed(m_params.cfg);
        return *p;
    }

    const elliptic::point<T>& get_result_point_pk()
    {
        auto p = const_cast<elliptic::point<T>*>(m_ecdsa_pk->get_point());
        p->convert_to_mixed(m_params.cfg);
        return *p;
    }

    elliptic::retcode_e get_result(core::mp<T>& x, core::mp<T>& y)
    {
        return m_ecdsa->get(x, y);
    }

    elliptic::ecc_config<T>& get_configuration()
    {
        return m_params.cfg;
    }

    elliptic::point<T>& get_base()
    {
        return *m_params.base.get();
    }

    core::mpz<T>& get_order_G()
    {
        return m_order_G;
    }

    virtual size_t get_order_G_bits()
    {
        return m_order_G.sizeinbase(2);
    }

    std::unique_ptr<elliptic::point<T>>& get_pk()
    {
        return m_public_key;
    }

    void set_pk(elliptic::point<T>* pk)
    {
        m_public_key = std::unique_ptr<elliptic::point<T>>(pk);
    }

private:
    void prime_setup()
    {
        m_params.cfg.mod.mod = core::mpz<T>(m_params.curve->p, 16);
        m_params.cfg.mod.mod_bits = m_params.cfg.mod.mod.sizeinbase(2);
        m_params.cfg.mod.k =
            (m_params.curve->num_bits + std::numeric_limits<T>::digits - 1) >> core::bits_log2<T>::value();
        m_params.cfg.mod.blog2 = std::numeric_limits<T>::digits;
        m_params.cfg.mod.reduction = core::REDUCTION_MONTGOMERY;
        auto a = new core::mpz<T>(m_params.curve->a, 16);
        m_params.cfg.a_is_minus_3 = a->get_str(16) == "-3";
        if (a->is_negative()) {
            *a += m_params.cfg.mod.mod;
        }

        core::mpz<T> temp;
        temp.setbit(m_params.cfg.mod.blog2 * m_params.cfg.mod.k * 2);
        core::mpz<T>::tdiv_qr(m_params.cfg.mod.mod_inv, m_params.cfg.mod.mont_R2, temp, m_params.cfg.mod.mod);

        m_params.n = m_params.curve->num_bytes;

        m_params.n_mod.mod = core::mpz<T>(m_params.curve->order_m, 16);
        m_params.n_mod.mod_bits = m_params.n_mod.mod.sizeinbase(2);
        m_params.n_mod.k =
            (m_params.curve->num_bits + std::numeric_limits<T>::digits - 1) >> core::bits_log2<T>::value();
        m_params.n_mod.blog2 = std::numeric_limits<T>::digits;
        m_params.n_mod.reduction = core::REDUCTION_BARRETT;

        core::mpz<T> temp_n;
        temp_n.setbit(m_params.n_mod.blog2 * m_params.n_mod.k * 2);
        core::mpz<T>::tdiv_qr(m_params.n_mod.mod_inv, m_params.n_mod.mont_R2, temp_n, m_params.n_mod.mod);

        if (core::REDUCTION_MONTGOMERY == m_params.cfg.mod.reduction) {
            core::mpz<T> R, temp_m, s, t;
            R.setbit(std::numeric_limits<T>::digits * m_params.cfg.mod.k);
            temp_m = m_params.cfg.mod.mod;
            core::mpz<T>::gcdext(temp, s, t, R, temp_m);
            m_params.cfg.mod.mont_inv = 0;
            if (t.get_limbsize() > 0) {
                m_params.cfg.mod.mont_inv = t.is_negative()? t[0] : -t[0];  // (R[0] - t[0]) mod B, R[0] is always 0
            }

            a->mul_mont(m_params.cfg.mod.mont_R2, m_params.cfg.mod);
        }

        if (core::REDUCTION_MONTGOMERY == m_params.n_mod.reduction) {
            core::mpz<T> R, temp_m, s, t;
            R.setbit(std::numeric_limits<T>::digits * m_params.n_mod.k);
            temp_m = m_params.n_mod.mod;
            core::mpz<T>::gcdext(temp, s, t, R, temp_m);
            m_params.n_mod.mont_inv = 0;
            if (t.get_limbsize() > 0) {
                m_params.n_mod.mont_inv = t.is_negative()? t[0] : -t[0];  // (R[0] - t[0]) mod B, R[0] is always 0
            }
        }

        m_params.cfg.a = std::shared_ptr<core::mp<T>>(a);

        core::mpz<T> g_x(m_params.curve->g_x, 16);
        core::mpz<T> g_y(m_params.curve->g_y, 16);
        m_params.base = std::unique_ptr<elliptic::point<T>>(
            new elliptic::weierstrass_prime_affine<T>(m_params.cfg, g_x, g_y));

        // Generate the base point for Shamir's trick
        core::scalar_coding_e coding = core::SCALAR_PRE_8;
        if (core::SCALAR_BINARY_DUAL == coding) {
            core::mpz<T> g_x_dual(m_params.curve->g_x_dual, 16);
            core::mpz<T> g_y_dual(m_params.curve->g_y_dual, 16);
            auto pt = new elliptic::weierstrass_prime_affine<T>(m_params.cfg, g_x_dual, g_y_dual);
            m_params.base_dual = std::unique_ptr<elliptic::point<T>>(pt);
        }

        m_ecdsa    = std::unique_ptr<elliptic::ecc<T>>(new elliptic::ecc<T>(m_params.cfg,
                                                       m_params.field,
                                                       elliptic::POINT_COORD_JACOBIAN,
                                                       coding,
                                                       true));
        m_ecdsa_pk = std::unique_ptr<elliptic::ecc<T>>(new elliptic::ecc<T>(m_params.cfg,
                                                       m_params.field,
                                                       elliptic::POINT_COORD_JACOBIAN,
                                                       core::SCALAR_PRE_5,
                                                       true));

        if (core::SCALAR_BINARY_DUAL == coding) {
            m_ecdsa->setup(*m_params.base.get(), *m_params.base_dual.get());
        }
        else {
            m_ecdsa->setup(*m_params.base.get());
        }
    }

    void binary_setup()
    {
        m_params.cfg.mod.mod = core::mpz<T>(m_params.curve->p, 16);
        m_params.cfg.mod.mod_bits = m_params.cfg.mod.mod.sizeinbase(2);
        m_params.cfg.mod.k =
            (m_params.curve->num_bits + std::numeric_limits<T>::digits - 1) >> core::bits_log2<T>::value();
        m_params.cfg.mod.blog2 = std::numeric_limits<T>::digits;
        m_params.cfg.mod.reduction = core::REDUCTION_NAIVE;
        m_params.cfg.a = std::shared_ptr<core::mp<T>>(new core::mp_gf2n<T>(m_params.curve->a, m_params.curve->p, 16));
        m_params.cfg.b = std::shared_ptr<core::mp<T>>(new core::mp_gf2n<T>(m_params.curve->b, m_params.curve->p, 16));
        m_params.cfg.a_is_1 = m_params.cfg.a->is_one();
        m_params.cfg.a_is_zero = m_params.cfg.a->is_zero();
        m_params.cfg.b_is_1 = m_params.cfg.b->is_one();
        m_params.n = m_params.curve->num_bytes;

        m_params.n_mod.mod = core::mpz<T>(m_params.curve->order_m, 16);
        m_params.n_mod.mod_bits = m_params.n_mod.mod.sizeinbase(2);
        m_params.n_mod.k =
            (m_params.curve->num_bits + std::numeric_limits<T>::digits - 1) >> core::bits_log2<T>::value();
        m_params.n_mod.blog2 = std::numeric_limits<T>::digits;
        m_params.n_mod.reduction = core::REDUCTION_BARRETT;

        core::mpz<T> temp_n;
        temp_n.setbit(m_params.n_mod.blog2 * m_params.n_mod.k * 2);
        core::mpz<T>::tdiv_qr(m_params.n_mod.mod_inv, m_params.n_mod.mont_R2, temp_n, m_params.n_mod.mod);

        core::mp_gf2n<T> g_x(m_params.curve->g_x, m_params.curve->p, 16);
        core::mp_gf2n<T> g_y(m_params.curve->g_y, m_params.curve->p, 16);
        m_params.base = std::unique_ptr<elliptic::point<T>>(
            new elliptic::weierstrass_binary_affine<T>(m_params.cfg, g_x, g_y));

        m_ecdsa    = std::unique_ptr<elliptic::ecc<T>>(new elliptic::ecc<T>(m_params.cfg,
                                                       m_params.field,
                                                       elliptic::POINT_COORD_JACOBIAN,
                                                       core::SCALAR_PRE_8,
                                                       true));
        m_ecdsa_pk = std::unique_ptr<elliptic::ecc<T>>(new elliptic::ecc<T>(m_params.cfg,
                                                       m_params.field,
                                                       elliptic::POINT_COORD_JACOBIAN,
                                                       core::SCALAR_PRE_5,
                                                       true));

        m_ecdsa->setup(*m_params.base.get());
    }

    const pkc_e  m_scheme;
    const size_t m_set;

    const phantom_vector<std::string> m_sets = {
        "P192",
        "P224",
        "P256",
        "P384",
        "P521",
        "B163",
        "B233",
        "B283",
        "B409",
        "B571",
        "K163",
        "K233",
        "K283",
        "K409",
        "K571"
    };

    /// The DLP IBE parameter sets
    ecdsa_set_t<T> m_params;

    std::unique_ptr<elliptic::ecc<T>> m_ecdsa;
    std::unique_ptr<elliptic::ecc<T>> m_ecdsa_pk;

    core::mpz<T> m_order_G;

    std::unique_ptr<elliptic::point<T>> m_public_key;

    phantom_vector<uint8_t> m_sk;
    phantom_vector<uint8_t> m_pk;
};

}  // namespace schemes
}  // namespace phantom
