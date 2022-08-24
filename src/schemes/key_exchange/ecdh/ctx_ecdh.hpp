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

#include "./phantom.hpp"
#include "./phantom_memory.hpp"
#include "ecc/curves.hpp"
#include "core/mpz.hpp"
#include "core/mp_gf2n.hpp"
#include "ecc/ecc.hpp"


namespace phantom {
namespace schemes {

/// Definitions for the ECDH parameter sets
template<class T>
struct ecdh_set_t
{
    uint16_t                            set;
    elliptic::field_e                   field;
    size_t                              n;           ///< Length of the ring polynomial
    const elliptic::ec_params_t*        curve;
    elliptic::ecc_config<T>             cfg;
    std::unique_ptr<elliptic::point<T>> base;

    ecdh_set_t() {}
    virtual ~ecdh_set_t() {}
    ecdh_set_t(ecdh_set_t&&) = default;
};

template<typename T>
class mod_solinas_secp192r1 : public core::mod_custom<T>
{
private:

public:
    mod_solinas_secp192r1() {}
    virtual ~mod_solinas_secp192r1() {}

    virtual core::mpz<T>& reduce(core::mpz<T>& a, const core::mod_config<T>& cfg)
    {
        return static_reduce(a, cfg);
    }

    static core::mpz<uint64_t>& static_reduce(core::mpz<uint64_t>& a, const core::mod_config<uint64_t>& cfg)
    {
        while (a.is_negative()) {
            a = a + cfg.mod;
        }

        if (a < cfg.mod) {
            return a;
        }

        phantom_vector<uint64_t> v;
        a.get_words(v);
        v.resize(6);

        uint64_t cc = 0;
        uint64_t temp = v[0];
        temp  += v[3];
        cc    += (temp - v[3]) >> 63;
        temp  += v[5];
        cc    += (temp - v[5]) >> 63;
        v[0]   = temp;
        temp   = v[1] + cc;
        cc     = (temp - cc) >> 63;
        temp  += v[3];
        cc    += (temp - v[3]) >> 63;
        temp  += v[4];
        cc    += (temp - v[4]) >> 63;
        temp  += v[5];
        cc    += (temp - v[5]) >> 63;
        v[1]   = temp;
        temp   = v[2] + cc;
        cc     = (temp - v[2]) >> 63;
        temp  += v[4];
        cc    += (temp - v[4]) >> 63;
        temp  += v[5];
        cc    += (temp - v[5]) >> 63;
        v[2]   = temp;
        v[3]   = cc;
        v.resize(4);
        a.set_words(v);

        if (a >= cfg.mod) {
            a = a - cfg.mod;
        }
        return a;
    }

    static core::mpz<uint32_t>& static_reduce(core::mpz<uint32_t>& a, const core::mod_config<uint32_t>& cfg)
    {
        while (a.is_negative()) {
            a = a + cfg.mod;
        }

        if (a < cfg.mod) {
            return a;
        }

        phantom_vector<uint32_t> v;
        a.get_words(v);
        v.resize(12);
        uint32_t t[6] = { v[0], v[1], v[2], v[3], v[4], v[5] };
        uint32_t s1[6] = { v[6], v[6], v[6], v[6], 0, 0 };
        uint32_t s2[6] = { 0, 0, v[4], v[4], v[4], v[4] };
        uint32_t s3[6] = { v[5], v[5], v[5], v[5], v[5], v[5] };
        v.resize(8);

        uint32_t cc = 0;
        for (size_t i=0; i < 6; i++) {
            uint32_t temp = t[i] + cc;
            cc     = temp < cc;
            temp  += s1[i];
            cc    += temp < s1[i];
            temp  += s2[i];
            cc    += temp < s2[i];
            temp  += s3[i];
            cc    += temp < s3[i];
            v[i]   = temp;
        }
        v[6] = cc;
        a.set_words(v);

        while (a >= cfg.mod) {
            a = a - cfg.mod;
        }
        return a;
    }

    static core::mpz<uint16_t>& static_reduce(core::mpz<uint16_t>& a, const core::mod_config<uint16_t>& cfg)
    {
        return a;
    }
};

/**
 * @brief An ECDH context class used to store key, curve and algorithm specific parameters
 */
class ctx_ecdh : public user_ctx
{
public:
    virtual ~ctx_ecdh() {}

    virtual elliptic::field_e field() = 0;

    virtual size_t get_wordsize() = 0;
    virtual size_t get_log2_wordsize() = 0;
    virtual phantom_vector<uint8_t>& sk() = 0;
    virtual size_t n() = 0;
    virtual size_t get_curve_bits() = 0;
    virtual size_t get_curve_bytes() = 0;
    virtual const char* get_modulus() const = 0;
};

/// A class describing the ECDH user context
template<class T>
class ctx_ecdh_tmpl : public ctx_ecdh
{
public:
    explicit ctx_ecdh_tmpl(size_t set) : m_scheme(PKC_KEY_ECDH), m_set(set)
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

            case 15: m_params.curve = &elliptic::curves::param_ec_curve25519;
                     m_params.field = elliptic::field_e::MONTGOMERY_PRIME_FIELD;
                     break;
            case 16: m_params.curve = &elliptic::curves::param_ec_curve448;
                     m_params.field = elliptic::field_e::MONTGOMERY_PRIME_FIELD;
                     break;

            default: {}
        }

        switch (m_params.field)
        {
            case elliptic::field_e::WEIERSTRASS_PRIME_FIELD:  weierstrass_prime_setup();  break;
            case elliptic::field_e::WEIERSTRASS_BINARY_FIELD: weierstrass_binary_setup(); break;
            case elliptic::field_e::MONTGOMERY_PRIME_FIELD:   montgomery_prime_setup();   break;
            default: {}
        }
    }

    virtual ~ctx_ecdh_tmpl() {}

    ctx_ecdh_tmpl(const ctx_ecdh_tmpl&) = delete;

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

    virtual pkc_e get_scheme() { return m_scheme;}
    virtual size_t get_set() { return m_set; }

    virtual phantom_vector<uint8_t>& sk() { return m_sk; }
    virtual size_t n() { return m_params.n; }
    virtual size_t get_curve_bits() { return m_params.curve->num_bits; }
    virtual size_t get_curve_bytes() { return m_params.curve->num_bytes; }
    virtual const char* get_modulus() const { return m_params.curve->p; }

    void setup_init(const elliptic::point<T>& p_base)
    {
        m_ecdh_init->setup(p_base);
    }

    void scalar_point_mul_init(const phantom_vector<uint8_t>& secret)
    {
        m_ecdh_init->scalar_point_mul(secret);
    }

    elliptic::retcode_e get_result_init(core::mp<T>* x, core::mp<T>* y)
    {
        return m_ecdh_init->get(x, y);
    }

    void setup_final(const elliptic::point<T>& p_base)
    {
        m_ecdh_final->setup(p_base);
    }

    void scalar_point_mul_final(const phantom_vector<uint8_t>& secret)
    {
        m_ecdh_final->scalar_point_mul(secret);
    }

    elliptic::retcode_e get_result_final(core::mp<T>* x, core::mp<T>* y)
    {
        return m_ecdh_final->get(x, y);
    }

    elliptic::ecc_config<T>& get_configuration()
    {
        return m_params.cfg;
    }

    elliptic::point<T>& get_base()
    {
        return *m_params.base.get();
    }

private:
    void weierstrass_prime_setup()
    {
        m_cst = std::unique_ptr<core::mod_custom<T>>(new mod_solinas_secp192r1<T>());
        m_params.cfg.mod.cst = m_cst.get();

        m_params.cfg.mod.mod = core::mpz<T>(m_params.curve->p, 16);
        m_params.cfg.mod.mod_bits = m_params.cfg.mod.mod.sizeinbase(2);
        m_params.cfg.mod.k =
            (m_params.curve->num_bits + std::numeric_limits<T>::digits - 1) >> core::bits_log2<T>::value();
        m_params.cfg.mod.blog2 = std::numeric_limits<T>::digits;
        m_params.cfg.mod.reduction = core::REDUCTION_MONTGOMERY;
        auto a = new core::mpz<T>(m_params.curve->a, 16);
        m_params.cfg.a = std::shared_ptr<core::mp<T>>(a);
        m_params.cfg.a_is_minus_3 = m_params.cfg.a->get_str(16) == "-3";
        if (a->is_negative()) {
            *a += m_params.cfg.mod.mod;
        }
        m_params.n = m_params.curve->num_bytes;

        core::mpz<T> temp;
        temp.setbit(m_params.cfg.mod.blog2 *  m_params.cfg.mod.k * 2);
        core::mpz<T>::tdiv_qr(m_params.cfg.mod.mod_inv, m_params.cfg.mod.mont_R2, temp, m_params.cfg.mod.mod);

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

        core::mpz<T> g_x(m_params.curve->g_x, 16);
        core::mpz<T> g_y(m_params.curve->g_y, 16);
        m_params.base = std::unique_ptr<elliptic::point<T>>(
            new elliptic::weierstrass_prime_affine<T>(m_params.cfg, g_x, g_y));

        m_ecdh_init  = std::unique_ptr<elliptic::ecc<T>>(new elliptic::ecc<T>(m_params.cfg,
                                                         m_params.field,
                                                         elliptic::POINT_COORD_JACOBIAN,
                                                         core::ECC_PRE_8,
                                                         true));
        m_ecdh_final = std::unique_ptr<elliptic::ecc<T>>(new elliptic::ecc<T>(m_params.cfg,
                                                         m_params.field,
                                                         elliptic::POINT_COORD_JACOBIAN,
                                                         core::ECC_PRE_5,
                                                         true));
    }

    void montgomery_prime_setup()
    {
        m_params.cfg.mod.mod = core::mpz<T>(m_params.curve->p, 16);
        m_params.cfg.mod.mod_bits = m_params.cfg.mod.mod.sizeinbase(2);
        m_params.cfg.mod.k =
            (m_params.curve->num_bits + std::numeric_limits<T>::digits - 1) >> core::bits_log2<T>::value();
        m_params.cfg.mod.blog2 = std::numeric_limits<T>::digits;
        m_params.cfg.mod.reduction = core::REDUCTION_MONTGOMERY;
        auto a = new core::mpz<T>(m_params.curve->a, 16);
        m_params.cfg.a = std::shared_ptr<core::mp<T>>(a);
        m_params.cfg.a_is_minus_1 = m_params.cfg.a->get_str(16) == "-1";
        if (a->is_negative()) {
            *a += m_params.cfg.mod.mod;
        }
        auto b = new core::mpz<T>(m_params.curve->b, 16);
        m_params.cfg.b = std::shared_ptr<core::mp<T>>(b);
        if (b->is_negative()) {
            *b += m_params.cfg.mod.mod;
        }
        auto d = new core::mpz<T>(m_params.curve->a, 16);
        *d = (*d + T(2)) >> 2;
        m_params.cfg.d = std::shared_ptr<core::mp<T>>(d);
        if (d->is_negative()) {
            *d += m_params.cfg.mod.mod;
        }
        m_params.n = m_params.curve->num_bytes;

        core::mpz<T> temp;
        temp.setbit(m_params.cfg.mod.blog2 *  m_params.cfg.mod.k * 2);
        core::mpz<T>::tdiv_qr(m_params.cfg.mod.mod_inv, m_params.cfg.mod.mont_R2, temp, m_params.cfg.mod.mod);

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
            b->mul_mont(m_params.cfg.mod.mont_R2, m_params.cfg.mod);
            d->mul_mont(m_params.cfg.mod.mont_R2, m_params.cfg.mod);
        }

        core::mpz<T> g_x(m_params.curve->g_x, 16);
        core::mpz<T> g_y(m_params.curve->g_y, 16);
        m_params.base = std::unique_ptr<elliptic::point<T>>(
            new elliptic::montgomery_prime_affine<T>(m_params.cfg, g_x, g_y));

        m_ecdh_init  = std::unique_ptr<elliptic::ecc<T>>(new elliptic::ecc<T>(m_params.cfg,
                                                         m_params.field,
                                                         elliptic::POINT_COORD_PROJECTIVE,
                                                         core::ECC_MONT_LADDER,
                                                         false));
        m_ecdh_final = std::unique_ptr<elliptic::ecc<T>>(new elliptic::ecc<T>(m_params.cfg,
                                                         m_params.field,
                                                         elliptic::POINT_COORD_PROJECTIVE,
                                                         core::ECC_MONT_LADDER,
                                                         false));
    }

    void weierstrass_binary_setup()
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

        core::mp_gf2n<T> g_x(m_params.curve->g_x, m_params.curve->p, 16);
        core::mp_gf2n<T> g_y(m_params.curve->g_y, m_params.curve->p, 16);
        m_params.base = std::unique_ptr<elliptic::point<T>>(
            new elliptic::weierstrass_binary_affine<T>(m_params.cfg, g_x, g_y));

        m_ecdh_init  = std::unique_ptr<elliptic::ecc<T>>(new elliptic::ecc<T>(m_params.cfg,
                                                         m_params.field,
                                                         elliptic::POINT_COORD_JACOBIAN,
                                                         core::ECC_PRE_8,
                                                         true));
        m_ecdh_final = std::unique_ptr<elliptic::ecc<T>>(new elliptic::ecc<T>(m_params.cfg,
                                                         m_params.field,
                                                         elliptic::POINT_COORD_JACOBIAN,
                                                         core::ECC_PRE_5,
                                                         true));
    }

    const pkc_e  m_scheme;
    const size_t m_set;

    /// The DLP IBE parameter sets
    ecdh_set_t<T> m_params;

    std::unique_ptr<elliptic::ecc<T>> m_ecdh_init;
    std::unique_ptr<elliptic::ecc<T>> m_ecdh_final;

    std::unique_ptr<core::mod_custom<T>> m_cst;

    phantom_vector<uint8_t> m_sk;
};

}  // namespace schemes
}  // namespace phantom
