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

#include "./phantom.hpp"
#include "./phantom_memory.hpp"
#include "crypto/hash_sha2.hpp"
#include "crypto/hash_sha3.hpp"
#include "core/mpz.hpp"


namespace phantom {
namespace rsa {

/// Definitions for the RSA parameters
struct rsa_set_t {
    uint16_t    set;
    hash_alg_e  hash;
    uint16_t    n_bits;
    const char* e;
};

/// A class describing the Kyber user context
class ctx_rsa : public user_ctx
{
public:
    virtual ~ctx_rsa() {}

    virtual size_t get_wordsize() = 0;
    virtual size_t get_mod_bits() = 0;
    virtual size_t get_mod_bytes() = 0;
    virtual pkc_e get_scheme() = 0;
    virtual size_t get_set() = 0;

    virtual void setup_mod() = 0;

    virtual void set_label(phantom_vector<uint8_t>& label) = 0;
    virtual phantom_vector<uint8_t>& get_label() = 0;
    virtual bool set_hash(hash_alg_e alg) = 0;
    virtual crypto::hash* get_hash() = 0;
    virtual size_t get_hlen() = 0;
    virtual size_t get_saltlen() = 0;
};


template<typename T>
class rsa_cryptosystem;


/// A class describing the RSA PKE user context
template<class T>
class ctx_rsa_tmpl : public ctx_rsa
{
public:
    ctx_rsa_tmpl(pkc_e scheme, hash_alg_e hash, uint32_t min_exp_bits, size_t set,
                 const phantom::rsa::rsa_set_t *params, size_t num_params, bool masking)
     : m_scheme(scheme), m_set(set)
    {
        m_params = phantom_vector<phantom::rsa::rsa_set_t>(params, params + num_params);
        for (phantom::rsa::rsa_set_t p : m_params) {
            m_sets.push_back(std::to_string(p.n_bits));
        }

        m_rsa_pke = std::unique_ptr<phantom::rsa::rsa_cryptosystem<T>>(
            new phantom::rsa::rsa_cryptosystem<T>(min_exp_bits, core::scalar_coding_e::SCALAR_BINARY, masking));

        if (!set_hash(hash)) {
            throw std::runtime_error("Hash is unknown");
        }
    }

    virtual ~ctx_rsa_tmpl() {}

    ctx_rsa_tmpl(const ctx_rsa_tmpl&) = delete;

    virtual size_t get_wordsize()
    {
        return std::numeric_limits<T>::digits;
    }

    virtual size_t get_mod_bits()
    {
        switch (m_set & 0xff)
        {
            case 0 : return 1024;
            case 1 : return 1536;
            case 2 : return 2048;
            case 3 : return 3072;
            case 4 : return 4096;
        }

        return 0;
    }

    virtual size_t get_mod_bytes()
    {
        return (get_mod_bits() + 7) >> 3;
    }

    pkc_e get_scheme() override { return m_scheme;}
    size_t get_set() override { return m_set; }
    const std::string& get_set_name() override { return m_sets[m_set]; }
    const phantom_vector<std::string>& get_set_names() { return m_sets; }

    virtual core::mod_config<T>& mod() { return m_mod; }
    virtual core::mod_config<T>& pmod() { return m_pmod; }
    virtual core::mod_config<T>& qmod() { return m_qmod; }

    virtual phantom::rsa::rsa_cryptosystem<T>* pke() { return m_rsa_pke.get(); }

    core::mpz<T>& n() { return m_n; }
    core::mpz<T>& e() { return m_e; }
    core::mpz<T>& d() { return m_d; }
    core::mpz<T>& p() { return m_p; }
    core::mpz<T>& q() { return m_q; }
    core::mpz<T>& exp1() { return m_exp1; }
    core::mpz<T>& exp2() { return m_exp2; }
    core::mpz<T>& inv() { return m_inv; }

    static void setup_mod_basic(core::mod_config<T>& cfg, core::mpz<T>& n)
    {
        cfg.mod = n;
        cfg.mod_bits = n.sizeinbase(2);
        cfg.k = (n.sizeinbase(2) + std::numeric_limits<T>::digits - 1) >> core::bits_log2<T>::value();
        cfg.blog2 = std::numeric_limits<T>::digits;
        cfg.reduction = core::REDUCTION_MONTGOMERY;

        core::mpz<T> temp;
        temp.setbit(cfg.blog2 *  cfg.k * 2);
        core::mpz<T>::tdiv_qr(cfg.mod_inv, cfg.mont_R2, temp, n);

        if (core::REDUCTION_MONTGOMERY == cfg.reduction) {
            core::mpz<T> R, temp_m, s, t;
            R.setbit(std::numeric_limits<T>::digits * cfg.k);
            temp_m = n;
            core::mpz<T>::gcdext(temp, s, t, R, temp_m);
            cfg.mont_inv = 0;
            if (t.get_limbsize() > 0) {
                cfg.mont_inv = t.is_negative()? t[0] : -t[0];  // (R[0] - t[0]) mod B, R[0] is always 0
            }
        }
    }

    virtual void setup_mod()
    {
        setup_mod_basic(m_mod, m_n);
        setup_mod_basic(m_pmod, m_p);
        setup_mod_basic(m_qmod, m_q);
    }

    virtual void set_label(phantom_vector<uint8_t>& label)
    {
        m_label = label;
    }

    virtual phantom_vector<uint8_t>& get_label()
    {
        return m_label;
    }

    virtual bool set_hash(hash_alg_e alg)
    {
        m_hash_alg = alg;

        switch (alg)
        {
        case HASH_SHA2_224:
            m_hblocklen = 28; m_hlen = 28; m_hash = std::unique_ptr<crypto::hash>(new crypto::hash_sha2());
            break;
        case HASH_SHA2_256:
            m_hblocklen = 32; m_hlen = 32; m_hash = std::unique_ptr<crypto::hash>(new crypto::hash_sha2());
            break;
        case HASH_SHA2_384:
            m_hblocklen = 48; m_hlen = 48; m_hash = std::unique_ptr<crypto::hash>(new crypto::hash_sha2());
            break;
        case HASH_SHA2_512:
            m_hblocklen = 64; m_hlen = 64; m_hash = std::unique_ptr<crypto::hash>(new crypto::hash_sha2());
            break;
        case HASH_SHA2_512_224:
            m_hblocklen = 64; m_hlen = 28; m_hash = std::unique_ptr<crypto::hash>(new crypto::hash_sha2());
            break;
        case HASH_SHA2_512_256:
            m_hblocklen = 64; m_hlen = 32; m_hash = std::unique_ptr<crypto::hash>(new crypto::hash_sha2());
            break;

        case HASH_SHA3_224:
            m_hblocklen = 28; m_hlen = 28; m_hash = std::unique_ptr<crypto::hash>(new crypto::hash_sha3());
            break;
        case HASH_SHA3_256:
            m_hblocklen = 32; m_hlen = 32; m_hash = std::unique_ptr<crypto::hash>(new crypto::hash_sha3());
            break;
        case HASH_SHA3_384:
            m_hblocklen = 48; m_hlen = 48; m_hash = std::unique_ptr<crypto::hash>(new crypto::hash_sha3());
            break;
        case HASH_SHA3_512:
            m_hblocklen = 64; m_hlen = 64; m_hash = std::unique_ptr<crypto::hash>(new crypto::hash_sha3());
            break;

        default: return false;
        }

        return true;
    }

    virtual crypto::hash* get_hash()
    {
        return m_hash.get();
    }

    virtual size_t get_hlen()
    {
        return m_hlen;
    }

    virtual size_t get_hblocklen()
    {
        return m_hblocklen;
    }

    virtual size_t get_saltlen()
    {
        return (m_set >> 16) & 0xff;
    }

private:
    const pkc_e  m_scheme;
    const size_t m_set;

    phantom_vector<phantom::rsa::rsa_set_t> m_params;

    phantom_vector<std::string> m_sets;

    std::unique_ptr<phantom::rsa::rsa_cryptosystem<T>> m_rsa_pke;

    std::unique_ptr<crypto::hash> m_hash;

    core::mod_config<T> m_mod;
    core::mod_config<T> m_pmod;
    core::mod_config<T> m_qmod;

    phantom_vector<uint8_t> m_label;
    size_t m_hlen;
    size_t m_hblocklen;
    hash_alg_e m_hash_alg;

    core::mpz<T> m_n;
    core::mpz<T> m_e;
    core::mpz<T> m_d;
    core::mpz<T> m_p;
    core::mpz<T> m_q;
    core::mpz<T> m_exp1;
    core::mpz<T> m_exp2;
    core::mpz<T> m_inv;
};

}  // namespace rsa
}  // namespace phantom
