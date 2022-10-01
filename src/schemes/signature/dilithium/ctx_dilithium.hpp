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
#include "crypto/csprng.hpp"
#include "crypto/random_seed.hpp"
#include "core/reduction_montgomery.hpp"
#include "core/ntt_binary.hpp"
#include "crypto/xof_sha3.hpp"
#include "sampling/gaussian_cdf.hpp"


namespace phantom {
namespace schemes {

/// A class describing the Dilithium user context
class ctx_dilithium : public user_ctx
{
    using reducer_dilithium   = core::montgomery<uint32_t>;
    using reduction_dilithium = core::reduction_montgomery<uint32_t>;
    using ntt_dilithium       = core::ntt_binary<reduction_dilithium, uint32_t>;

public:
    explicit ctx_dilithium(size_t set) :
        m_scheme(PKC_SIG_DILITHIUM),
        m_set(set % 5),
        m_dilithium(std::unique_ptr<dilithium>(new dilithium(m_set))),
        m_reduce(reducer_dilithium(m_dilithium->get_params()->q, m_dilithium->get_params()->inv_q, 32,
                                   m_dilithium->get_params()->R, m_dilithium->get_params()->R2)),
        m_reduction(m_reduce)
    {
        uint32_t g     = m_dilithium->get_params()->g;
        uint32_t inv_g = m_dilithium->get_params()->inv_g;
        size_t   n     = m_dilithium->get_params()->n;
        ntt_dilithium *ntt32 = new ntt_dilithium(m_reduction, g, inv_g, n);
        if (!ntt32) {
            throw std::invalid_argument("NTT object could not be instantiated");
        }
        m_ntt          = std::unique_ptr<ntt_dilithium>(ntt32);
        m_prng         = std::shared_ptr<csprng>(csprng::make(0x10000000, random_seed::seed_cb));

        // Sets 0-4 are deterministic, 5-9 are non-deterministic
        m_is_deterministic = (set < 5);
    }
    virtual ~ctx_dilithium() {}

    pkc_e get_scheme() override { return m_scheme;}
    size_t get_set() override { return m_is_deterministic ? m_set : m_set + 5; }
    const std::string& get_set_name() override { return m_sets[m_is_deterministic ? m_set : m_set + 5]; }
    const phantom_vector<std::string>& get_set_names() { return m_sets; }

    dilithium* get_dilithium() { return m_dilithium.get(); }
    const reduction_dilithium& get_reduction() { return m_reduction; }
    std::shared_ptr<csprng> get_csprng() { return m_prng; }
    ntt_dilithium* get_ntt() { return m_ntt.get(); }

    uint8_t* rho() { return m_rho; }
    uint8_t* K() { return m_K; }
    uint8_t* tr() { return m_tr; }
    phantom_vector<int32_t>& s1() { return m_s1; }
    phantom_vector<int32_t>& s2() { return m_s2; }
    phantom_vector<int32_t>& t() { return m_t; }
    phantom_vector<int32_t>& t1() { return m_t1; }
    phantom_vector<uint32_t>& ntt_s1() { return m_ntt_s1; }
    phantom_vector<uint32_t>& ntt_s2() { return m_ntt_s2; }
    phantom_vector<uint32_t>& ntt_t0() { return m_ntt_t0; }
    phantom_vector<uint32_t>& ntt_t1() { return m_ntt_t1; }

    bool is_deterministic() { return m_is_deterministic; }

private:
    alignas(DEFAULT_MEM_ALIGNMENT) uint8_t m_rho[32];  ///< ρ - a 256-bit random number
    alignas(DEFAULT_MEM_ALIGNMENT) uint8_t m_K[32];    ///< K - a 256-bit random number
    alignas(DEFAULT_MEM_ALIGNMENT) uint8_t m_tr[48];   ///< tr - a 384-bit random number

    const pkc_e              m_scheme;  ///< The crypto scheme associated with this user
    const size_t             m_set;     ///< The parameter set associated with this user
    phantom_vector<int32_t>  m_s1;      ///< The Dilithium s1 private key component
    phantom_vector<int32_t>  m_s2;      ///< The Dilithium s2 private key component
    phantom_vector<int32_t>  m_t;       ///< The Dilithium t key component
    phantom_vector<int32_t>  m_t1;      ///< The Dilithium t1 private key component
    phantom_vector<uint32_t> m_ntt_s1;  ///< The Dilithium s1 private key component in NTT domain
    phantom_vector<uint32_t> m_ntt_s2;  ///< The Dilithium s2 private key component in NTT domain
    phantom_vector<uint32_t> m_ntt_t0;  ///< The Dilithium t0 private key component in NTT domain
    phantom_vector<uint32_t> m_ntt_t1;  ///< The Dilithium s1 public key component in NTT domain

    std::unique_ptr<dilithium>     m_dilithium;
    const reducer_dilithium        m_reduce;
    const reduction_dilithium      m_reduction;
    std::shared_ptr<csprng>        m_prng;
    std::unique_ptr<ntt_dilithium> m_ntt;

    /// Flag indicating if the signature is created in a deterministic manner
    bool m_is_deterministic;

    const phantom_vector<std::string> m_sets = { "2", "3", "5", "5+", "5++",
                                                 "2-random", "3-random", "5-random", "5+-random", "5++-random" };
};

}  // namespace schemes
}  // namespace phantom


