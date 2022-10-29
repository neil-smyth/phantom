/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <string>
#include <memory>

#include "schemes/signature/signature.hpp"
#include "crypto/csprng.hpp"
#include "crypto/random_seed.hpp"
#include "core/reduction_montgomery.hpp"
#include "core/ntt_binary.hpp"
#include "crypto/xof_sha3.hpp"
#include "sampling/gaussian_cdf.hpp"


namespace phantom {
namespace schemes {

/// Definitions for the Falcon parameters
struct falcon_set_t {
    uint16_t set;
    uint32_t q;
    uint32_t inv_q;
    uint16_t q_bits;
    uint16_t n;
    uint16_t n_bits;
    uint32_t g;
    uint32_t inv_g;
    uint32_t R;
    uint32_t R2;
    float    bd;
};

/// A class describing the Falcon user context
class ctx_falcon : public user_ctx
{
    using reducer_falcon   = core::montgomery<uint32_t>;
    using reduction_falcon = core::reduction_montgomery<uint32_t>;
    using ntt_falcon       = core::ntt_binary<reduction_falcon, uint32_t>;
    using gaussian_falcon  = sampling::gaussian<int32_t, uint64_t>;

public:
    explicit ctx_falcon(size_t set) :
        m_scheme(PKC_SIG_FALCON),
        m_set(set),
        m_reduce(reducer_falcon(m_params[set].q, m_params[set].inv_q, 31,
                                m_params[set].R, m_params[set].R2)),
        m_reduction(m_reduce)
    {
        if (m_set > 2) {
            throw std::invalid_argument("Parameter set is out of range");
        }

        uint32_t q     = m_params[m_set].q;
        uint32_t g     = m_params[m_set].g;
        size_t   n     = m_params[m_set].n;
        ntt_falcon* ntt32 = new ntt_falcon(m_reduction, g, n);
        if (!ntt32) {
            throw std::invalid_argument("NTT object could not be instantiated");
        }
        m_ntt          = std::unique_ptr<ntt_falcon>(ntt32);

        float    sigma = 1.17 * sqrt(q / (2 * n));
        m_prng         = std::shared_ptr<csprng>(csprng::make(0x10000000, random_seed::seed_cb));
        gaussian_falcon* sampler = new sampling::gaussian_cdf<int32_t, uint64_t>(m_prng, sigma, 10.0f);
        if (!sampler) {
            throw std::invalid_argument("Gaussian sampler object could not be instantiated");
        }
        m_gaussian     = std::unique_ptr<gaussian_falcon>(sampler);

        m_xof          = std::unique_ptr<crypto::xof_sha3>(new crypto::xof_sha3());
    }
    virtual ~ctx_falcon() {}

    /// The Falcon parameter sets
    static const falcon_set_t m_params[2];

    pkc_e get_scheme() override { return m_scheme;}
    size_t get_set() override { return m_set; }
    const std::string& get_set_name() override { return m_sets[m_set]; }
    const phantom_vector<std::string>& get_set_names() { return m_sets; }

    phantom_vector<int32_t>& f() { return m_f; }
    phantom_vector<int32_t>& g() { return m_g; }
    phantom_vector<int32_t>& F() { return m_F; }
    phantom_vector<int32_t>& G() { return m_G; }
    phantom_vector<double>& master_tree() { return m_master_tree; }
    phantom_vector<int32_t>& h() { return m_h; }
    phantom_vector<uint32_t>& h_ntt() { return m_h_ntt; }
    phantom_vector<int32_t>& s1() { return m_s1; }
    phantom_vector<uint32_t>& s1_ntt() { return m_s1_ntt; }
    phantom_vector<int32_t>& s2() { return m_s2; }
    phantom_vector<uint32_t>& s2_ntt() { return m_s2_ntt; }

    const reduction_falcon& get_reduction() { return m_reduction; }
    std::shared_ptr<csprng> get_csprng() { return m_prng; }
    ntt_falcon* get_ntt() { return m_ntt.get(); }
    gaussian_falcon* get_gaussian() { return m_gaussian.get(); }
    crypto::xof_sha3* get_xof() { return m_xof.get(); }

private:
    const pkc_e              m_scheme;       ///< The crypto scheme associated with this user
    const size_t             m_set;          ///< The parameter set associated with this user
    phantom_vector<int32_t>  m_f;
    phantom_vector<int32_t>  m_g;
    phantom_vector<int32_t>  m_F;
    phantom_vector<int32_t>  m_G;
    phantom_vector<double>   m_master_tree;  ///< The master tree derived from the private key(s)
    phantom_vector<int32_t>  m_h;            ///< The public key
    phantom_vector<uint32_t> m_h_ntt;        ///< The public key in NTT domain and Montgomery representation
    phantom_vector<int32_t>  m_s1;
    phantom_vector<uint32_t> m_s1_ntt;
    phantom_vector<int32_t>  m_s2;
    phantom_vector<uint32_t> m_s2_ntt;

    const phantom_vector<std::string> m_sets = { "512", "1024" };

    const reducer_falcon              m_reduce;
    const reduction_falcon            m_reduction;
    std::shared_ptr<csprng>           m_prng;
    std::unique_ptr<ntt_falcon>       m_ntt;
    std::unique_ptr<crypto::xof_sha3> m_xof;
    std::unique_ptr<gaussian_falcon>  m_gaussian;  ///< The selected Gaussian sampler
};

}  // namespace schemes
}  // namespace phantom


