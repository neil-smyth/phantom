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

#include "schemes/ibe/ibe.hpp"
#include "crypto/csprng.hpp"
#include "core/reduction_montgomery.hpp"
#include "core/ntt_binary.hpp"
#include "crypto/random_seed.hpp"
#include "crypto/xof_sha3.hpp"
#include "sampling/gaussian_cdf.hpp"


namespace phantom {
namespace schemes {

/// Definitions for the DLP IBE parameters
struct ibe_dlp_set_t {
    uint16_t set;
    size_t   logn;        ///< Length of the ring polynomial in base-2
    size_t   n;           ///< Length of the ring polynomial
    uint32_t q;
    uint32_t inv_q;
    size_t   q_bits;
    uint32_t l;
    uint32_t scale;
    uint32_t g;
    uint32_t inv_g;
    uint32_t R;
    uint32_t R2;
};

/// A class describing the DLP IBE user context
class ctx_ibe_dlp : public user_ctx
{
    using reducer_dlp_ibe   = core::montgomery<uint32_t>;
    using reduction_dlp_ibe = core::reduction_montgomery<uint32_t>;
    using ntt_dlp_ibe       = core::ntt_binary<reduction_dlp_ibe, uint32_t>;
    using gaussian_dlp_ibe  = sampling::gaussian<int32_t, uint64_t>;

    const phantom_vector<std::string> m_sets = { "Light", "Normal" };

public:
    explicit ctx_ibe_dlp(size_t set) :
        m_scheme(PKC_IBE_DLP),
        m_set(set),
        m_reduce(reducer_dlp_ibe(m_params[set].q, m_params[set].inv_q, 31,
                                    m_params[set].R, m_params[set].R2)),
        m_reduction(m_reduce)
    {
        if (m_set > 4) {
            throw std::invalid_argument("Parameter set is out of range");
        }

        uint32_t q     = m_params[m_set].q;
        uint32_t g     = m_params[m_set].g;
        size_t   n     = m_params[m_set].n;
        ntt_dlp_ibe* ntt32 = new ntt_dlp_ibe(m_reduction, g, n);
        if (!ntt32) {
            throw std::invalid_argument("NTT object could not be instantiated");
        }
        m_ntt          = std::unique_ptr<ntt_dlp_ibe>(ntt32);

        float    sigma = 1.17 * sqrt(q / (2 * n));
        m_prng         = std::shared_ptr<csprng>(csprng::make(0x10000000, random_seed::seed_cb));
        gaussian_dlp_ibe* sampler = new sampling::gaussian_cdf<int32_t, uint64_t>(m_prng, sigma, 10.0f);
        if (!sampler) {
            throw std::invalid_argument("Gaussian sampler object could not be instantiated");
        }
        m_gaussian     = std::unique_ptr<gaussian_dlp_ibe>(sampler);

        m_xof          = std::unique_ptr<crypto::xof_sha3>(new crypto::xof_sha3());
    }
    virtual ~ctx_ibe_dlp() {}

    /// The DLP IBE parameter sets
    static const ibe_dlp_set_t m_params[2];

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

    const reduction_dlp_ibe& get_reduction() { return m_reduction; }
    std::shared_ptr<csprng> get_csprng() { return m_prng; }
    ntt_dlp_ibe* get_ntt() { return m_ntt.get(); }
    gaussian_dlp_ibe* get_gaussian() { return m_gaussian.get(); }
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

    const reducer_dlp_ibe             m_reduce;
    const reduction_dlp_ibe           m_reduction;
    std::shared_ptr<csprng>           m_prng;
    std::unique_ptr<ntt_dlp_ibe>      m_ntt;
    std::unique_ptr<crypto::xof_sha3> m_xof;
    std::unique_ptr<gaussian_dlp_ibe> m_gaussian;  ///< The selected Gaussian sampler
};

}  // namespace schemes
}  // namespace phantom
