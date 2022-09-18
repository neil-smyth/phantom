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

#include "./phantom.hpp"
#include "./phantom_memory.hpp"
#include "schemes/kem/saber/saber_indcpa.hpp"
#include "crypto/hash_sha3.hpp"
#include "crypto/hash.hpp"


namespace phantom {
namespace schemes {

/// A class describing the saber user context
class ctx_saber : public user_ctx
{
public:
    explicit ctx_saber(size_t set) : m_scheme(PKC_KEM_SABER), m_set(set)
    {
        m_saber_pke = std::unique_ptr<saber_indcpa>(new saber_indcpa(m_set));
        m_hash = std::unique_ptr<crypto::hash>(new crypto::hash_sha3());
    }
    virtual ~ctx_saber() {}

    pkc_e get_scheme() override { return m_scheme;}
    size_t get_set() override { return m_set; }
    const std::string& get_set_name() override { return m_sets[m_set]; }
    const phantom_vector<std::string>& get_set_names() { return m_sets; }

    phantom_vector<uint8_t>& pk() { return m_pk; }
    phantom_vector<uint8_t>& sk() { return m_sk; }
    phantom_vector<uint8_t>& pkh() { return m_pkh; }
    uint8_t* z() { return m_z; }
    saber_indcpa* pke() { return m_saber_pke.get(); }
    crypto::hash* get_hash() { return m_hash.get(); }

private:
    const pkc_e  m_scheme;
    const size_t m_set;

    const phantom_vector<std::string> m_sets = { "LightSaber", "Saber", "FireSaber" };

    std::unique_ptr<saber_indcpa> m_saber_pke;
    std::unique_ptr<crypto::hash> m_hash;

    phantom_vector<uint8_t> m_pk;
    phantom_vector<uint8_t> m_sk;
    phantom_vector<uint8_t> m_pkh;
    alignas(DEFAULT_MEM_ALIGNMENT) uint8_t m_z[32];
};

}  // namespace schemes
}  // namespace phantom
