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
#include "schemes/kem/kyber/kyber_indcpa.hpp"


namespace phantom {
namespace schemes {

/// A class describing the Kyber user context
class ctx_kyber_pke : public user_ctx
{
public:
    explicit ctx_kyber_pke(size_t set) : m_scheme(PKC_KEM_KYBER), m_set(set)
    {
        m_kyber_pke = std::unique_ptr<kyber_indcpa>(new kyber_indcpa(m_set));
    }
    virtual ~ctx_kyber_pke() {}

    pkc_e get_scheme() override { return m_scheme;}
    size_t get_set() override { return m_set; }
    const std::string& get_set_name() override
    {
        static const std::string sets[] = { "Light", "Normal", "Paranoid" };
        return sets[m_set];
    }

    phantom_vector<int16_t>& s() { return m_s; }
    phantom_vector<int16_t>& t() { return m_t; }
    phantom_vector<uint16_t>& t_ntt() { return m_t_ntt; }
    uint8_t* rho() { return m_rho; }
    uint8_t* z() { return m_z; }
    kyber_indcpa* pke() { return m_kyber_pke.get(); }

private:
    const pkc_e  m_scheme;
    const size_t m_set;

    std::unique_ptr<kyber_indcpa> m_kyber_pke;

    phantom_vector<int16_t> m_s;
    phantom_vector<int16_t> m_t;
    phantom_vector<uint16_t> m_t_ntt;
    alignas(DEFAULT_MEM_ALIGNMENT) uint8_t m_rho[32];
    alignas(DEFAULT_MEM_ALIGNMENT) uint8_t m_z[32];
};

}  // namespace schemes
}  // namespace phantom
