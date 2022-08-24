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

#include "./phantom.hpp"
#include "./phantom_memory.hpp"
#include "schemes/kem/saber/saber_indcpa.hpp"
#include "schemes/pke/saber/ctx_saber_pke.hpp"


namespace phantom {
namespace schemes {

/// A class describing the saber user context
class ctx_saber_pke : public user_ctx
{
public:
    explicit ctx_saber_pke(size_t set) : m_scheme(PKC_KEM_SABER), m_set(set)
    {
        m_saber_indcpa = std::unique_ptr<saber_indcpa>(new saber_indcpa(m_set));
    }
    virtual ~ctx_saber_pke() {}

    virtual pkc_e get_scheme() { return m_scheme;}
    virtual size_t get_set() { return m_set; }

    phantom_vector<uint8_t>& pk() { return m_pk; }
    phantom_vector<uint8_t>& sk() { return m_sk; }
    saber_indcpa* pke() { return m_saber_indcpa.get(); }

private:
    const pkc_e  m_scheme;
    const size_t m_set;

    std::unique_ptr<saber_indcpa> m_saber_indcpa;

    phantom_vector<uint8_t> m_pk;
    phantom_vector<uint8_t> m_sk;
};

}  // namespace schemes
}  // namespace phantom
