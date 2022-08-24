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

#include "schemes/kem/kem.hpp"
#include "crypto/csprng.hpp"
#include "core/reduction_montgomery.hpp"
#include "core/ntt_binary.hpp"
#include "sampling/gaussian_cdf.hpp"
#include "crypto/xof_sha3.hpp"
#include "./phantom.hpp"


#define SABER_N         256
#define SABRE_MSG_LEN   (SABER_N/8)


namespace phantom {
namespace schemes {

/// Definitions for the Kyber parameters
struct saber_set_t {
    uint16_t set;
    uint16_t q;
    uint16_t n;
    uint16_t l;
    uint16_t p;
    uint16_t T;
    uint16_t mean;
    uint16_t eq;
    uint16_t ep;
    uint16_t et;
    uint16_t mu;
    uint16_t h1;
    uint16_t h2;
};

/// A class providing a Kyber IND-CPA PKE implementation
class saber_indcpa
{
    using red_mont     = core::reduction_montgomery<uint16_t>;
    using ntt_red_mont = core::ntt_binary<red_mont, uint16_t>;

public:
    /// Class constructor based on the required security strength
    explicit saber_indcpa(security_strength_e bits);

    /// Class constructor based on the specified parameter set
    explicit saber_indcpa(size_t set);

    /// Class destructor
    virtual ~saber_indcpa();

    static const saber_set_t m_params[3];

    static size_t bits_2_set(security_strength_e bits);

    void keygen(phantom_vector<uint8_t>& pk, phantom_vector<uint8_t>& sk);
    void enc(const phantom_vector<uint8_t>& pk, const phantom_vector<uint8_t>& pt,
        const uint8_t* _RESTRICT_ seed_s, phantom_vector<uint8_t>& ct);
    void dec(const phantom_vector<uint8_t>& sk, const phantom_vector<uint8_t>& ct,
        uint8_t* pt);

    csprng* get_prng() { return m_prng.get(); }
    crypto::xof_sha3* get_xof() { return m_xof.get(); }

private:
    // Initialize an instance of the PKE algorithm
    void init();

    static void polq2bs(uint8_t* _RESTRICT_ out, const uint16_t* _RESTRICT_ in);
    static void bs2polq(uint16_t* _RESTRICT_ out, const uint8_t* _RESTRICT_ in);
    static void polp2bs(uint8_t* _RESTRICT_ out, const uint16_t* _RESTRICT_ in);
    static void bs2polp(uint16_t* _RESTRICT_ out, const uint8_t* _RESTRICT_ in);

    void gen_matrix_shake128(uint16_t* _RESTRICT_ A, const uint8_t* seed, size_t l, size_t k);
    static uint64_t load_littleendian(const uint8_t *x, int bytes);
    static void cbd_6(const uint8_t* _RESTRICT_ buf, uint16_t* _RESTRICT_ s);
    static void cbd_8(const uint8_t* _RESTRICT_ buf, uint16_t* _RESTRICT_ s);
    static void cbd_10(const uint8_t* _RESTRICT_ buf, uint16_t* _RESTRICT_ s);
    void gen_secret_shake128(uint16_t* _RESTRICT_ s, const uint8_t* seed, size_t l, size_t mu);
    static void matrix_mul(uint16_t *out, size_t l, const uint16_t *in1, const uint16_t *in2, bool transpose);

    std::shared_ptr<csprng>           m_prng;
    std::unique_ptr<crypto::xof_sha3> m_xof;

    const size_t m_set;
};

}  // namespace schemes
}  // namespace phantom
