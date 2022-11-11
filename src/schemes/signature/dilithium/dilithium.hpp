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

#include "crypto/csprng.hpp"
#include "core/reduction_montgomery.hpp"
#include "crypto/xof_sha3.hpp"
#include "sampling/gaussian_cdf.hpp"


namespace phantom {
namespace schemes {

/// dilithium_set_t Definitions for the Dilithium parameters
struct dilithium_set_t {
    uint16_t set;
    uint32_t q;
    uint32_t inv_q;
    uint16_t q_bits;
    uint32_t barrett_m_q;
    uint16_t n;
    uint16_t n_bits;
    uint16_t k;
    uint16_t l;
    uint16_t d;
    uint16_t weight_of_c;
    uint32_t gamma_1;
    uint16_t gamma_1_bits;
    uint32_t gamma_2;
    uint16_t eta;
    uint16_t eta_bits;
    uint16_t z_bits;
    uint16_t beta;
    uint16_t omega;
    uint16_t omega_bits;
    uint32_t g;
    uint32_t inv_g;
    uint32_t R;
    uint32_t R2;
};


/**
 * @brief A component class for Dilithium
 */
class dilithium
{
public:
    /// Class constructor that requires a valid parameter set
    explicit dilithium(size_t set);

    /// Class destructor
    ~dilithium();

    /// Return a pointer to a SHAKE XOF object
    crypto::xof_sha3* get_xof() { return m_xof.get(); }

    /// Return a pointer to the parameter set in use
    const dilithium_set_t* get_params() { return &m_params[m_set]; }

    /// Barrett reduction of a input argument
    static inline uint32_t barrett_reduction(const uint32_t& x, size_t k, const uint32_t& m, const uint32_t& q);

    /// Division of an input argument by q
    static inline uint32_t barrett_division(const uint32_t& x, size_t k, const uint32_t& m, const uint32_t& q);

    // Dilithium HighBits()
    void high_bits(uint8_t * _RESTRICT_ out, const uint32_t * _RESTRICT_ in, size_t n, size_t k) const;

    // Dilithium LowBits()
    void low_bits(int32_t * _RESTRICT_ out, const int32_t * _RESTRICT_ in, size_t n, size_t k) const;

    // Uniform sample rejection of an array in the range 0 <= s <= q-1
    size_t reject_uniform(int32_t *s, size_t len, const uint8_t *buf, size_t buflen, uint32_t q);

    // Sample rejection of an array in the range -eta <= s <= eta
    size_t reject_eta(int32_t *s, size_t len, int32_t eta, const uint8_t *buf, size_t eta_blockbytes);

    /// Count the number of '1' values in a hint array
    uint32_t check_hint_ones(const int32_t *h, size_t k, size_t n) const;

    /// Dilithium UseHint()
    void use_hint(uint8_t * _RESTRICT_ z, const int32_t * _RESTRICT_ h, const int32_t * _RESTRICT_ r,
        size_t n, size_t k) const;

    /// Dilithium MakeHint()
    uint32_t make_hint(int32_t *_RESTRICT_ h, const int32_t *_RESTRICT_ r,
        const uint8_t *_RESTRICT_ z, size_t n, size_t k) const;

    /// Dilithium Power2Round()
    void pwr_2_round(int32_t * _RESTRICT_ y, int32_t * _RESTRICT_ x,
        size_t n, size_t k, uint32_t d) const;

    /// Dilithium ExpandMask()
    void expand_mask(const uint8_t *mu, uint32_t kappa,
        uint32_t gamma_1, uint32_t gamma_1_bits, size_t l, size_t n, int32_t *y);

    /// Dilithium H()
    void h_function(int32_t *c, const uint8_t *mu, const uint8_t *w1, size_t n, size_t k);

    /// A random oracle
    void oracle(size_t n, size_t weight_of_c, int32_t *c,
        const uint8_t *seed) const;

    /// Dilithium CRH(p, t1) - inner CRH()
    void collision_resistant_hash_t1(const uint8_t *rho, const int32_t *t1,
        size_t n, size_t k, size_t bits, uint8_t *hash) const;

    /// Dilithium CRH(CRH(p, t1) || m) - outer CRH(), consumes 'in', the pre-computed CRH(p, t1)
    void collision_resistant_hash_message(const uint8_t *in, const phantom_vector<uint8_t>& msg, uint8_t *mu) const;

protected:
    // HighBits for Dilithium 2
    static inline int32_t decompose_high_95232(int32_t r);

    // HighBits for Dilithium 3 and 5
    static inline int32_t decompose_high_261888(int32_t r);

    /// Decompose() for Dilithium 2
    static inline void decompose_95232(int32_t * _RESTRICT_ t1, int32_t _RESTRICT_ *t0, int32_t in);

    /// Decompose() for Dilithium 3 & 5
    static inline void decompose_261888(int32_t * _RESTRICT_ t1, int32_t _RESTRICT_ *t0, int32_t in);

    /// The selected Dilithium parameter set
    size_t m_set;

    /// The Dilithium parameter sets
    static const dilithium_set_t m_params[5];

    /// A SHAKE object
    std::unique_ptr<crypto::xof_sha3> m_xof;
};

}  // namespace schemes
}  // namespace phantom

