/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "schemes/signature/dilithium/dilithium.hpp"
#include "logging/logger.hpp"
#include "core/const_time_enabled.hpp"
#include "core/poly.hpp"
#include "packing/packer.hpp"
#include "packing/unpacker.hpp"
#include "packing/stream.hpp"


namespace phantom {
namespace schemes {


const dilithium_set_t dilithium::m_params[4] = {
    {
        0, 8380417, 4236238847, 23, 128, 256, 8, 3, 2, 14, 60, 523776, 19, 261888, 2050, 7, 3, 20, 330, 64, 7,
        1753, 731434, 4193792, 2365951
    },
    {
        1, 8380417, 4236238847, 23, 128, 256, 8, 4, 3, 14, 60, 523776, 19, 261888, 2050, 6, 3, 20, 285, 80, 7,
        1753, 731434, 4193792, 2365951
    },
    {
        2, 8380417, 4236238847, 23, 128, 256, 8, 5, 4, 14, 60, 523776, 19, 261888, 2050, 5, 3, 20, 235, 96, 7,
        1753, 731434, 4193792, 2365951
    },
    {
        3, 8380417, 4236238847, 23, 128, 256, 8, 6, 5, 14, 60, 523776, 19, 261888, 2050, 3, 2, 20, 145, 120, 7,
        1753, 731434, 4193792, 2365951
    }
};


dilithium::dilithium(size_t set) : m_set(set)
{
    if (set > 3) {
        throw std::invalid_argument("Parameter set is out of range");
    }

    m_xof = std::unique_ptr<crypto::xof_sha3>(new crypto::xof_sha3());
}

dilithium::~dilithium()
{
}

void dilithium::oracle(size_t n, size_t weight_of_c, int32_t *c,
    size_t num_weight_bytes, const uint8_t *signs) const
{
    size_t i, j, k, b;
    uint8_t mask = 1;

    // Initialise the first n - weight_of_c output coefficients to zero
    memset(c, 0, (n-weight_of_c)*sizeof(int32_t));

    // Distribute the weight_of_c non-zero bytes throughout the array
    for (i=n-weight_of_c, j=0, k=num_weight_bytes; i < n; i++, k++) {
        b = signs[k];
        while (b > i) {
            b >>= 1;
        }

        c[i] = c[b];
        c[b] = 1 - (2 * (static_cast<uint8_t>(-(signs[j] & mask)) >> 7));

        // Increment j when mask is 0x80 and about to return to 0x01
        j += mask >> 7;

        // Rotate a single bit mask around the 8-bit mask variable
        mask = core::bit_manipulation::rotl(mask, 1);
    }
}

uint32_t dilithium::barrett_reduction(const uint32_t& x, size_t k, const uint32_t& m, const uint32_t& q)
{
    uint64_t t, c;
    t  = (static_cast<uint64_t>(x) * static_cast<uint64_t>(m)) >> k;
    c  = x - (t * q);
    c -= q * ((q - c - 1) >> 63);  // i.e. if q <= c then c -= q
    return c;
}

uint32_t dilithium::barrett_division(const uint32_t& x, size_t k, const uint32_t& m, const uint32_t& q)
{
    uint64_t t, c;
    t  = (static_cast<uint64_t>(x) * static_cast<uint64_t>(m)) >> k;
    c  = x - (t * q);
    t += ((q - c - 1) >> 63);  // i.e. if q <= c then t++
    return t;
}

uint32_t dilithium::round_alpha(const uint32_t a, uint32_t& a0, uint32_t q,
    uint32_t alpha_q, uint32_t alpha_m, uint32_t alpha_k)
{
    uint32_t a1, cond;

    // a0 = temp mod alpha_q
    a0   = barrett_reduction(a, alpha_k, alpha_m, alpha_q);

    // if a0 > (alpha_q >> 1) a0 -= alpha_q
    a0  -= alpha_q * (((alpha_q >> 1) - a0) >> 31);

    a1   = a - a0;

    // if a1 == (q - 1) {a1 = 0, a0--}, otherwise a1 /= alpha_q
    q--;
    cond = ~((a1 - q) | (q - a1)) >> 31;
    a1   = (1 ^ cond) * barrett_division(a1, alpha_k, alpha_m, alpha_q);
    a0  -= cond;

    return a1;
}

void dilithium::high_bits(uint8_t * _RESTRICT_ out, const uint32_t * _RESTRICT_ in, size_t n, size_t k) const
{
    uint32_t q         = m_params[m_set].q;
    uint32_t gamma_2   = m_params[m_set].gamma_2 * 2;
    uint32_t gamma_2_m = m_params[m_set].gamma_2_m;

    for (size_t i=0; i < k*n; i++) {
        uint32_t r1;
        out[i] = round_alpha(in[i], r1, q, gamma_2, gamma_2_m, 30);
    }
}

void dilithium::low_bits(int32_t * _RESTRICT_ out, const int32_t * _RESTRICT_ in, size_t n, size_t k) const
{
    uint32_t r1;
    uint32_t q         = m_params[m_set].q;
    uint32_t gamma_2   = m_params[m_set].gamma_2 * 2;
    uint32_t gamma_2_m = m_params[m_set].gamma_2_m;

    for (size_t i=0; i < k*n; i++) {
        round_alpha(in[i], r1, q, gamma_2, gamma_2_m, 30);
        r1    += q * (r1 >> 31);
        out[i] = r1;
    }
}

// Truncate the input ring polynomial by d bits and compute the residual.
// NOTE: in MUST be in the range 0 to q-1 inclusive
void dilithium::decompose(int32_t * _RESTRICT_ t1, uint8_t * _RESTRICT_ t0, const int32_t * _RESTRICT_ in, size_t n,
    size_t k, uint32_t alpha, uint32_t q) const
{
    size_t i;
    uint32_t gamma_2   = m_params[m_set].gamma_2 * 2;
    uint32_t gamma_2_m = m_params[m_set].gamma_2_m;

    for (i=0; i < k*n; i++) {
        uint32_t r1;
        t0[i] = round_alpha(in[i], r1, q, gamma_2, gamma_2_m, 30);
        r1   += q * (r1 >> 31);
        t1[i] = r1;
    }
}

// As per Algorithm 5, find the HighOrderBits of r and r + z given reduction
// factor alpha. If there is a mismatch return a 1, otherwise return a 0.
uint32_t dilithium::make_hint(int32_t *_RESTRICT_ h, const int32_t *_RESTRICT_ r,
    const int32_t *_RESTRICT_ z, size_t n, size_t k) const
{
    size_t i;
    uint32_t t, sum = 0;
    uint32_t q         = m_params[m_set].q;
    uint32_t gamma_2   = m_params[m_set].gamma_2 * 2;
    uint32_t gamma_2_m = m_params[m_set].gamma_2_m;

    for (i=0; i < k*n; i++) {
        // (r[i] + z[i]) mod q
        uint32_t add;
        add  = r[i] + z[i];
        add -= ((q - add - 1) >> 31) * q;
        add += (add >> 31) * q;
        h[i] = add;
    }
    for (i=0; i < k*n; i++) {
        uint32_t r1  = round_alpha(r[i], t, q, gamma_2, gamma_2_m, 30);
        uint32_t r0  = round_alpha(h[i], t, q, gamma_2, gamma_2_m, 30);
        uint32_t add = static_cast<uint32_t>(-(r1 ^ r0)) >> 31;  // i.e. r1 != r0;
        h[i] = add;
        sum += add;
    }

    return sum;
}

uint32_t dilithium::check_hint_ones(const int32_t *h, size_t k, size_t n) const
{
    uint32_t sum[8] = { 0 };

    for (size_t i=0; i < k*n >> 3; i++) {
        sum[0] += h[(i << 3)  ];
        sum[1] += h[(i << 3)+1];
        sum[2] += h[(i << 3)+2];
        sum[3] += h[(i << 3)+3];
        sum[4] += h[(i << 3)+4];
        sum[5] += h[(i << 3)+5];
        sum[6] += h[(i << 3)+6];
        sum[7] += h[(i << 3)+7];
    }

    return sum[0] + sum[1] + sum[2] + sum[3] + sum[4] + sum[5] + sum[6] + sum[7];
}

// As per Algorithm 6, use the h hint bits to recover z from r
void dilithium::use_hint(uint8_t * _RESTRICT_ z, const int32_t * _RESTRICT_ h, const int32_t * _RESTRICT_ r,
    size_t n, size_t k) const
{
    uint32_t q         = m_params[m_set].q;
    uint32_t gamma_2   = m_params[m_set].gamma_2 * 2;
    uint32_t gamma_2_m = m_params[m_set].gamma_2_m;
    uint32_t m         = (q - 1) / gamma_2;
    uint32_t mask      = m - 1;

    for (size_t i=0; i < k*n; i++) {
        uint32_t t1, t2, cond;
        t2   = round_alpha(r[i], t1, q, gamma_2, gamma_2_m, 30);
        cond = (t1 - 1) >> 31;
        t2  += h[i] & (cond ^ 1);
        t2  -= h[i] & cond;

        // if t2 < 0 add (q-1) / α
        t2  += m * (t2 >> 31);

        // t2 % ((q-1) / α)
        z[i] = t2 & mask;
    }
}

// Truncate the input ring polynomial x by d bits and write to y.
// NOTE: x MUST be in the range 0 to q-1 inclusive
void dilithium::pwr_2_round(int32_t * _RESTRICT_ y, int32_t * _RESTRICT_ x, uint32_t q,
   size_t n, size_t k, uint32_t d) const
{
    int32_t sign      = 1 << d;
    int32_t sign_m1   = sign - 1;
    int32_t thresh    = sign >> 1;
    int32_t thresh_p1 = thresh + 1;
    int32_t thresh_m1 = thresh - 1;

    for (size_t i=n*k; i--;) {
        int32_t t;
        t    = x[i] & sign_m1;
        t   -= thresh_p1;
        t   += (static_cast<uint32_t>(t) >> 31) & sign;
        t   -= thresh_m1;
        y[i] = (x[i] - t) >> d;
        x[i] = t;
    }
}

void dilithium::expand_mask(const uint8_t *mu, uint32_t kappa,
    uint32_t gamma_1, uint32_t q, size_t l, size_t n, int32_t *y, const uint8_t *K)
{
    size_t limit = n * l;
    uint8_t kappa_bytes[2] = {static_cast<uint8_t>(kappa >> 8), static_cast<uint8_t>(kappa & 0xFF)};
    uint32_t thresh = 2 * gamma_1 - 2;
    uint32_t add    = q + gamma_1 - 1;

    // Initialise the XOF and absorb the input data to configure the state
    m_xof->init(32);
    m_xof->absorb(mu, 48);
    m_xof->absorb(K, 32);
    m_xof->absorb(kappa_bytes, 2);
    m_xof->final();

    uint32_t samples[2];
    size_t j = 0;

    uint8_t seed[5];

    while (j < limit) {
        // Create 5 bytes from which two 20-bit samples are generated
        m_xof->squeeze(seed, 5);
        samples[0] = ((static_cast<uint32_t>(seed[2]) & 0xF) << 16) |
                      (static_cast<uint32_t>(seed[1]) << 8) |
                       static_cast<uint32_t>(seed[0]);
        samples[1] =  (static_cast<uint32_t>(seed[4]) << 12) |
                      (static_cast<uint32_t>(seed[3]) << 4) |
                      (static_cast<uint32_t>(seed[2]) >> 4);

        // Overwrite the current output index with a sample, incrementing the output index only if
        // the value lies within the range 0 to 2^20 - 1
        uint32_t cond;
        cond = (samples[0] - thresh) >> 31;
        y[j] = samples[0];
        j   += cond;
        if (limit == j) {
            break;
        }
        cond = (samples[1] - thresh) >> 31;
        y[j] = samples[1];
        j   += cond;
    }

    for (size_t i = 0; i < limit; i++) {
        int32_t temp = add - y[i];
        y[i] = barrett_reduction(temp, 30, 2050, gamma_1);
    }
}

void dilithium::h_function(int32_t *c, const uint8_t *mu, const uint8_t *w1, size_t n, size_t k)
{
    const size_t weight_of_c = m_params[m_set].weight_of_c;
    const size_t num_weight_bytes = (weight_of_c + 7) >> 3;
    phantom_vector<uint8_t> signs(num_weight_bytes + weight_of_c);

    m_xof->init(16);
    m_xof->absorb(mu, 48);
    m_xof->absorb(w1, k*n);
    m_xof->final();
    m_xof->squeeze(signs.data(), num_weight_bytes + weight_of_c);

    // Generate the output coefficients for the spare polynomial
    oracle(n, weight_of_c, c, num_weight_bytes, signs.data());
}

void dilithium::collision_resistant_hash_t1(const uint8_t *rho, const int32_t *t1,
    size_t n, size_t k, size_t bits, uint8_t *hash) const
{
    // Generate the bit packed public key
    phantom_vector<uint8_t> msg;

    packing::packer pack(bits * k * n + 32*8);
    for (size_t i=0; i < 32; i++) {
        pack.write_unsigned(rho[i], 8, packing::RAW);
    }
    for (size_t i=0; i < k*n; i++) {
        pack.write_unsigned(t1[i], bits, packing::RAW);
    }

    pack.flush();
    msg = pack.get();

    // Create a SHAKE-256 XOF
    m_xof->init(32);

    // Absorb the input data to configure the state
    m_xof->absorb(msg.data(), msg.size());
    m_xof->final();

    // Create 48 bytes of output data
    m_xof->squeeze(hash, 48);
}

void dilithium::collision_resistant_hash_message(const uint8_t *in,
                                                 const phantom_vector<uint8_t>& msg,
                                                 uint8_t *mu) const
{
    // Initialise the XOF
    m_xof->init(32);

    // Absorb the input data to configure the state
    m_xof->absorb(in, 48);
    m_xof->absorb(msg.data(), msg.size());
    m_xof->final();

    // Create 48 bytes of output data
    m_xof->squeeze(mu, 48);
}

}  // namespace schemes
}  // namespace phantom
