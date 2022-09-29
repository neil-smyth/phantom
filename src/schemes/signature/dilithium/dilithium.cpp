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


const dilithium_set_t dilithium::m_params[3] = {
    {
        0, 8380417, 4236238847, 23, 128, 256, 8, 4, 4, 13, 39, 131072, 18, 95232, 22550, 2, 2, 20, 78, 80, 7,
        1753, 731434, 4193792, 2365951
    },
    {
        1, 8380417, 4236238847, 23, 128, 256, 8, 6, 5, 13, 49, 523776, 20, 261888, 2050, 4, 3, 20, 196, 55, 6,
        1753, 731434, 4193792, 2365951
    },
    {
        2, 8380417, 4236238847, 23, 128, 256, 8, 8, 7, 13, 60, 523776, 20, 261888, 2050, 2, 2, 20, 120, 75, 7,
        1753, 731434, 4193792, 2365951
    }
};


dilithium::dilithium(size_t set) : m_set(set)
{
    if (set > 2) {
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
    std::fill(c, c + (n - weight_of_c), 0);

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

void dilithium::high_bits(uint8_t * _RESTRICT_ out, const uint32_t * _RESTRICT_ in, size_t n, size_t k) const
{
    uint32_t q         = m_params[m_set].q;
    uint32_t gamma_2   = m_params[m_set].gamma_2;

    if (gamma_2 == (q-1)/32) {
        for (size_t i=0; i < k*n; i++) {
            out[i] = decompose_35_r1(in[i]);
        }
    }
    else {
        for (size_t i=0; i < k*n; i++) {
            out[i] = decompose_2_r1(in[i]);
        }
    }
}

void dilithium::low_bits(int32_t * _RESTRICT_ out, const int32_t * _RESTRICT_ in, size_t n, size_t k) const
{
    uint32_t q         = m_params[m_set].q;
    uint32_t gamma_2   = m_params[m_set].gamma_2;
    int32_t  r1, r0;

    if (gamma_2 == (q-1)/32) {
        for (size_t i=0; i < k*n; i++) {
            decompose_35(&r1, &r0, in[i], q, gamma_2);
            out[i] = r0;
        }
    }
    else {
        for (size_t i=0; i < k*n; i++) {
            decompose_2(&r1, &r0, in[i], q, gamma_2);
            out[i] = r0;
        }
    }
}

// Truncate the input ring polynomial by d bits and compute the residual.
// NOTE: in MUST be in the range 0 to q-1 inclusive
void dilithium::decompose_blocks(int32_t * _RESTRICT_ t1, int32_t * _RESTRICT_ t0, const int32_t * _RESTRICT_ in, size_t n,
    size_t k, uint32_t q) const
{
    size_t i;
    uint32_t gamma_2   = m_params[m_set].gamma_2;
    int32_t temp;

    if (gamma_2 == (q-1)/32) {
        for (i=0; i < k*n; i++) {
            decompose_35(&t1[i], &temp, in[i], q, gamma_2);
            t0[i] = temp;
        }
    }
    else {
        for (i=0; i < k*n; i++) {
            decompose_2(&t1[i], &temp, in[i], q, gamma_2);
            t0[i] = temp;
        }
    }
}

int32_t dilithium::decompose_2_r1(int32_t r)
{
    int32_t r1;
    r1  = (r + 127) >> 7;
    r1  = (r1 * 11275 + (1 << 23)) >> 24;
    r1 ^= ((43 - r1) >> 31) & r1;
    return r1;
}

int32_t dilithium::decompose_35_r1(int32_t r)
{
    int32_t r1;
    r1  = (r + 127) >> 7;
    r1  = (r1 * 1025 + (1 << 21)) >> 22;
    r1 &= 0xf;
    return r1;
}

void dilithium::decompose_2(int32_t * _RESTRICT_ t1, int32_t _RESTRICT_ *t0, int32_t in, int32_t q, int32_t gamma_2)
{
    *t1 = decompose_2_r1(in);

    *t0  = in - *t1 * 2 * gamma_2;
    *t0 -= (((q-1)/2 - *t0) >> 31) & q;
}

void dilithium::decompose_35(int32_t * _RESTRICT_ t1, int32_t _RESTRICT_ *t0, int32_t in, int32_t q, int32_t gamma_2)
{
    *t1 = decompose_35_r1(in);

    *t0  = in - *t1 * 2 * gamma_2;
    *t0 -= (((q-1)/2 - *t0) >> 31) & q;
}

size_t dilithium::rej_uniform(int32_t *a,
                              size_t len,
                              const uint8_t *buf,
                              size_t buflen,
                              uint32_t q)
{
  size_t ctr, pos;
  uint32_t t;

  ctr = pos = 0;
  while (ctr < len && pos + 3 <= buflen) {
    t  = buf[pos++];
    t |= static_cast<uint32_t>(buf[pos++]) << 8;
    t |= static_cast<uint32_t>(buf[pos++]) << 16;
    t &= 0x7FFFFF;

    if (t < q)
      a[ctr++] = t;
  }

  return ctr;
}

// As per Algorithm 5, find the HighOrderBits of r and r + z given reduction
// factor alpha. If there is a mismatch return a 1, otherwise return a 0.
uint32_t dilithium::make_hint(int32_t *_RESTRICT_ h, const int32_t *_RESTRICT_ r,
    const uint8_t *_RESTRICT_ z, size_t n, size_t k) const
{
    uint32_t sum     = 0;
    int32_t  gamma_2 = m_params[m_set].gamma_2;

    LOG_DEBUG_ARRAY("MAKE_HINT: r", r, k*n);
    LOG_DEBUG_ARRAY("MAKE_HINT: r + z", z, k*n);

    for (size_t i=0; i < k*n; i++) {
        h[i] = r[i] > gamma_2 || r[i] < -gamma_2 || (r[i] == -gamma_2 && z[i] != 0);
        sum += h[i];
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
    uint32_t gamma_2   = m_params[m_set].gamma_2;
    int32_t  r1, r0;

    for (size_t i=0; i < k*n; i++) {
        if (gamma_2 == (q-1)/32) {
            decompose_35(&r1, &r0, r[i], q, gamma_2);
        }
        else {
            decompose_2(&r1, &r0, r[i], q, gamma_2);
        }

        if (h[i] == 0) {
            z[i] = r1;
        }
        else {
            if (gamma_2 == (q - 1) / 32) {
                if (r0 > 0)
                    z[i] = (r1 + 1) & 15;
                else
                    z[i] = (r1 - 1) & 15;
            }
            else {
                if (r0 > 0)
                    z[i] = (r1 == 43) ?  0 : r1 + 1;
                else
                    z[i] = (r1 ==  0) ? 43 : r1 - 1;
            }
        }
    }
}

// Truncate the input ring polynomial x by d bits and write to y.
// NOTE: x MUST be in the range 0 to q-1 inclusive
void dilithium::pwr_2_round(int32_t * _RESTRICT_ y, int32_t * _RESTRICT_ x, uint32_t q,
   size_t n, size_t k, uint32_t d) const
{
    int32_t sign      = 1 << (d - 1);
    int32_t sign_mask = sign - 1;

    for (size_t i=n*k; i--;) {
        y[i] = (x[i] + sign_mask - 1) >> d;
        x[i] = x[i] - (y[i] << d);
    }
}

void dilithium::expand_mask(const uint8_t *mu, uint32_t kappa,
    uint32_t gamma_1, uint32_t gamma_1_bits, uint32_t q, size_t l, size_t n, int32_t *y, const uint8_t *K)
{
    int32_t samples[4];
    uint8_t seed[9];

    kappa *= l;

    for (size_t i=0; i < l; i++) {

        uint8_t kappa_bytes[2] = {static_cast<uint8_t>(kappa & 0xFF), static_cast<uint8_t>(kappa >> 8)};
        kappa++;

        // Initialise the XOF and absorb the input data to configure the state
        m_xof->init(32);
        m_xof->absorb(mu, 64);
        m_xof->absorb(kappa_bytes, 2);
        m_xof->final();

        int32_t *out = y + n * i;

        size_t j = 0;
        while (j < n) {
            // Create 5 bytes from which two gamma_1_bits samples are generated
            if (20 == gamma_1_bits) {
                m_xof->squeeze(seed, 5);
                samples[0] = ((static_cast<uint32_t>(seed[2]) & 0xf) << 16) |
                             ((static_cast<uint32_t>(seed[1])      ) <<  8) |
                             ((static_cast<uint32_t>(seed[0])      )      );
                samples[1] = ((static_cast<uint32_t>(seed[4]) & 0xf) << 14) |
                             ((static_cast<uint32_t>(seed[3])      ) <<  4) |
                             ((static_cast<uint32_t>(seed[2])      ) >>  4);
                
                out[j++] = gamma_1 - samples[0];
                out[j++] = gamma_1 - samples[1];
            }
            else {
                m_xof->squeeze(seed, 9);
                samples[0] = ((static_cast<uint32_t>(seed[2]) & 0x03) << 16) |
                             ((static_cast<uint32_t>(seed[1])       ) <<  8) |
                             ((static_cast<uint32_t>(seed[0])       )      );
                samples[1] = ((static_cast<uint32_t>(seed[4]) & 0x0f) << 14) |
                             ((static_cast<uint32_t>(seed[3])       ) <<  6) |
                             ((static_cast<uint32_t>(seed[2])       ) >>  2);
                samples[2] = ((static_cast<uint32_t>(seed[6]) & 0x3f) << 12) |
                             ((static_cast<uint32_t>(seed[5])       ) <<  4) |
                             ((static_cast<uint32_t>(seed[4])       ) >>  4);
                samples[3] = ((static_cast<uint32_t>(seed[8])       ) << 10) |
                             ((static_cast<uint32_t>(seed[7])       ) <<  2) |
                             ((static_cast<uint32_t>(seed[6])       ) >>  6);
                
                out[j++] = gamma_1 - samples[0];
                out[j++] = gamma_1 - samples[1];
                out[j++] = gamma_1 - samples[2];
                out[j++] = gamma_1 - samples[3];
            }
        }
    }
}

void dilithium::h_function(int32_t *c, const uint8_t *mu, const uint8_t *w1, size_t n, size_t k)
{
    const size_t weight_of_c = m_params[m_set].weight_of_c;
    const size_t num_weight_bytes = (weight_of_c + 7) >> 3;
    phantom_vector<uint8_t> signs(num_weight_bytes + weight_of_c);

    m_xof->init(16);
    m_xof->absorb(mu, 64);
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

    // Create 32 bytes of output data
    m_xof->squeeze(hash, 32);
}

void dilithium::collision_resistant_hash_message(const uint8_t *in,
                                                 const phantom_vector<uint8_t>& msg,
                                                 uint8_t *mu) const
{
    // Initialise the XOF
    m_xof->init(32);

    // Absorb the input data to configure the state
    m_xof->absorb(in, 32);
    m_xof->absorb(msg.data(), msg.size());
    m_xof->final();

    // Create 64 bytes of output data
    m_xof->squeeze(mu, 64);
}

}  // namespace schemes
}  // namespace phantom
