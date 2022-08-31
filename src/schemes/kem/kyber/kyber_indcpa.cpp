/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "schemes/kem/kyber/kyber_indcpa.hpp"

#include <algorithm>

#include "sampling/uniform_sampler.hpp"
#include "logging/logger.hpp"
#include "core/poly.hpp"
#include "packing/packer.hpp"
#include "packing/unpacker.hpp"
#include "packing/stream.hpp"
#include "crypto/random_seed.hpp"
#include "crypto/xof_sha3.hpp"


namespace phantom {
namespace schemes {

const kyber_set_t kyber_indcpa::m_params[3] = {
    {0, 7681, 13, 0x8884, 12, 256, 8, 2, 5, 4, 11, 3, 11, 62, 1115, 4088, 5569},
    {1, 7681, 13, 0x8884, 12, 256, 8, 3, 4, 4, 11, 3, 11, 62, 1115, 4088, 5569},
    {2, 7681, 13, 0x8884, 12, 256, 8, 4, 3, 3, 11, 3, 11, 62, 1115, 4088, 5569},
};


size_t kyber_indcpa::bits_2_set(security_strength_e bits)
{
    // Select the most appropriate parameter set for the given security strength
    size_t set = 0;
    switch (bits)
    {
        case SECURITY_STRENGTH_60:
        case SECURITY_STRENGTH_80:
        case SECURITY_STRENGTH_96:  set = 0; break;

        case SECURITY_STRENGTH_112:
        case SECURITY_STRENGTH_128: set = 1; break;

        case SECURITY_STRENGTH_160: set = 2; break;

        default: throw std::invalid_argument("Security strength is invalid");
    }

    return set;
}

kyber_indcpa::kyber_indcpa(security_strength_e bits) :
    m_set(bits_2_set(bits)),
    m_reduce(core::montgomery<uint16_t>(m_params[m_set].q,
                                        m_params[m_set].q - 2,
                                        16,
                                        m_params[m_set].R,
                                        m_params[m_set].R2)),
    m_reduction(m_reduce)
{
    init();
}

kyber_indcpa::kyber_indcpa(size_t set) :
    m_set(set),
    m_reduce(core::montgomery<uint16_t>(m_params[set].q,
                                        m_params[set].q - 2,
                                        16,
                                        m_params[set].R,
                                        m_params[set].R2)),
    m_reduction(m_reduce)
{
    init();
}

void kyber_indcpa::init()
{
    if (m_set > 2) {
        throw std::invalid_argument("Parameter set is out of range");
    }

    uint16_t g     = m_params[m_set].g;
    uint16_t inv_g = m_params[m_set].inv_g;
    size_t   n     = m_params[m_set].n;
    ntt_red_mont *ntt16 = new ntt_red_mont(m_reduction, g, inv_g, n);
    if (!ntt16) {
        throw std::invalid_argument("NTT object could not be instantiated");
    }
    m_ntt          = std::unique_ptr<ntt_red_mont>(ntt16);

    m_prng         = std::shared_ptr<csprng>(csprng::make(0x10000000, random_seed::seed_cb));

    m_xof          = std::unique_ptr<crypto::xof_sha3>(new crypto::xof_sha3());

    LOG_DEBUG("Kyber KEM Scheme");
}

kyber_indcpa::~kyber_indcpa()
{
}

// Uniform random sampling of a ring of n elements
void kyber_indcpa::uniform_random_ring_q(size_t i, size_t j, const uint8_t* rho, uint16_t *a,
    size_t n, uint16_t q, size_t q_bits)
{
    uint32_t mask = (1 << q_bits) - 1;
    phantom_vector<uint8_t> blockvec(2*n);
    uint8_t* block = blockvec.data();
    uint8_t seed[34];
    std::copy(rho, rho + 32, seed);
    seed[32] = i;
    seed[33] = j;

    m_xof->init(16);
    m_xof->absorb(seed, 34);
    m_xof->final();

    size_t ctr = 0;
    size_t pos = 2*n;
    while (ctr < n) {
        if (2*n == pos) {
            m_xof->squeeze(block, n * sizeof(uint16_t));
            pos = 0;
        }

        uint16_t v = block[pos] | static_cast<uint16_t>(block[pos + 1]);
        v &= mask;

        // If v < q then set a[ctr] to v and increment ctr
        uint16_t select = core::const_time_enabled<uint16_t>::cmp_lessthan(v, q);
        a[ctr] ^= (a[ctr] ^ v) & -select;
        ctr += select;
        pos += 2;
    }
}

// Compute t = A * y
void kyber_indcpa::create_rand_product(
    uint16_t q, size_t q_bits, uint16_t* _RESTRICT_ t, int16_t* _RESTRICT_ y, size_t logn,
    size_t k, const uint8_t* rho, bool transposed)
{
    const size_t n = 1 << logn;

    uint16_t *yu = reinterpret_cast<uint16_t*>(y);
    phantom_vector<uint16_t> scratch(2 * n);
    uint16_t *block = scratch.data();
    uint16_t *c     = block + n;

    for (size_t i = 0; i < k*n; i++) {
        int16_t tmp = y[i];
        tmp += q & (tmp >> 15);
        yu[i] = m_reduction.convert_to(tmp);
    }

    // Compute the NTT of the input to create_rand_product() as an initial step
    for (size_t i = 0; i < k; i++) {
        m_ntt->fwd(yu + i*n, logn);
    }

    if (transposed) {
        // k x l matrix multiplication of n-element rings
        for (size_t i = 0; i < k; i++) {
            uniform_random_ring_q(0, i, rho, c, n, q, q_bits);
            m_ntt->mul(t + i*n, yu, c);
        }

        for (size_t j = 1; j < k; j++) {
            for (size_t i = 0; i < k; i++) {
                uniform_random_ring_q(j, i, rho, c, n, q, q_bits);
                m_ntt->mul(block, yu + j*n, c);

                for (size_t k = 0; k < n; k++) {
                    t[i*n + k] = m_reduction.add(t[i*n + k], block[k]);
                }
            }
        }

        for (size_t i = 0; i < k; i++) {
            m_ntt->inv(t + i*n, logn);
        }
    }
    else {
        // k x l matrix multiplication of n-element rings
        for (size_t i = 0; i < k; i++) {
            uniform_random_ring_q(i, 0, rho, c, n, q, q_bits);
            m_ntt->mul(t + i*n, yu, c);

            for (size_t j = 1; j < k; j++) {
                uniform_random_ring_q(i, j, rho, c, n, q, q_bits);
                m_ntt->mul(block, yu + j*n, c);

                for (size_t k = 0; k < n; k++) {
                    t[i*n + k] = m_reduction.add(t[i*n + k], block[k]);
                }
            }

            m_ntt->inv(t + i*n, logn);
        }
    }

    for (size_t i = 0; i < k*n; i++) {
        t[i] = m_reduction.convert_from(t[i]);
    }
}

void kyber_indcpa::binomial_rand_sample(uint16_t q, int16_t eta,
    int16_t *s, size_t n, size_t m)
{
    alignas(DEFAULT_MEM_ALIGNMENT) uint16_t a[8];
    alignas(DEFAULT_MEM_ALIGNMENT) uint8_t t[5];

    // Accumulate over each bit lane of the byte and scale the output
    for (size_t i = 0; i < (m*n)>>2; i++) {
        m_prng->get_mem(t, eta);
        a[0] = t[0] & 0x01;
        a[1] = t[0] & 0x02;
        a[2] = t[0] & 0x04;
        a[3] = t[0] & 0x08;
        a[4] = t[0] & 0x10;
        a[5] = t[0] & 0x20;
        a[6] = t[0] & 0x40;
        a[7] = t[0] & 0x80;
        for (int16_t idx = 1; idx < eta; idx++) {
            a[0] += t[idx] & 0x01;
            a[1] += t[idx] & 0x02;
            a[2] += t[idx] & 0x04;
            a[3] += t[idx] & 0x08;
            a[4] += t[idx] & 0x10;
            a[5] += t[idx] & 0x20;
            a[6] += t[idx] & 0x40;
            a[7] += t[idx] & 0x80;
        }

        s[4*i+0] =  a[0]       - (a[1] >> 1);
        s[4*i+1] = (a[2] >> 2) - (a[3] >> 3);
        s[4*i+2] = (a[4] >> 4) - (a[5] >> 5);
        s[4*i+3] = (a[6] >> 6) - (a[7] >> 7);
    }
}

void kyber_indcpa::binomial_rand_sample_shake128(uint16_t q, int16_t eta,
    int16_t *s, size_t n, size_t m)
{
    alignas(DEFAULT_MEM_ALIGNMENT) uint16_t a[8];
    alignas(DEFAULT_MEM_ALIGNMENT) uint8_t t[5];

    for (size_t i = 0; i < (m*n)>>2; i++) {
        m_xof->squeeze(t, eta);
        a[0] = t[0] & 0x01;
        a[1] = t[0] & 0x02;
        a[2] = t[0] & 0x04;
        a[3] = t[0] & 0x08;
        a[4] = t[0] & 0x10;
        a[5] = t[0] & 0x20;
        a[6] = t[0] & 0x40;
        a[7] = t[0] & 0x80;
        for (int16_t idx = 1; idx < eta; idx++) {
            a[0] += t[idx] & 0x01;
            a[1] += t[idx] & 0x02;
            a[2] += t[idx] & 0x04;
            a[3] += t[idx] & 0x08;
            a[4] += t[idx] & 0x10;
            a[5] += t[idx] & 0x20;
            a[6] += t[idx] & 0x40;
            a[7] += t[idx] & 0x80;
        }

        s[4*i+0] =  a[0]       - (a[1] >> 1);
        s[4*i+1] = (a[2] >> 2) - (a[3] >> 3);
        s[4*i+2] = (a[4] >> 4) - (a[5] >> 5);
        s[4*i+3] = (a[6] >> 6) - (a[7] >> 7);
    }
}

void kyber_indcpa::compress(int16_t *inout, size_t n, size_t k, size_t d,
    uint16_t q, uint16_t q_inv, uint16_t q_norm)
{
    int64_t  rnd_q2 = q >> 1;
    uint64_t mod_2d = (1 << d) - 1;
    size_t   shift  = 16 + q_norm;

    for (size_t i = 0; i < k*n; i++) {
        uint64_t t = (static_cast<uint64_t>(inout[i]) << d) + rnd_q2;
        t          = (t * q_inv) >> shift;
        inout[i]   = t & mod_2d;
    }
}

// Translate an integer in the range 0 ... 2^d - 1 to an element in Zq,
// where d < rnd(2^d - 1)
void kyber_indcpa::decompress(int16_t *inout, size_t n, size_t k, size_t d, uint16_t q)
{
    for (size_t i = 0; i < k*n; i++) {
        int32_t t = (inout[i] * q) >> d;
        inout[i] = t;
    }
}

void kyber_indcpa::keygen(uint8_t * _RESTRICT_ rho, int16_t * _RESTRICT_ s, int16_t * _RESTRICT_ t)
{
    // NOTE: the psuedorandom number r is provided as an input
    // and the public key is already decompressed

    size_t   n        = m_params[m_set].n;
    size_t   n_bits   = m_params[m_set].n_bits;
    size_t   k        = m_params[m_set].k;
    uint16_t q        = m_params[m_set].q;
    uint16_t q_bits   = m_params[m_set].q_bits;
    uint16_t q_inv    = m_params[m_set].q_inv;
    uint16_t q_norm   = m_params[m_set].q_norm;
    uint16_t eta      = m_params[m_set].eta;
    uint16_t dt_bits  = m_params[m_set].d_t;

    int16_t *e = reinterpret_cast<int16_t*>(aligned_malloc(k * n * sizeof(int16_t)));

    // Generate a 256 bit random byte array to be used to seed a CSPRNG.
    m_prng->get_mem(rho, 32);
    LOG_DEBUG_ARRAY("rho", rho, 32);

    // Generate s1 and s2 from a uniform random distribution with values of
    // -eta to +eta inclusive.
    binomial_rand_sample(q, eta, s, n, k);
    binomial_rand_sample(q, eta, e, n, k);
    LOG_DEBUG_ARRAY("s = Sam(sigma)", s, k * n);
    LOG_DEBUG_ARRAY("e = Sam(sigma)", e, k * n);

    // Matrix multiplication of A and s1, where A is uniform random
    // sampled as a k x l matrix of ring polynomials with n coefficients.
    // The kxl A matrix is multiplied by the lx1 s1 matrix to form a kx1
    // matrix to which s2 is added.
    create_rand_product(q, q_bits, reinterpret_cast<uint16_t*>(t), s, n_bits, k, rho, false);
    LOG_DEBUG_ARRAY("t = As", t, k * n);
    core::poly<int16_t>::add(t, k * n, t, e);
    core::poly<int16_t>::centre(t, q, k * n);
    compress(t, n, k, dt_bits, q, q_inv, q_norm);
    LOG_DEBUG_ARRAY("Compress(As + e)", t, k * n);
    decompress(t, n, k, dt_bits, q);
    LOG_DEBUG_ARRAY("Decompress(As + e)", t, k * n);
    LOG_DEBUG_ARRAY("t = As + e", t, k * n);
    LOG_DEBUG_ARRAY("NTT(s)", s, k * n);

    // Free the temporary memory resources (and erase the contents)
    aligned_free(e);
}

void kyber_indcpa::map_message(int16_t* _RESTRICT_ v, const uint8_t*  _RESTRICT_ m, size_t n, uint16_t q2)
{
    for (size_t i = 0, j = 0; i < n>>3; i++, j += 8) {
        v[j  ] += ((m[i] >> 7) & 1) * q2;
        v[j+1] += ((m[i] >> 6) & 1) * q2;
        v[j+2] += ((m[i] >> 5) & 1) * q2;
        v[j+3] += ((m[i] >> 4) & 1) * q2;
        v[j+4] += ((m[i] >> 3) & 1) * q2;
        v[j+5] += ((m[i] >> 2) & 1) * q2;
        v[j+6] += ((m[i] >> 1) & 1) * q2;
        v[j+7] += ((m[i] >> 0) & 1) * q2;
    }
}

void kyber_indcpa::enc(int16_t * _RESTRICT_ u, int16_t * _RESTRICT_ v, const uint16_t * _RESTRICT_ t_ntt,
    const uint8_t * _RESTRICT_ rho, size_t logn, size_t k, const uint8_t * _RESTRICT_ m)
{
    LOG_DEBUG("Kyber CPA Encryption\n");

    // NOTE: the psuedorandom number r is provided as an input
    // and the public key is already decompressed

    size_t   n        = 1 << logn;
    uint16_t q        = m_params[m_set].q;
    uint16_t q2       = q >> 1;
    uint16_t q_bits   = m_params[m_set].q_bits;
    uint16_t q_inv    = m_params[m_set].q_inv;
    uint16_t q_norm   = m_params[m_set].q_norm;
    uint16_t eta      = m_params[m_set].eta;
    uint16_t d_u      = m_params[m_set].d_u;
    uint16_t d_v      = m_params[m_set].d_v;

    int16_t *temp  = reinterpret_cast<int16_t*>(aligned_malloc((2 * k + 1) * n * sizeof(int16_t)));
    int16_t *r_eta = temp;
    int16_t *e1    = r_eta + k * n;
    int16_t *e2    = e1 + k * n;

    LOG_DEBUG_ARRAY("m", m, 32);
    LOG_DEBUG_ARRAY("rho", rho, 32);
    LOG_DEBUG_ARRAY("r", r_eta, 32);

    binomial_rand_sample_shake128(q, eta, r_eta, n, k);
    binomial_rand_sample_shake128(q, eta, e1, n, k);
    binomial_rand_sample_shake128(q, eta, e2, n, 1);
    LOG_DEBUG_ARRAY("r_eta = Sam(r)", r_eta, k*n);
    LOG_DEBUG_ARRAY("e1 = Sam(r)", e1, k * n);
    LOG_DEBUG_ARRAY("e2 = Sam(r)", e2, n);

    // Generate a random kxk matrix A of n-element rings, multiply by r_eta
    // and add e1
    uint16_t *uu = reinterpret_cast<uint16_t*>(u);
    create_rand_product(q, q_bits, uu, r_eta, logn, k, rho, true);
    core::poly<int16_t>::add_mod(u, k*n, u, e1, q);
    LOG_DEBUG_ARRAY("NTT(r_eta)", r_eta, k * n);

    // Calculate the sum of the products of the k n-element rings of t and r
    uint16_t *uv      = reinterpret_cast<uint16_t*>(v);
    uint16_t *ue1     = reinterpret_cast<uint16_t*>(e1);
    uint16_t *u_r_eta = reinterpret_cast<uint16_t*>(r_eta);
    m_ntt->mul(uv, u_r_eta, t_ntt);
    for (size_t i=1; i < k; i++) {
        m_ntt->mul(ue1 + i*n, u_r_eta + i*n, t_ntt + i*n);
        for (size_t j = 0; j < n; j++) {
            uv[j] = m_reduction.add(ue1[i*n + j], uv[j]);
        }
    }
    m_ntt->inv(uv, logn);
    m_reduction.convert_from(uv, uv, n);
    LOG_DEBUG_ARRAY("tT.r", v, n);

    // Map the message to q/2 and add to v
    map_message(v, m, n, q2);

    // Generate e2 and add to v to form the final uncompressed v
    core::poly<int16_t>::add_mod(v, n, v, e2, q);
    LOG_DEBUG_ARRAY("u = AT.r + e1", u, k * n);
    LOG_DEBUG_ARRAY("v = t^Tr + [q/2].m + e2", v, n);

    // Compress the two encryption variables
    compress(u, n, k, d_u, q, q_inv, q_norm);
    compress(v, n, 1, d_v, q, q_inv, q_norm);
    LOG_DEBUG_ARRAY("Compress(u)", u, k*n);
    LOG_DEBUG_ARRAY("Compress(v)", v, n);

    // Free the temporary memory resources (and erase the contents)
    aligned_free(temp);
}

void kyber_indcpa::dec(int16_t* _RESTRICT_ u, int16_t* _RESTRICT_ v,
    const uint16_t* _RESTRICT_ s, size_t logn, size_t k, uint8_t* _RESTRICT_ m)
{
    const size_t n = 1 << logn;

    LOG_DEBUG("Kyber CPA Decryption\n");
    LOG_DEBUG_ARRAY("NTT(s)", s, k*n);

    uint16_t q        = m_params[m_set].q;
    uint16_t q_inv    = m_params[m_set].q_inv;
    uint16_t q_norm   = m_params[m_set].q_norm;
    uint16_t d_u      = m_params[m_set].d_u;
    uint16_t d_v      = m_params[m_set].d_v;

    // Expand the transmitted u and v coefficients
    decompress(u, n, k, d_u, q);
    decompress(v, n, 1, d_v, q);
    LOG_DEBUG_ARRAY("Decompress(u)", u, k*n);
    LOG_DEBUG_ARRAY("Decompress(v)", v, n);

    // Multiply the transpose of s by u and subtract from v
    uint16_t *uu = reinterpret_cast<uint16_t*>(u);
    m_reduction.convert_to(uu, uu, k * n);
    m_ntt->fwd(uu, logn);
    m_ntt->mul(uu, s, uu);
    for (size_t i = 1; i < k; i++) {
        m_ntt->fwd(uu + i*n, logn);
        m_ntt->mul(uu + i*n, s + i*n, uu + i*n);

        for (size_t j = 0; j < n; j++) {
            uu[j] = m_reduction.add(uu[i*n + j], uu[j]);
        }
    }
    m_ntt->inv(uu, logn);
    m_reduction.convert_from(uu, uu, n);
    LOG_DEBUG_ARRAY("sT.u", u, n);
    core::poly<int16_t>::sub(v, n, v, u);
    core::poly<int16_t>::centre(v, q, n);
    LOG_DEBUG_ARRAY("v - sT.u", v, n);

    // Perform rounding of the output message
    compress(v, n, 1, 1, q, q_inv, q_norm);
    LOG_DEBUG_ARRAY("Compress(v)", v, n);

    // Generate the output message bytes
    for (size_t i = 0, j = 0; i < 32; i++) {
        m[i]  = v[j++] << 7;
        m[i] |= v[j++] << 6;
        m[i] |= v[j++] << 5;
        m[i] |= v[j++] << 4;
        m[i] |= v[j++] << 3;
        m[i] |= v[j++] << 2;
        m[i] |= v[j++] << 1;
        m[i] |= v[j++];
    }
    LOG_DEBUG_ARRAY("m", m, 32);
}

}  // namespace schemes
}  // namespace phantom
