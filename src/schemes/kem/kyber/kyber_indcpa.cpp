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

#include "schemes/kem/kyber/kyber_ntt.hpp"
#include "schemes/kem/kyber/kyber_reduce.hpp"
#include "sampling/uniform_sampler.hpp"
#include "logging/logger.hpp"
#include "core/poly.hpp"
#include "packing/packer.hpp"
#include "packing/unpacker.hpp"
#include "packing/stream.hpp"
#include "crypto/random_seed.hpp"
#include "crypto/hash_sha3.hpp"
#include "crypto/xof_sha3.hpp"



#define SHAKE128_RATE             168
#define XOF_BLOCKBYTES            SHAKE128_RATE
#define GEN_MATRIX_NBLOCKS(n, q)  ((12*(n)/8*(1 << 12)/(q) + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)


namespace phantom {
namespace schemes {

const kyber_set_t kyber_indcpa::m_params[3] = {
    {0, 3329, 12, 0x9D7E, 27, 256, 8, 2, 3, 3, 2, 10, 4, 12, 62209, 2285, 1353},
    {1, 3329, 12, 0x9D7E, 27, 256, 8, 3, 2, 3, 2, 10, 4, 12, 62209, 2285, 1353},
    {2, 3329, 12, 0x9D7E, 27, 256, 8, 4, 2, 3, 2, 11, 5, 12, 62209, 2285, 1353},
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

        default: {
            LOG_ERROR("Security strength is invalid", g_pkc_log_level);
            throw std::invalid_argument("Security strength is invalid");
        }
    }

    return set;
}

kyber_indcpa::kyber_indcpa(security_strength_e bits) :
    m_set(bits_2_set(bits))
{
    init();
}

kyber_indcpa::kyber_indcpa(size_t set) :
    m_set(set)
{
    init();
}

void kyber_indcpa::init()
{
    if (m_set > 2) {
        throw std::invalid_argument("Parameter set is out of range");
    }

    m_prng   = std::shared_ptr<csprng>(csprng::make(0x10000000, random_seed::seed_cb));
    m_xof    = std::unique_ptr<crypto::xof_sha3>(new crypto::xof_sha3());
    m_sha3   = std::unique_ptr<crypto::hash_sha3>(new crypto::hash_sha3());

    LOG_DEBUG("Kyber KEM Scheme", g_pkc_log_level);
}

kyber_indcpa::~kyber_indcpa()
{
}

size_t kyber_indcpa::reject_uniform(int16_t *r, size_t len, uint16_t q, const uint8_t *buf, size_t buflen)
{
    size_t ctr, pos;

    ctr = pos = 0;
    while (ctr < len && pos + 3 <= buflen) {
        uint16_t val0 = ((buf[pos+0] >> 0) | (static_cast<uint16_t>(buf[pos + 1]) << 8)) & 0xfff;
        uint16_t val1 = ((buf[pos+1] >> 4) | (static_cast<uint16_t>(buf[pos + 2]) << 4)) & 0xfff;
        pos += 3;

        if (val0 < q) {
            r[ctr++] = val0;
        }
        if (ctr < len && val1 < q) {
            r[ctr++] = val1;
        }
    }

    return ctr;
}

// Not static for benchmarking
void kyber_indcpa::gen_matrix(int16_t *a, const uint8_t *seed, bool transposed)
{
    const size_t n       = m_params[m_set].n;
    const uint16_t q     = m_params[m_set].q;
    const size_t kyber_k = m_params[m_set].k;

    unsigned int off;
    phantom_vector<uint8_t> scratch(GEN_MATRIX_NBLOCKS(n, q) * XOF_BLOCKBYTES + 2);
    uint8_t *buf   = scratch.data();
    uint8_t *nonce = buf + GEN_MATRIX_NBLOCKS(n, q) * XOF_BLOCKBYTES;

    for (size_t i=0; i < kyber_k; i++) {
        for (size_t j=0; j < kyber_k; j++) {
            size_t buflen = GEN_MATRIX_NBLOCKS(n, q) * XOF_BLOCKBYTES;

            if (transposed) {
                nonce[0] = i;
                nonce[1] = j;
            }
            else {
                nonce[0] = j;
                nonce[1] = i;
            }

            // SHAKE-128
            m_xof->init(16);
            m_xof->absorb(seed, 32);
            m_xof->absorb(nonce, 2);
            m_xof->squeeze(buf, buflen);

            size_t ctr = reject_uniform(a + i*n*kyber_k + j*n, n, q, buf, buflen);

            while (ctr < n) {
                off    = buflen % 3;

                for (size_t k = 0; k < off; k++) {
                    buf[k] = buf[buflen - off + k];
                }

                m_xof->squeeze(buf + off, XOF_BLOCKBYTES);
                buflen = off + XOF_BLOCKBYTES;
                ctr   += reject_uniform(a + i*n*kyber_k + j*n + ctr, n - ctr, q, buf, buflen);
            }
        }
    }
}

void kyber_indcpa::shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    m_xof->init(32);
    m_xof->absorb(in, inlen);
    m_xof->final();
    m_xof->squeeze(out, outlen);
}

void kyber_indcpa::kyber_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce)
{
    uint8_t extkey[KYBER_SYMBYTES+1];

    memcpy(extkey, key, KYBER_SYMBYTES);
    extkey[KYBER_SYMBYTES] = nonce;

    shake256(out, outlen, extkey, sizeof(extkey));
}

void kyber_indcpa::binomial_getnoise(int16_t *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce,
        const uint16_t eta, const size_t n, const size_t k)
{
    assert(3 == eta || 2 == eta);
    phantom_vector<uint8_t> buf(3 * n / 4);

    for (size_t i = 0; i < k; i++) {
        kyber_shake256_prf(buf.data(), buf.size(), seed, nonce++);
        if (3 == eta) {
            cbd3(r + n*i, buf.data(), n);
        }
        else {
            cbd2(r + n*i, buf.data(), n);
        }
    }
}

uint32_t kyber_indcpa::load32_littleendian(const uint8_t x[4])
{
    uint32_t r;
    r  = static_cast<uint32_t>(x[0]);
    r |= static_cast<uint32_t>(x[1]) << 8;
    r |= static_cast<uint32_t>(x[2]) << 16;
    r |= static_cast<uint32_t>(x[3]) << 24;
    return r;
}

uint32_t kyber_indcpa::load24_littleendian(const uint8_t x[3])
{
    uint32_t r;
    r  = static_cast<uint32_t>(x[0]);
    r |= static_cast<uint32_t>(x[1]) << 8;
    r |= static_cast<uint32_t>(x[2]) << 16;
    return r;
}

void kyber_indcpa::cbd2(int16_t *r, const uint8_t *buf, const size_t n)
{
    uint32_t t, d;
    int16_t  a, b;

    for (size_t i = 0; i < n/8; i++) {
        t  = load32_littleendian(buf+4*i);
        d  = t & 0x55555555;
        d += (t>>1) & 0x55555555;

        for (size_t j = 0; j < 8; j++) {
            a = (d >> (4*j+0)) & 0x3;
            b = (d >> (4*j+2)) & 0x3;
            r[8*i+j] = a - b;
        }
    }
}

void kyber_indcpa::cbd3(int16_t *r, const uint8_t *buf, const size_t n)
{
    uint32_t t, d;
    int16_t  a, b;

    for (size_t i = 0; i < n/4; i++) {
        t  = load24_littleendian(buf+3*i);
        d  = t & 0x00249249;
        d += (t>>1) & 0x00249249;
        d += (t>>2) & 0x00249249;

        for (size_t j = 0; j < 4; j++) {
            a = (d >> (6*j+0)) & 0x7;
            b = (d >> (6*j+3)) & 0x7;
            r[4*i+j] = a - b;
        }
    }
}

void kyber_indcpa::compress(int16_t *inout, size_t n, size_t k, size_t d,
    uint16_t q, uint16_t q_inv, uint16_t q_norm)
{
    int64_t rnd_q2 = q >> 1;
    int16_t mod_2d = (1 << (d + 1)) - 1;

    for (size_t i = 0; i < k*n; i++) {
        inout[i] += (inout[i] >> 15) & q;
        inout[i]  = ((((static_cast<uint64_t>(inout[i]) << (d + 1)) + rnd_q2) * q_inv) >> q_norm) & mod_2d;
    }
}

// Translate an integer in the range 0 ... 2^d - 1 to an element in Zq,
// where d < rnd(2^d - 1)
void kyber_indcpa::decompress(int16_t *inout, size_t n, size_t k, size_t d, uint16_t q)
{
    int16_t mod_2d = (1 << (d + 1)) - 1;
    int16_t d_2    = 1 << d;

    for (size_t i = 0; i < k*n; i++) {
        inout[i] = (static_cast<uint32_t>(inout[i] & mod_2d) * q + d_2) >> (d + 1);
    }
}

void kyber_indcpa::map_msg_to_poly(int16_t *r, const uint8_t *msg, const uint16_t q, const size_t n)
{
    int16_t mask;

    for (size_t i = 0; i < n/8; i++) {
        for (size_t j = 0; j < 8; j++) {
            mask = -static_cast<int16_t>((msg[i] >> j)&1);
            r[8*i+j] = mask & ((q+1)/2);
        }
    }
}

void kyber_indcpa::map_poly_to_msg(uint8_t *msg, const int16_t *a, const uint16_t q,
    const uint16_t q_inv, const uint16_t q_norm, const size_t n)
{
    uint16_t t;

    for (size_t i = 0; i < n/8; i++) {
        msg[i] = 0;
        for (size_t j = 0; j < 8; j++) {
            t  = a[8*i+j];
            t += (static_cast<int16_t>(t) >> 15) & q;
            t  = (static_cast<uint64_t>(((t << 1) + q/2) * q_inv) >> q_norm) & 1;
            msg[i] |= t << j;
        }
    }
}

void kyber_indcpa::keygen(uint8_t * _RESTRICT_ rho, int16_t * _RESTRICT_ s, int16_t * _RESTRICT_ t)
{
    // NOTE: the psuedorandom number r is provided as an input
    // and the public key is already decompressed

    const size_t   n        = m_params[m_set].n;
    const size_t   k        = m_params[m_set].k;
    const uint16_t q        = m_params[m_set].q;
    const uint16_t mont_inv = m_params[m_set].mont_inv;
    const uint16_t eta1     = m_params[m_set].eta1;

    phantom_vector<int16_t> scratch((1 + k) * k * n);
    int16_t *e = scratch.data();
    int16_t *a = e + k * n;

    // Generate a 256 bit random byte array to be used to seed a CSPRNG.
    m_prng->get_mem(rho, 32);
    LOG_DEBUG_ARRAY("rho", g_pkc_log_level, rho, 32);

    // Generate the seed for matrix A from rho
    uint8_t noiseseed[64];
    m_sha3->init(32);
    m_sha3->update(rho, 32);
    m_sha3->final(noiseseed);
    LOG_DEBUG_ARRAY("noiseseed", g_pkc_log_level, noiseseed, sizeof(noiseseed));

    // Generate matrix A deterministically using noiseseed
    gen_matrix(a, noiseseed, false);

    // Generate s1 and s2 from a uniform random distribution with values of
    // -eta to +eta inclusive.
    uint8_t nonce = 0;
    binomial_getnoise(s, noiseseed, nonce+=k, eta1, n, k);
    binomial_getnoise(e, noiseseed, nonce+=k, eta1, n, k);
    LOG_DEBUG_ARRAY("s", g_pkc_log_level, s, k * n);
    LOG_DEBUG_ARRAY("e", g_pkc_log_level, e, k * n);

    // Convert sand e tothe NTT domain
    kyber_ntt::fwd_ntt(s, k, n, q, mont_inv);
    kyber_ntt::fwd_ntt(e, k, n, q, mont_inv);
    LOG_DEBUG_ARRAY("NTT(s)", g_pkc_log_level, s, k * n);

    // Calculate t = As + e (NTT domain)
    kyber_ntt::mul_acc_mont(t, k, k, a, s, n, q, mont_inv);
    kyber_ntt::tomont(t, k, n, q, mont_inv);
    core::poly<int16_t>::add(t, k * n, t, e);

    // Map t to the range -q/2 to q/2
    kyber_reduce::poly_barrett(t, n, k, q);
    LOG_DEBUG_ARRAY("t = As + e", g_pkc_log_level, t, k * n);
}

void kyber_indcpa::enc(int16_t * _RESTRICT_ u, int16_t * _RESTRICT_ v, const int16_t * _RESTRICT_ t_ntt,
    const uint8_t * _RESTRICT_ pk_rho, const uint8_t *coins, size_t k, const uint8_t * _RESTRICT_ m)
{
    LOG_DEBUG("Kyber CPA Encryption\n", g_pkc_log_level);

    // NOTE: the psuedorandom number r is provided as an input
    // and the public key is already decompressed

    const size_t   n        = m_params[m_set].n;
    const uint16_t q        = m_params[m_set].q;
    const uint16_t q_inv    = m_params[m_set].q_inv;
    const uint16_t mont_inv = m_params[m_set].mont_inv;
    const uint16_t q_norm   = m_params[m_set].q_norm;
    const uint16_t eta1     = m_params[m_set].eta1;
    const uint16_t eta2     = m_params[m_set].eta2;
    const uint16_t d_u      = m_params[m_set].d_u;
    const uint16_t d_v      = m_params[m_set].d_v;

    int16_t *temp  = reinterpret_cast<int16_t*>(aligned_malloc(((k + 2) * k + 2) * n * sizeof(int16_t)));
    int16_t *at    = temp;
    int16_t *mm    = at + k * k * n;
    int16_t *r_eta = mm + n;
    int16_t *e1    = r_eta + k * n;
    int16_t *e2    = e1 + k * n;

    LOG_DEBUG_ARRAY("m", g_pkc_log_level, m, 32);
    LOG_DEBUG_ARRAY("rho", g_pkc_log_level, pk_rho, 32);
    LOG_DEBUG_ARRAY("r", g_pkc_log_level, r_eta, 32);

    phantom_vector<uint8_t> noiseseed_vec(64);
    uint8_t *noiseseed = noiseseed_vec.data();

    uint8_t nonce = 0;
    binomial_getnoise(r_eta, coins, nonce+=k, eta1, n, k);
    binomial_getnoise(e1, coins, nonce+=k, eta2, n, k);
    binomial_getnoise(e2, coins, nonce++, eta2, n, 1);
    LOG_DEBUG_ARRAY("r_eta = Sam(r)", g_pkc_log_level, r_eta, k*n);
    LOG_DEBUG_ARRAY("e1 = Sam(r)", g_pkc_log_level, e1, k * n);
    LOG_DEBUG_ARRAY("e2 = Sam(r)", g_pkc_log_level, e2, n);

    LOG_DEBUG_ARRAY("t = As + e", g_pkc_log_level, t_ntt, k * n);

    crypto::hash_sha3 sha3;
    sha3.init(32);
    sha3.update(pk_rho, 32);
    sha3.final(noiseseed);

    kyber_ntt::fwd_ntt(r_eta, k, n, q, mont_inv);

    // Generate a random kxk matrix A of n-element rings, multiply by r_eta
    // and add e1
    gen_matrix(at, noiseseed, true);
    kyber_ntt::mul_acc_mont(u, k, k, at, r_eta, n, q, mont_inv);
    kyber_ntt::mul_acc_mont(v, k, 1, t_ntt, r_eta, n, q, mont_inv);
    kyber_ntt::invntt_tomont(u, k, n, q, mont_inv);
    kyber_ntt::invntt_tomont(v, 1, n, q, mont_inv);
    LOG_DEBUG_ARRAY("tT.r", g_pkc_log_level, v, n);

    core::poly<int16_t>::add(u, k*n, u, e1);
    LOG_DEBUG_ARRAY("NTT(r_eta)", g_pkc_log_level, r_eta, k * n);

    // Map the message to q/2 and add to v with e2
    map_msg_to_poly(mm, m, q, n);
    core::poly<int16_t>::add(v, n, v, mm);
    core::poly<int16_t>::add(v, n, v, e2);

    // Map u and v to the range -q/2 to q/2
    kyber_reduce::poly_barrett(u, n, k, q);
    kyber_reduce::poly_barrett(v, n, 1, q);
    LOG_DEBUG_ARRAY("u = AT.r + e1", g_pkc_log_level, u, k * n);
    LOG_DEBUG_ARRAY("v = t^Tr + [q/2].m + e2", g_pkc_log_level, v, n);

    // Compress the two encryption variables
    compress(u, n, k, d_u, q, q_inv, q_norm);
    compress(v, n, 1, d_v, q, q_inv, q_norm);
    LOG_DEBUG_ARRAY("Compress(u)", g_pkc_log_level, u, k*n);
    LOG_DEBUG_ARRAY("Compress(v)", g_pkc_log_level, v, n);

    // Free the temporary memory resources (and erase the contents)
    aligned_free(temp);
}

void kyber_indcpa::dec(int16_t* _RESTRICT_ u, int16_t* _RESTRICT_ v,
    const int16_t* _RESTRICT_ s, size_t k, uint8_t* _RESTRICT_ m)
{
    const size_t   n        = m_params[m_set].n;
    const uint16_t q        = m_params[m_set].q;
    const uint16_t q_inv    = m_params[m_set].q_inv;
    const uint16_t mont_inv = m_params[m_set].mont_inv;
    const uint16_t q_norm   = m_params[m_set].q_norm;
    const uint16_t d_u      = m_params[m_set].d_u;
    const uint16_t d_v      = m_params[m_set].d_v;

    int16_t *temp  = reinterpret_cast<int16_t*>(aligned_malloc(n * sizeof(int16_t)));

    LOG_DEBUG("Kyber CPA Decryption\n", g_pkc_log_level);
    LOG_DEBUG_ARRAY("NTT(s)", g_pkc_log_level, reinterpret_cast<const int16_t*>(s), k*n);

    // Expand the transmitted u and v coefficients
    decompress(u, n, k, d_u, q);
    decompress(v, n, 1, d_v, q);
    LOG_DEBUG_ARRAY("Decompress(u)", g_pkc_log_level, u, k*n);
    LOG_DEBUG_ARRAY("Decompress(v)", g_pkc_log_level, v, n);

    kyber_ntt::fwd_ntt(u, k, n, q, mont_inv);
    kyber_ntt::mul_acc_mont(temp, k, 1, s, u, n, q, mont_inv);
    kyber_ntt::invntt_tomont(temp, 1, n, q, mont_inv);
    LOG_DEBUG_ARRAY("s*u", g_pkc_log_level, temp, n);

    core::poly<int16_t>::sub(v, n, v, temp);
    kyber_reduce::poly_barrett(v, n, 1, q);
    LOG_DEBUG_ARRAY("v", g_pkc_log_level, v, n);

    map_poly_to_msg(m, v, q, q_inv, q_norm, n);
    LOG_DEBUG_ARRAY("m decrypt", g_pkc_log_level, m, 32);

    // Free the temporary memory resources (and erase the contents)
    aligned_free(temp);
}

}  // namespace schemes
}  // namespace phantom
