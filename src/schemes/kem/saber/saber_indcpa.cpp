/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "schemes/kem/saber/saber_indcpa.hpp"

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


const saber_set_t saber_indcpa::m_params[3] = {
    {0, 8192, 256, 2, 1024,  8, 5, 13, 10, 3, 10, 4, 196},
    {1, 8192, 256, 3, 1024, 16, 4, 13, 10, 4,  8, 4, 228},
    {2, 8192, 256, 4, 1024, 32, 3, 13, 10, 6,  6, 4, 252},
};

size_t saber_indcpa::bits_2_set(security_strength_e bits)
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

        case SECURITY_STRENGTH_160:
        case SECURITY_STRENGTH_192:
        case SECURITY_STRENGTH_256: set = 2; break;

        default: {
            LOG_ERROR("Security strength is invalid", g_pkc_log_level);
            throw std::invalid_argument("Security strength is invalid");
        }
    }

    return set;
}

saber_indcpa::saber_indcpa(security_strength_e bits) : m_set(bits_2_set(bits))
{
    init();
}

saber_indcpa::saber_indcpa(size_t set) : m_set(set)
{
    init();
}

void saber_indcpa::init()
{
    if (m_set > 2) {
        throw std::invalid_argument("Parameter set is out of range");
    }

    m_prng = std::shared_ptr<csprng>(csprng::make(0x10000000, random_seed::seed_cb));
    m_xof  = std::unique_ptr<crypto::xof_sha3>(new crypto::xof_sha3());

    LOG_DEBUG("Kyber KEM Scheme", g_pkc_log_level);
}

saber_indcpa::~saber_indcpa()
{
}

void saber_indcpa::polq2bs(uint8_t* _RESTRICT_ out, const uint16_t* _RESTRICT_ in)
{
    for (size_t j = 0; j < SABER_N/8; j++) {
        size_t offset_out = 13 * j;
        size_t offset_in = 8 * j;
        out[offset_out +  0] = ((in[offset_in + 0] >>  0) & 0xff);
        out[offset_out +  1] = ((in[offset_in + 0] >>  8) & 0x1f) | ((in[offset_in + 1] & 0x07) << 5);
        out[offset_out +  2] = ((in[offset_in + 1] >>  3) & 0xff);
        out[offset_out +  3] = ((in[offset_in + 1] >> 11) & 0x03) | ((in[offset_in + 2] & 0x3f) << 2);
        out[offset_out +  4] = ((in[offset_in + 2] >>  6) & 0x7f) | ((in[offset_in + 3] & 0x01) << 7);
        out[offset_out +  5] = ((in[offset_in + 3] >>  1) & 0xff);
        out[offset_out +  6] = ((in[offset_in + 3] >>  9) & 0x0f) | ((in[offset_in + 4] & 0x0f) << 4);
        out[offset_out +  7] = ((in[offset_in + 4] >>  4) & 0xff);
        out[offset_out +  8] = ((in[offset_in + 4] >> 12) & 0x01) | ((in[offset_in + 5] & 0x7f) << 1);
        out[offset_out +  9] = ((in[offset_in + 5] >>  7) & 0x3f) | ((in[offset_in + 6] & 0x03) << 6);
        out[offset_out + 10] = ((in[offset_in + 6] >>  2) & 0xff);
        out[offset_out + 11] = ((in[offset_in + 6] >> 10) & 0x07) | ((in[offset_in + 7] & 0x1f) << 3);
        out[offset_out + 12] = ((in[offset_in + 7] >>  5) & 0xff);
    }
}

void saber_indcpa::bs2polq(uint16_t* _RESTRICT_ out, const uint8_t* _RESTRICT_ in)
{
    for (size_t j=0; j < SABER_N/8; j++) {
        size_t offset_in  = 13 * j;
        size_t offset_out = 8 * j;
        out[offset_out + 0] = ((in[offset_in +  0] & 0xff) <<  0) |
                              ((in[offset_in +  1] & 0x1f) <<  8);
        out[offset_out + 1] = ((in[offset_in +  1] >> 5) & 0x07)   |
                              ((in[offset_in +  2] & 0xff) <<  3)  |
                              ((in[offset_in +  3] & 0x03) << 11);
        out[offset_out + 2] = ((in[offset_in +  3] >> 2) & 0x3f)   |
                              ((in[offset_in +  4] & 0x7f) <<  6);
        out[offset_out + 3] = ((in[offset_in +  4] >> 7) & 0x01)   |
                              ((in[offset_in +  5] & 0xff) <<  1)  |
                              ((in[offset_in +  6] & 0x0f) <<  9);
        out[offset_out + 4] = ((in[offset_in +  6] >> 4) & 0x0f)   |
                              ((in[offset_in +  7] & 0xff) <<  4)  |
                              ((in[offset_in +  8] & 0x01) << 12);
        out[offset_out + 5] = ((in[offset_in +  8] >> 1) & 0x7f)   |
                              ((in[offset_in +  9] & 0x3f) <<  7);
        out[offset_out + 6] = ((in[offset_in +  9] >> 6) & 0x03)   |
                              ((in[offset_in + 10] & 0xff) <<  2)  |
                              ((in[offset_in + 11] & 0x07) << 10);
        out[offset_out + 7] = ((in[offset_in + 11] >> 3) & 0x1f)   |
                              ((in[offset_in + 12] & 0xff) <<  5);
    }
}

void saber_indcpa::polp2bs(uint8_t* _RESTRICT_ out, const uint16_t* _RESTRICT_ in)
{
    for (size_t j=0; j < SABER_N/4; j++) {
        size_t offset_byte = 5 * j;
        size_t offset_data = 4 * j;
        out[offset_byte + 0] = (in[offset_data + 0] & (0xff));
        out[offset_byte + 1] = ((in[offset_data + 0] >> 8) & 0x03) | ((in[offset_data + 1] & 0x3f) << 2);
        out[offset_byte + 2] = ((in[offset_data + 1] >> 6) & 0x0f) | ((in[offset_data + 2] & 0x0f) << 4);
        out[offset_byte + 3] = ((in[offset_data + 2] >> 4) & 0x3f) | ((in[offset_data + 3] & 0x03) << 6);
        out[offset_byte + 4] = ((in[offset_data + 3] >> 2) & 0xff);
    }
}

void saber_indcpa::bs2polp(uint16_t* _RESTRICT_ out, const uint8_t* _RESTRICT_ in)
{
    for (size_t j=0; j < SABER_N/4; j++) {
        size_t offset_in  = 5 * j;
        size_t offset_out = 4 * j;
        out[offset_out + 0] = ((in[offset_in + 0])      & (0xff)) | ((in[offset_in + 1] & 0x03) << 8);
        out[offset_out + 1] = ((in[offset_in + 1] >> 2) & (0x3f)) | ((in[offset_in + 2] & 0x0f) << 6);
        out[offset_out + 2] = ((in[offset_in + 2] >> 4) & (0x0f)) | ((in[offset_in + 3] & 0x3f) << 4);
        out[offset_out + 3] = ((in[offset_in + 3] >> 6) & (0x03)) | ((in[offset_in + 4] & 0xff) << 2);
    }
}

void saber_indcpa::gen_matrix_shake128(uint16_t* _RESTRICT_ A, const uint8_t* seed, size_t l, size_t k)
{
    // Create an array for the random output of the XOF
    phantom_vector<uint8_t> buf(k);

    // Use the random seed to generate
    m_xof->init(16);
    m_xof->absorb(seed, SABRE_MSG_LEN);
    m_xof->final();

    // Compute A from the random XOF output to generate L x L x 256 samples modulo p (i.e. 10 bits)
    for (size_t i=0; i < l; i++) {
        for (size_t j = 0; j < l; j++) {
            m_xof->squeeze(buf.data(), k);
            bs2polp(A + i*l*SABER_N + j*SABER_N, buf.data());
        }
    }
}

uint64_t saber_indcpa::load_littleendian(const uint8_t *x, size_t bytes)
{
    uint64_t r = x[0];
    for (size_t i = 1; i < bytes; i++) {
        r |= static_cast<uint64_t>(x[i]) << (8 * i);
    }
    return r;
}

void saber_indcpa::cbd_6(const uint8_t* _RESTRICT_ buf, uint16_t* _RESTRICT_ s)
{
    alignas(DEFAULT_MEM_ALIGNMENT) uint32_t t, d, a[4], b[4];

    for (size_t i=0; i < SABER_N/4; i++) {
        // Form a 24-bit unsigned random integer
        t  = static_cast<uint32_t>(buf[3*i+0]);
        t |= static_cast<uint32_t>(buf[3*i+1]) << 8;
        t |= static_cast<uint32_t>(buf[3*i+2]) << 16;

        // Calculate the sum of each 3-bit value within its value lane
        // to obtain eight values in the range of 0 to 3
        d  =  t       & 0x249249;
        d += (t >> 1) & 0x249249;
        d += (t >> 2) & 0x249249;

        // Isolate the 8 3-bit values into two arrays of 4 values
        a[0] =  d        & 0x7;
        b[0] = (d >>  3) & 0x7;
        a[1] = (d >>  6) & 0x7;
        b[1] = (d >>  9) & 0x7;
        a[2] = (d >> 12) & 0x7;
        b[2] = (d >> 15) & 0x7;
        a[3] = (d >> 18) & 0x7;
        b[3] = (d >> 21);

        // Calculate 4 values in the range of -3 to +3
        s[4*i + 0] = static_cast<uint16_t>(a[0] - b[0]);
        s[4*i + 1] = static_cast<uint16_t>(a[1] - b[1]);
        s[4*i + 2] = static_cast<uint16_t>(a[2] - b[2]);
        s[4*i + 3] = static_cast<uint16_t>(a[3] - b[3]);
    }
}

void saber_indcpa::cbd_8(const uint8_t* _RESTRICT_ buf, uint16_t* _RESTRICT_ s)
{
    alignas(DEFAULT_MEM_ALIGNMENT) uint32_t t, d, a[4], b[4];

    for (size_t i=0; i < SABER_N/4; i++) {
        // Form a 32-bit unsigned random integer
        t  = static_cast<uint32_t>(buf[4*i+0]);
        t |= static_cast<uint32_t>(buf[4*i+1]) << 8;
        t |= static_cast<uint32_t>(buf[4*i+2]) << 16;
        t |= static_cast<uint32_t>(buf[4*i+3]) << 24;

        // Calculate the sum of each 4-bit nibble within its nibble lane
        // to obtain eight values in the range of 0 to 4
        d  =  t       & 0x11111111;
        d += (t >> 1) & 0x11111111;
        d += (t >> 2) & 0x11111111;
        d += (t >> 3) & 0x11111111;

        // Isolate the 8 4-bit nibbles into two arrays of 4 values
        a[0] =  d        & 0xf;
        b[0] = (d >>  4) & 0xf;
        a[1] = (d >>  8) & 0xf;
        b[1] = (d >> 12) & 0xf;
        a[2] = (d >> 16) & 0xf;
        b[2] = (d >> 20) & 0xf;
        a[3] = (d >> 24) & 0xf;
        b[3] = (d >> 28);

        // Calculate 4 values in the range of -4 to +4
        s[4*i + 0] = static_cast<uint16_t>(a[0] - b[0]);
        s[4*i + 1] = static_cast<uint16_t>(a[1] - b[1]);
        s[4*i + 2] = static_cast<uint16_t>(a[2] - b[2]);
        s[4*i + 3] = static_cast<uint16_t>(a[3] - b[3]);
    }
}

void saber_indcpa::cbd_10(const uint8_t* _RESTRICT_ buf, uint16_t* _RESTRICT_ s)
{
    alignas(DEFAULT_MEM_ALIGNMENT) uint64_t t, d, a[4], b[4];

    for (size_t i=0; i < SABER_N/4; i++) {
            // Form a 40-bit unsigned random integer
        t  = static_cast<uint64_t>(buf[5*i+0]);
        t |= static_cast<uint64_t>(buf[5*i+1]) << 8;
        t |= static_cast<uint64_t>(buf[5*i+2]) << 16;
        t |= static_cast<uint64_t>(buf[5*i+3]) << 24;
        t |= static_cast<uint64_t>(buf[5*i+4]) << 32;

        // Calculate the sum of each 5-bit value within its value lane
        // to obtain eight values in the range of 0 to 5
        d  =  t       & 0x0842108421UL;
        d += (t >> 1) & 0x0842108421UL;
        d += (t >> 2) & 0x0842108421UL;
        d += (t >> 3) & 0x0842108421UL;
        d += (t >> 4) & 0x0842108421UL;

        // Isolate the 8 5-bit values into two arrays of 4 values
        a[0] =  d        & 0x1f;
        b[0] = (d >>  5) & 0x1f;
        a[1] = (d >> 10) & 0x1f;
        b[1] = (d >> 15) & 0x1f;
        a[2] = (d >> 20) & 0x1f;
        b[2] = (d >> 25) & 0x1f;
        a[3] = (d >> 30) & 0x1f;
        b[3] = (d >> 35);

        // Calculate 4 values in the range of -5 to +5
        s[4*i + 0] = static_cast<uint16_t>(a[0] - b[0]);
        s[4*i + 1] = static_cast<uint16_t>(a[1] - b[1]);
        s[4*i + 2] = static_cast<uint16_t>(a[2] - b[2]);
        s[4*i + 3] = static_cast<uint16_t>(a[3] - b[3]);
    }
}

void saber_indcpa::gen_secret_shake128(uint16_t* _RESTRICT_ s, const uint8_t* seed, size_t l, size_t mu)
{
    // Use the random seed to generate
    m_xof->init(16);
    m_xof->absorb(seed, SABRE_MSG_LEN);
    m_xof->final();

    phantom_vector<uint8_t> buf((SABER_N/4) * (mu/2));
    for (size_t i=0; i < l; i++) {
        m_xof->squeeze(buf.data(), (SABER_N/4) * (mu/2));

        switch (mu)
        {
        case 6:  cbd_6(buf.data(), s + i*SABER_N); break;
        case 8:  cbd_8(buf.data(), s + i*SABER_N); break;
        default: cbd_10(buf.data(), s + i*SABER_N);
        }
    }
}

void saber_indcpa::matrix_mul(uint16_t *out, size_t l, const uint16_t *in1, const uint16_t *in2, bool transpose)
{
    for (size_t i = 0; i < l; i++) {
        for (size_t j = 0; j < l; j++) {
            if (transpose) {
                core::poly<uint16_t>::mul_acc<uint32_t, uint64_t, SABER_N>(out + i*SABER_N,
                                                                           in1 + j*l*SABER_N + i*SABER_N,
                                                                           in2 + i*SABER_N);
            }
            else {
                core::poly<uint16_t>::mul_acc<uint32_t, uint64_t, SABER_N>(out + i*SABER_N,
                                                                           in1 + i*l*SABER_N + j*SABER_N,
                                                                           in2 + i*SABER_N);
            }
        }
    }
}

void saber_indcpa::keygen(phantom_vector<uint8_t>& pk, phantom_vector<uint8_t>& sk)
{
    LOG_DEBUG("Saber CPA Key Generation\n", g_pkc_log_level);

    // NOTE: the psuedorandom number r is provided as an input
    // and the public key is already decompressed

    size_t   l        = m_params[m_set].l;
    size_t   eq       = m_params[m_set].eq;
    size_t   ep       = m_params[m_set].ep;
    size_t   mu       = m_params[m_set].mu;
    size_t   h1       = m_params[m_set].h1;

    phantom_vector<uint8_t> storage_8(2 * SABRE_MSG_LEN);
    uint8_t* seed_s = storage_8.data();        // SABRE_MSG_LEN
    uint8_t* seed_A = seed_s + SABRE_MSG_LEN;  // SABRE_MSG_LEN

    phantom_vector<uint16_t> storage_16(l*SABER_N*(2+l));
    uint16_t* s = storage_16.data();    // l*SABER_N
    uint16_t* A = s + l*SABER_N;        // l*l*SABER_N
    uint16_t* b = A + l*l*SABER_N;      // l*SABER_N

    // Generate the 256-bit random seed for A, then generate the matrix A
    m_prng->get_mem(seed_A, SABRE_MSG_LEN);
    m_xof->init(16);
    m_xof->absorb(seed_A, SABRE_MSG_LEN);
    m_xof->final();
    m_xof->squeeze(seed_A, SABRE_MSG_LEN);
    LOG_DEBUG_ARRAY("seed_A", g_pkc_log_level, seed_A, SABRE_MSG_LEN);
    gen_matrix_shake128(A, seed_A, l, eq*(SABER_N/8));

    // Generate the 256-bit random seed for the secret and the secret matrix s
    m_prng->get_mem(seed_s, SABRE_MSG_LEN);
    gen_secret_shake128(s, seed_s, l, mu);

    // Calculate b = A^T.s and scale the output
    memset(b, 0, sizeof(uint16_t) * l * SABER_N);
    matrix_mul(b, l, A, s, true);
    for (size_t i=0; i < l*SABER_N; i++) {
        b[i] = (b[i] + h1) >> (eq - ep);
    }

    // Pack the 13-bit secret key and 10-bit public key into arrays
    // for distribution and storage
    sk = phantom_vector<uint8_t>(l*eq*(SABER_N/8));
    pk = phantom_vector<uint8_t>(l*ep*(SABER_N/8) + SABRE_MSG_LEN);
    for (size_t i=0; i < l; i++) {
        polq2bs(sk.data() + i * eq * (SABER_N/8), s + i*SABER_N);
        polp2bs(pk.data() + i * ep * (SABER_N/8), b + i*SABER_N);
    }

    // Append the seed to the end of the public key
    std::copy(seed_A, seed_A + SABRE_MSG_LEN, pk.begin() + l*ep*(SABER_N/8));
}

void saber_indcpa::enc(const phantom_vector<uint8_t>& pk, const phantom_vector<uint8_t>& pt,
    const uint8_t* _RESTRICT_ seed_s, phantom_vector<uint8_t>& ct)
{
    LOG_DEBUG("Saber CPA Encryption\n", g_pkc_log_level);

    size_t   l        = m_params[m_set].l;
    size_t   eq       = m_params[m_set].eq;
    size_t   ep       = m_params[m_set].ep;
    size_t   et       = m_params[m_set].et;
    size_t   mu       = m_params[m_set].mu;
    size_t   h1       = m_params[m_set].h1;

    phantom_vector<uint8_t> seed_A(SABRE_MSG_LEN);
    phantom_vector<uint16_t> storage(SABER_N * (2 + 3*l + l*l));
    uint16_t* mp = storage.data();   // SABER_N
    uint16_t* A  = mp + SABER_N;     // l*l*SABER_N
    uint16_t* bp = A + l*l*SABER_N;  // l*SABER_N
    uint16_t* b  = bp + l*SABER_N;   // l*SABER_N
    uint16_t* sp = b + l*SABER_N;    // l*SABER_N
    uint16_t* vp = sp + l*SABER_N;   // l*SABER_N

    // Create a local copy of the seed for A from the public key and use
    // it to generate the matrix A, identical to the matrix A from the other party
    std::copy(pk.begin() + l*ep*(SABER_N/8), pk.begin() + l*ep*(SABER_N/8) + SABRE_MSG_LEN, seed_A.begin());
    gen_matrix_shake128(A, seed_A.data(), l, eq*(SABER_N/8));

    // Generate the secret noise
    gen_secret_shake128(sp, seed_s, l, mu);

    // Calculate bp = A^T.sp
    memset(bp, 0, sizeof(uint16_t)*l*SABER_N);
    matrix_mul(bp, l, A, sp, true);
    for (size_t i=0; i < l*SABER_N; i++) {
        bp[i] = (bp[i] + h1) >> (eq - ep);
    }

    // Recreate the ciphertext from bp
    ct = phantom_vector<uint8_t>(l*ep*(SABER_N/8));
    for (size_t i=0; i < l; i++) {
        polp2bs(ct.data() + i*(ep*(SABER_N/8)), bp + i*SABER_N);
    }

    // Combine the public key with the noise to form vp
    memset(vp, 0, sizeof(uint16_t)*SABER_N);
    for (size_t i=0; i < l; i++) {
        bs2polp(b + i*SABER_N, pk.data() + i*(ep*(SABER_N/8)));
        core::poly<uint16_t>::mul_acc<uint32_t, uint64_t, SABER_N>(vp, b + i*SABER_N, sp + i*SABER_N);
    }

    // Translate each bit of the message into a 256 element message array
    uint16_t* mp_ptr = mp;
    for (size_t j=0; j < SABRE_MSG_LEN; j++) {
        uint8_t data = pt[j];
        *mp_ptr++ = (data >> 0) & 0x1;
        *mp_ptr++ = (data >> 1) & 0x1;
        *mp_ptr++ = (data >> 2) & 0x1;
        *mp_ptr++ = (data >> 3) & 0x1;
        *mp_ptr++ = (data >> 4) & 0x1;
        *mp_ptr++ = (data >> 5) & 0x1;
        *mp_ptr++ = (data >> 6) & 0x1;
        *mp_ptr++ = (data >> 7) & 0x1;
    }

    // Embed the message into the noisy array vp
    for (size_t j=0; j < SABER_N; j++) {
        vp[j] = (vp[j] - (mp[j] << (ep - 1)) + h1) >> (ep - et);
    }

    // Generate the packed message array
    packing::packer pack_c(SABER_N * et);
    for (size_t i=0; i < SABER_N; i++) {
        pack_c.write_unsigned(vp[i], et, packing::RAW);
    }
    pack_c.flush();
    auto ct_vp = pack_c.get();

    // Append the encrypted message to the ciphertext
    ct.insert(ct.end(), ct_vp.begin(), ct_vp.end());
}

void saber_indcpa::dec(const phantom_vector<uint8_t>& sk, const phantom_vector<uint8_t>& ct,
    uint8_t* pt)
{
    LOG_DEBUG("Saber CPA Decryption\n", g_pkc_log_level);

    size_t   l        = m_params[m_set].l;
    size_t   eq       = m_params[m_set].eq;
    size_t   ep       = m_params[m_set].ep;
    size_t   et       = m_params[m_set].et;
    size_t   h2       = m_params[m_set].h2;

    phantom_vector<uint16_t> storage(SABER_N * (2 + 2*l));
    uint16_t* s  = storage.data();    // l*SABER_N
    uint16_t* b  = s + l*SABER_N;     // l*SABER_N
    uint16_t* cm = b + l*SABER_N;     // SABER_N
    uint16_t* v  = cm + SABER_N;      // SABER_N

    // Unpack the secret key and the ciphertext and calculate v = b.s
    memset(v, 0, sizeof(uint16_t) * SABER_N);
    for (size_t i=0; i < l; i++) {
        bs2polq(s + i*SABER_N, sk.data() + i*(eq*(SABER_N/8)));
        bs2polp(b + i*SABER_N, ct.data() + i*(ep*(SABER_N/8)));
        core::poly<uint16_t>::mul_acc<uint32_t, uint64_t, SABER_N>(v, b + i*SABER_N, s + i*SABER_N);
    }

    // Unpack the ciphertext message from the end of the ciphertext structure
    phantom_vector<uint8_t> ucm(ct.begin() + l*ep*(SABER_N/8), ct.end());
    packing::unpacker unpack(ucm);
    for (size_t i=0; i < SABER_N; i++) {
        cm[i] = unpack.read_unsigned(et, packing::RAW);
    }

    // Remove the secret key controlled noise from the ciphertext message
    // to reveal the plaintext
    for (size_t i=0; i < SABER_N; i++)
    {
        v[i] = (v[i] + h2 - (cm[i] << (ep - et))) >> (ep - 1);
    }

    // Extract each plaintext bit from the 256 element message array
    // to form the 32 byte plaintext message
    uint16_t* v_ptr = v;
    for (size_t j=0; j < SABRE_MSG_LEN; j++)
    {
        pt[j]  = (*v_ptr++ & 0x01);
        pt[j] |= (*v_ptr++ & 0x01) << 1;
        pt[j] |= (*v_ptr++ & 0x01) << 2;
        pt[j] |= (*v_ptr++ & 0x01) << 3;
        pt[j] |= (*v_ptr++ & 0x01) << 4;
        pt[j] |= (*v_ptr++ & 0x01) << 5;
        pt[j] |= (*v_ptr++ & 0x01) << 6;
        pt[j] |= (*v_ptr++ & 0x01) << 7;
    }
}

}  // namespace schemes
}  // namespace phantom
