/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "schemes/signature/dilithium/dilithium_signature.hpp"
#include "schemes/signature/dilithium/ctx_dilithium.hpp"
#include "logging/logger.hpp"
#include "core/const_time.hpp"
#include "core/poly.hpp"
#include "packing/packer.hpp"
#include "packing/unpacker.hpp"
#include "packing/stream.hpp"


namespace phantom {
namespace schemes {


size_t dilithium_signature::bits_2_set(security_strength_e bits)
{
    // Select the most appropriate parameter set for the given security strength
    size_t set = 0;
    switch (bits)
    {
        case SECURITY_STRENGTH_60:  set = 0; break;

        case SECURITY_STRENGTH_80:
        case SECURITY_STRENGTH_96:  set = 1; break;

        case SECURITY_STRENGTH_112:
        case SECURITY_STRENGTH_128: set = 2; break;

        case SECURITY_STRENGTH_160: set = 3; break;

        default: throw std::invalid_argument("Security strength is invalid");
    }

    return set;
}

dilithium_signature::dilithium_signature()
{
}

dilithium_signature::~dilithium_signature()
{
}

std::unique_ptr<user_ctx> dilithium_signature::create_ctx(security_strength_e bits,
                                                          cpu_word_size_e size_hint,
                                                          bool masking) const
{
    ctx_dilithium* ctx = new ctx_dilithium(dilithium_signature::bits_2_set(bits));
    if (ctx->get_set() > 3) {
        throw std::invalid_argument("Parameter set is out of range");
    }
    return std::unique_ptr<user_ctx>(ctx);
}

std::unique_ptr<user_ctx> dilithium_signature::create_ctx(size_t set,
                                                          cpu_word_size_e size_hint,
                                                          bool masking) const
{
    ctx_dilithium* ctx = new ctx_dilithium(set);
    if (ctx->get_set() > 3) {
        throw std::invalid_argument("Parameter set is out of range");
    }
    return std::unique_ptr<user_ctx>(ctx);
}

uint32_t reject_eta(int32_t *s, unsigned int n, int32_t eta, const uint8_t *buf, uint32_t eta_blockbytes)
{
    uint32_t ctr, pos;
    ctr = pos = 0;
    while (ctr < n && pos < eta_blockbytes) {
        uint32_t t0 = buf[pos] & 0x0F;
        uint32_t t1 = buf[pos++] >> 4;

        if (2 == eta) {
            if (t0 < 15) {
                t0 = t0 - (205*t0 >> 10)*5;
                s[ctr++] = 2 - t0;
            }
            if(t1 < 15 && ctr < n) {
                t1 = t1 - (205*t1 >> 10)*5;
                s[ctr++] = 2 - t1;
            }
        }
        else {
            if(t0 < 9)
                s[ctr++] = 4 - t0;
            if(t1 < 9 && ctr < n)
                s[ctr++] = 4 - t1;
        }
    }

    return ctr;
}

void dilithium_signature::uniform_rand_sample_small(crypto::xof *xof, const phantom_vector<uint8_t>& seed, uint32_t q, int32_t eta, size_t bits,
    int32_t *s, size_t n, size_t m, uint16_t nonce) const
{
    // Uniform sampling of an mx1 matrix with coefficients of -eta to +eta

    uint32_t stream256_blockbytes = 136;
    uint32_t eta_nblocks;
    if (2 == eta) {
        eta_nblocks = (136 + stream256_blockbytes - 1) / stream256_blockbytes;
    }
    else {
        eta_nblocks = (227 + stream256_blockbytes - 1) / stream256_blockbytes;
    }

    phantom_vector<uint8_t> buf(eta_nblocks * stream256_blockbytes);

    uint32_t ctr;
    for (size_t i=0; i  <m*n; i+=256, nonce++) {

        uint8_t t[2];
        t[0] = nonce;
        t[1] = nonce >> 8;

        xof->init(32);
        xof->absorb(seed.data(), seed.size());
        xof->absorb(t, 2);
        xof->final();
        xof->squeeze(buf.data(), buf.size());

        ctr = reject_eta(s + i, n, eta, buf.data(), stream256_blockbytes * eta_nblocks);

        while (ctr < n) {
            xof->squeeze(buf.data(), stream256_blockbytes);
            ctr += reject_eta(s + i + ctr, n - ctr, eta, buf.data(), stream256_blockbytes);
        }
    }
}

void dilithium_signature::uniform_random_ring_q(dilithium* dil,
                                                uint8_t *seed,
                                                uint16_t nonce,
                                                int32_t *a,
                                                size_t n,
                                                uint32_t q,
                                                uint32_t q_bits) const
{
    /*uint32_t mask = (1 << q_bits) - 1;
    uint32_t t;
    uint8_t buf[3];

    size_t i = 0;
    while (i < n) {
        dil->get_xof()->squeeze(buf, 3);

        t  = buf[0];
        t |= static_cast<uint32_t>(buf[1]) << 8;
        t |= static_cast<uint32_t>(buf[2]) << 16;
        t &= mask;

        if (t < q) {
            a[i++] = t - (static_cast<uint32_t>(q - t - 1) >> 31) * q;
        }
    }*/
    #define SHAKE128_RATE          168
    #define STREAM128_BLOCKBYTES   SHAKE128_RATE
    #define POLY_UNIFORM_NBLOCKS   ((768 + STREAM128_BLOCKBYTES - 1)/STREAM128_BLOCKBYTES)
    unsigned int i, ctr, off;
    unsigned int buflen = POLY_UNIFORM_NBLOCKS*STREAM128_BLOCKBYTES;
    uint8_t buf[POLY_UNIFORM_NBLOCKS*STREAM128_BLOCKBYTES + 2];
    uint8_t nonce_bytes[2] = {static_cast<uint8_t>(nonce & 0xFF), static_cast<uint8_t>(nonce >> 8)};

    dil->get_xof()->init(16);
    dil->get_xof()->absorb(seed, 32);
    dil->get_xof()->absorb(nonce_bytes, 2);
    dil->get_xof()->squeeze(buf, POLY_UNIFORM_NBLOCKS * SHAKE128_RATE);

    ctr = dil->rej_uniform(a, n, buf, buflen, q);

    while (ctr < n) {
        off = buflen % 3;
        for (i = 0; i < off; ++i)
        buf[i] = buf[buflen - off + i];

        dil->get_xof()->squeeze(buf + off, SHAKE128_RATE);
        buflen = STREAM128_BLOCKBYTES + off;
        ctr += dil->rej_uniform(a + ctr, n - ctr, buf, buflen, q);
    }
}

void dilithium_signature::create_rand_product(
    ctx_dilithium& ctx, uint8_t *seed, uint32_t q, uint32_t q_bits, uint32_t *t, int32_t *y, size_t logn,
    size_t k, size_t l, uint32_t *c) const
{
    const size_t n = 1 << logn;

    uint32_t *block = reinterpret_cast<uint32_t*>(aligned_malloc(n * sizeof(uint32_t)));
    uint32_t *yu    = reinterpret_cast<uint32_t*>(aligned_malloc(l * n * sizeof(uint32_t)));

    for (size_t i=0; i < l*n; i++) {
        y[i] += q * (static_cast<uint32_t>(y[i]) >> 31);
    }

    LOG_DEBUG_ARRAY("CHECKME", y, l*n);

    ctx.get_reduction().convert_to(yu, reinterpret_cast<uint32_t*>(y), l*n);

    // Compute the NTT of the input to create_rand_product() as an initial step
    for (size_t i=0; i < l; i++) {
        ctx.get_ntt()->fwd(yu + i*n, logn);
    }

    // k x l matrix multiplication of n-element rings
    for (size_t i=0; i < k; i++) {
        uniform_random_ring_q(ctx.get_dilithium(), seed, (i << 8), reinterpret_cast<int32_t*>(c), n, q, q_bits);
        ctx.get_ntt()->mul(t + i*n, yu, c);

        for (size_t j=1; j < l; j++) {
            uniform_random_ring_q(ctx.get_dilithium(), seed, (i << 8) + j, reinterpret_cast<int32_t*>(c), n, q, q_bits);
            ctx.get_ntt()->mul(c, yu + j*n, c);

            for (size_t k=0; k < n; k++) {
                t[i*n + k] = ctx.get_reduction().add(t[i*n + k], c[k]);
            }
        }
        ctx.get_ntt()->inv(t + i*n, logn);
    }

    ctx.get_reduction().convert_from(t, t, k*n);

    aligned_free(block);
    aligned_free(yu);
}

bool dilithium_signature::keygen(std::unique_ptr<user_ctx>& ctx)
{
    ctx_dilithium& myctx = dynamic_cast<ctx_dilithium&>(*ctx.get());

    size_t   n        = myctx.get_dilithium()->get_params()->n;
    size_t   n_bits   = myctx.get_dilithium()->get_params()->n_bits;
    uint32_t q        = myctx.get_dilithium()->get_params()->q;
    uint32_t q_bits   = myctx.get_dilithium()->get_params()->q_bits;
    uint32_t eta      = myctx.get_dilithium()->get_params()->eta;
    uint32_t eta_bits = myctx.get_dilithium()->get_params()->eta_bits;
    uint32_t l        = myctx.get_dilithium()->get_params()->l;
    uint32_t k        = myctx.get_dilithium()->get_params()->k;
    uint32_t d        = myctx.get_dilithium()->get_params()->d;

    phantom_vector<uint32_t> c(n);
    phantom_vector<uint8_t>  rho_prime(64);

    // Generate rho and K, a 256 bit random byte array to be used to seed
    myctx.get_csprng()->get_mem(myctx.rho(), 32);
    myctx.get_csprng()->get_mem(rho_prime.data(), rho_prime.size());
    myctx.get_csprng()->get_mem(myctx.K(), 32);
    LOG_DEBUG_ARRAY("rho", myctx.rho(), 32);
    LOG_DEBUG_ARRAY("rho_prime", rho_prime.data(), rho_prime.size());
    LOG_DEBUG_ARRAY("K", myctx.K(), 32);

    // Generate s1 and s2 from a uniform random distribution with values of
    // -eta to +eta inclusive
    myctx.s1() = phantom_vector<int32_t>(l*n);
    myctx.s2() = phantom_vector<int32_t>(k*n);
    uniform_rand_sample_small(myctx.get_dilithium()->get_xof(), rho_prime, q, eta, eta_bits, myctx.s1().data(), n, l, 0);
    uniform_rand_sample_small(myctx.get_dilithium()->get_xof(), rho_prime, q, eta, eta_bits, myctx.s2().data(), n, k, l);
    myctx.t()  = phantom_vector<int32_t>(k*n);
    LOG_DEBUG_ARRAY("s1", myctx.s1().data(), myctx.s1().size());
    LOG_DEBUG_ARRAY("s2", myctx.s2().data(), myctx.s2().size());

    myctx.ntt_s1() = phantom_vector<uint32_t>(l*n);
    myctx.ntt_s2() = phantom_vector<uint32_t>(k*n);
    to_montgomery(myctx, myctx.ntt_s1().data(), myctx.s1().data(), q, l*n, 0);
    for (size_t i = 0; i < l; i++) {
        myctx.get_ntt()->fwd(myctx.ntt_s1().data() + i*n, n_bits);
    }
    to_montgomery(myctx, myctx.ntt_s2().data(), myctx.s2().data(), q, k*n, 0);
    for (size_t i = 0; i < k; i++) {
        myctx.get_ntt()->fwd(myctx.ntt_s2().data() + i*n, n_bits);
    }

    // Matrix multiplication of A and s1, where A is uniform random
    // sampled as a k x l matrix of ring polynomials with n coefficients.
    // The kxl A matrix is multiplied by the lx1 s1 matrix to form a kx1
    // matrix to which s2 is added.
    /*myctx.get_dilithium()->get_xof()->init(32);
    myctx.get_dilithium()->get_xof()->absorb(myctx.rho(), 32);
    myctx.get_dilithium()->get_xof()->final();*/
    create_rand_product(myctx, myctx.rho(), q, q_bits,
                        reinterpret_cast<uint32_t*>(myctx.t().data()), myctx.s1().data(), n_bits, k, l, c.data());
    core::poly<int32_t>::add(myctx.t().data(), k*n, myctx.t().data(), myctx.s2().data());
    core::poly<int32_t>::mod_unsigned(myctx.t().data(), k*n, q);
    LOG_DEBUG_ARRAY("t", (uint32_t*)myctx.t().data(), myctx.t().size());

    // Truncate and round the t ring polynomial by d bits and write to the public key.
    myctx.t1() = phantom_vector<int32_t>(k*n);
    myctx.get_dilithium()->pwr_2_round(myctx.t1().data(), myctx.t().data(), q, n, k, d);
    LOG_DEBUG_ARRAY("t1", myctx.t1().data(), myctx.t1().size());
    LOG_DEBUG_ARRAY("t0", myctx.t().data(), myctx.t().size());

    myctx.ntt_t0() = phantom_vector<uint32_t>(k*n);
    to_montgomery(myctx, myctx.ntt_t0().data(), myctx.t().data(), q, k*n, 0);
    for (size_t i = 0; i < k; i++) {
        myctx.get_ntt()->fwd(myctx.ntt_t0().data() + i*n, n_bits);
    }

    // Create tr (associated with the private key) for use in deterministic signature generation.
    // tr is formed from the 32 bytes of rho and the bit packed representation of t1.
    myctx.get_dilithium()->collision_resistant_hash_t1(myctx.rho(), myctx.t1().data(), n, k, q_bits - d, myctx.tr());
    LOG_DEBUG_ARRAY("tr", myctx.tr(), 32);

    // Convert t1 to Montgomery representation for use in verification
    myctx.ntt_t1() = phantom_vector<uint32_t>(k*n);
    for (size_t i = 0; i < k*n; i++) {
        myctx.ntt_t1()[i]   = myctx.t1()[i];
        myctx.ntt_t1()[i] <<= d;
        myctx.ntt_t1()[i]  -= q & (static_cast<int32_t>(q - myctx.ntt_t1()[i]) >> 31);
    }
    myctx.get_reduction().convert_to(myctx.ntt_t1().data(), myctx.ntt_t1().data(), k*n);
    for (size_t i = 0; i < k; i++) {
        myctx.get_ntt()->fwd(myctx.ntt_t1().data() + i*n, n_bits);
    }

    return true;
}

bool dilithium_signature::set_public_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& key)
{
    ctx_dilithium& myctx = dynamic_cast<ctx_dilithium&>(*ctx.get());

    size_t   n      = myctx.get_dilithium()->get_params()->n;
    size_t   k      = myctx.get_dilithium()->get_params()->k;
    uint32_t d      = myctx.get_dilithium()->get_params()->d;
    uint32_t q_bits = myctx.get_dilithium()->get_params()->q_bits;

    myctx.t1().clear();
    myctx.t1().resize(k*n);

    packing::unpacker up(key);
    for (size_t i = 0; i < 32; i++) {
        myctx.rho()[i] = up.read_unsigned(8, packing::RAW);
    }
    for (size_t i = k*n; i--;) {
        myctx.t1().push_back(up.read_unsigned(q_bits - d, packing::RAW));
    }

    return true;
}

bool dilithium_signature::get_public_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& key)
{
    ctx_dilithium& myctx = dynamic_cast<ctx_dilithium&>(*ctx.get());

    size_t   n      = myctx.get_dilithium()->get_params()->n;
    size_t   k      = myctx.get_dilithium()->get_params()->k;
    uint32_t d      = myctx.get_dilithium()->get_params()->d;
    uint32_t q_bits = myctx.get_dilithium()->get_params()->q_bits;

    key.clear();

    packing::packer pack((q_bits - d) * k * n + 32 * 8);
    for (size_t i=0; i < 32; i++) {
        pack.write_unsigned(myctx.rho()[i], 8, packing::RAW);
    }
    for (size_t i=0; i < k*n; i++) {
        pack.write_unsigned(myctx.t1()[i], q_bits - d, packing::RAW);
    }

    key = pack.get();

    return true;
}

bool dilithium_signature::set_private_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& key)
{
    ctx_dilithium& myctx = dynamic_cast<ctx_dilithium&>(*ctx.get());

    size_t   n        = myctx.get_dilithium()->get_params()->n;
    size_t   l        = myctx.get_dilithium()->get_params()->l;
    size_t   k        = myctx.get_dilithium()->get_params()->k;
    uint32_t q_bits   = myctx.get_dilithium()->get_params()->q_bits;
    uint32_t eta_bits = myctx.get_dilithium()->get_params()->eta_bits;

    myctx.s1().clear();
    myctx.s1().resize(l*n);
    myctx.s2().clear();
    myctx.s2().resize(k*n);
    myctx.t1().clear();
    myctx.t1().resize(k*n);

    packing::unpacker up(key);
    for (size_t i=0; i < 32; i++) {
        myctx.rho()[i] = up.read_unsigned(8, packing::RAW);
    }
    for (size_t i=0; i < 32; i++) {
        myctx.K()[i] = up.read_unsigned(8, packing::RAW);
    }
    for (size_t i=0; i < 32; i++) {
        myctx.tr()[i] = up.read_unsigned(8, packing::RAW);
    }
    for (size_t i=l*n; i--;) {
        myctx.s1().push_back(up.read_unsigned(eta_bits + 1, packing::RAW));
    }
    for (size_t i=k*n; i--;) {
        myctx.s2().push_back(up.read_unsigned(eta_bits + 1, packing::RAW));
    }
    for (size_t i=k*n; i--;) {
        myctx.t().push_back(up.read_unsigned(q_bits, packing::RAW));
    }

    return true;
}

bool dilithium_signature::get_private_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& key)
{
    ctx_dilithium& myctx = dynamic_cast<ctx_dilithium&>(*ctx.get());

    size_t   n        = myctx.get_dilithium()->get_params()->n;
    size_t   l        = myctx.get_dilithium()->get_params()->l;
    size_t   k        = myctx.get_dilithium()->get_params()->k;
    uint32_t q_bits   = myctx.get_dilithium()->get_params()->q_bits;
    uint32_t eta_bits = myctx.get_dilithium()->get_params()->eta_bits;

    key.clear();

    packing::packer pack(((eta_bits + 1) * (l + k) + q_bits * k) * n + (32 + 32 + 48) * 8);
    for (size_t i = 0; i < 32; i++) {
        pack.write_unsigned(myctx.rho()[i], 8, packing::RAW);
    }
    for (size_t i = 0; i < 32; i++) {
        pack.write_unsigned(myctx.K()[i], 8, packing::RAW);
    }
    for (size_t i = 0; i < 32; i++) {
        pack.write_unsigned(myctx.tr()[i], 8, packing::RAW);
    }
    for (size_t i = 0; i < l*n; i++) {
        pack.write_unsigned(myctx.s1()[i], eta_bits + 1, packing::RAW);
    }
    for (size_t i = 0; i < k*n; i++) {
        pack.write_unsigned(myctx.s2()[i], eta_bits + 1, packing::RAW);
    }
    for (size_t i = 0; i < k*n; i++) {
        pack.write_unsigned(myctx.t()[i], q_bits, packing::RAW);
    }

    key = pack.get();

    return true;
}

void dilithium_signature::to_montgomery(ctx_dilithium& ctx, uint32_t *out, const int32_t *in,
    uint32_t q, size_t n, size_t offset) const
{
    uint32_t temp;
    for (size_t j = 0; j < n; j++) {
        temp   = in[j + offset];
        temp  += q * (temp >> 31);
        out[j] = ctx.get_reduction().convert_to(temp);
    }
}

void dilithium_signature::from_montgomery(ctx_dilithium& ctx, int32_t *out, const uint32_t *in,
    uint32_t q, size_t n, size_t offset) const
{
    ctx.get_reduction().convert_from(reinterpret_cast<uint32_t*>(out) + offset, in, n);
}

uint32_t dilithium_signature::check_norm_inf(const int32_t *v, size_t n, size_t l, uint32_t q, uint32_t b) const
{
    uint32_t  lower_half = (q - 1) >> 1;
    uint32_t  upper_b    = q - b;
    const uint32_t *vu   = reinterpret_cast<const uint32_t*>(v);

    // Scan through the l matrices of length n
    volatile uint32_t retval = 0;
    for (size_t i = 0; i < l*n; i++) {
        uint32_t v_lte_q2 = (vu[i] - lower_half - 1) >> 31;
        uint32_t v_gte_b  = (b - vu[i] - 1) >> 31;
        uint32_t v_gte_ub = (vu[i] - upper_b - 1) >> 31;
        retval |= (v_lte_q2 & v_gte_b) | (~v_lte_q2 & v_gte_ub);
    }

    return retval;
}

bool dilithium_signature::sign(const std::unique_ptr<user_ctx>& ctx,
                               const phantom_vector<uint8_t>& m,
                               phantom_vector<uint8_t>& s)
{
    ctx_dilithium& myctx = dynamic_cast<ctx_dilithium&>(*ctx.get());
    dilithium *dil       = myctx.get_dilithium();

    size_t    n            = dil->get_params()->n;
    size_t    n_bits       = dil->get_params()->n_bits;
    size_t    q            = dil->get_params()->q;
    uint32_t  q_bits       = dil->get_params()->q_bits;
    uint32_t  z_bits       = dil->get_params()->z_bits;
    uint32_t  beta         = dil->get_params()->beta;
    uint32_t  omega        = dil->get_params()->omega;
    uint32_t  omega_bits   = dil->get_params()->omega_bits;
    uint32_t  gamma_1      = dil->get_params()->gamma_1;
    uint32_t  gamma_1_bits = dil->get_params()->gamma_1_bits;
    uint32_t  gamma_2      = dil->get_params()->gamma_2;
    size_t    l            = dil->get_params()->l;
    size_t    k            = dil->get_params()->k;
    uint32_t  kappa        = 0;

    phantom_vector<uint8_t> vec_mu(64);
    uint8_t  *mu           = vec_mu.data();
    phantom_vector<uint8_t> storage_u8(k * n);
    uint8_t  *w1_bytes     = storage_u8.data();

    phantom_vector<uint32_t> storage_u32((3 + 2*l + 7*k) * n);
    int32_t  *c            = reinterpret_cast<int32_t*>(storage_u32.data());
    int32_t  *y            = c + n;
    int32_t  *t0           = y + l*n;
    int32_t  *t1           = t0 + k*n;
    int32_t  *z            = t1 + k*n;
    int32_t  *wcs2         = z + l*n;
    int32_t  *ct0          = wcs2 + k*n;
    int32_t  *h            = ct0 + k*n;
    int32_t  *r1           = h + k*n;
    uint32_t *ntt_c        = reinterpret_cast<uint32_t*>(r1 + k*n);
    uint32_t *w            = ntt_c + n;
    uint32_t *ntt_temp     = w + k*n;

    dil->collision_resistant_hash_message(myctx.tr(), m, mu);
    LOG_DEBUG_ARRAY("mu", mu, 64);

    phantom_vector<uint8_t> rho_prime(64);
    if (myctx.is_deterministic()) {
        dil->collision_resistant_hash_message(myctx.K(), vec_mu, rho_prime.data());
    }
    else {
        myctx.get_csprng()->get_mem(rho_prime.data(), 64);
    }
    LOG_DEBUG_ARRAY("rho_prime", rho_prime.data(), 64);

restart:
    // Generate y from the deterministic ExpandMask() function
    dil->expand_mask(rho_prime.data(), kappa, gamma_1, gamma_1_bits, q, l, n, y, myctx.K());
    kappa += l;
    LOG_DEBUG_ARRAY("y", y, l*n);

    // w = Ay
    /*dil->get_xof()->init(16);
    dil->get_xof()->absorb(myctx.rho(), 32);
    dil->get_xof()->final();*/
    create_rand_product(myctx, myctx.rho(), q, q_bits, w, y, n_bits, k, l, (reinterpret_cast<uint32_t*>(c)));
    LOG_DEBUG_ARRAY("create_rand_product() rho", myctx.rho(), 32);
    LOG_DEBUG_ARRAY("create_rand_product() w = Ay", w, k*n);

    // Generate the high order representation of w
    dil->high_bits(w1_bytes, w, n, k);
    LOG_DEBUG_ARRAY("w1", w1_bytes, k*n);

    // Calculate H(mu, w1) and use it to create sparse polynomial c with weight_of_c
    // coefficients and the values 1 or -1
    dil->h_function(c, mu, w1_bytes, n, k);
    LOG_DEBUG_ARRAY("c", c, n);
    to_montgomery(myctx, ntt_c, c, q, n, 0);
    myctx.get_ntt()->fwd(ntt_c, n_bits);

    // Calculate cs1
    for (size_t i=0; i < l; i++) {
        myctx.get_ntt()->mul(reinterpret_cast<uint32_t*>(z + n*i), myctx.ntt_s1().data() + i*n, ntt_c);
        myctx.get_ntt()->inv(reinterpret_cast<uint32_t*>(z + n*i), n_bits);
        from_montgomery(myctx, z, reinterpret_cast<const uint32_t*>(z) + n*i, q, n, n*i);
    }
    LOG_DEBUG_ARRAY("cs1", z, l*n);

    //Compute z = y + cs1
    core::poly<int32_t>::add(z, l*n, z, y);
    for (size_t i=0; i < l*n; i++) {
        z[i] -= q & (static_cast<int32_t>(q - z[i]) >> 31);
    }
    LOG_DEBUG_ARRAY("z = y + cs1", z, l*n);

    // Check 1 - Verify that the norm of z = y + cs1 is less than gamma_1 - beta
    if (check_norm_inf(z, n, l, q, gamma_1 - beta)) {
        LOG_DEBUG("RESTART: || y + c * s1 || >= gamma_1 - beta");
        goto restart;
    }

    // Check 2 - Verify that the norm of LowOrderBits_q(w - c*s2, 2*gamma_2) is
    // less than gamma_2 - beta
    for (size_t i=0; i < k; i++) {
        myctx.get_ntt()->mul(ntt_temp, myctx.ntt_s2().data() + i*n, ntt_c);
        myctx.get_ntt()->inv(ntt_temp, n_bits);
        from_montgomery(myctx, wcs2, ntt_temp, q, n, n*i);
    }
    LOG_DEBUG_ARRAY("cs2", wcs2, k*n);
    core::poly<int32_t>::sub_mod(wcs2, k*n, reinterpret_cast<int32_t*>(w), wcs2, q);
    //core::poly<int32_t>::mod_unsigned(wcs2, k*n, q);
    LOG_DEBUG_ARRAY("w - cs2", wcs2, k*n);

    // (r1, r0) = Decompose(w - c*s2, 2* gamma2)
    dil->decompose_blocks(t1, r1, wcs2, n, k, q);
    LOG_DEBUG_ARRAY("decompose t1", t1, k*n);
    LOG_DEBUG_ARRAY("decompose t0", r1, k*n);
    core::poly<int32_t>::mod_unsigned(r1, k*n, q);

    if (check_norm_inf(r1, n, k, q, gamma_2 - beta)) {
        LOG_DEBUG("RESTART: || r0 || >= gamma_2 - beta");
        goto restart;
    }

    // Calculate ct0
    for (size_t i=0; i < k; i++) {
        myctx.get_ntt()->mul(ntt_temp, myctx.ntt_t0().data() + n*i, ntt_c);
        myctx.get_ntt()->inv(ntt_temp, n_bits);
        from_montgomery(myctx, ct0, ntt_temp, q, n, n*i);
    }
    core::poly<int32_t>::mod_unsigned(ct0, k*n, q);
    LOG_DEBUG_ARRAY("ct0", ct0, k*n);

    core::poly<int32_t>::centre(ct0, q, k*n);

    if (check_norm_inf(ct0, n, k, q, gamma_2)) {
        LOG_DEBUG("RESTART: || c*t0 || >= gamma_2");
        goto restart;
    }

    // Create the hint to be appended to the signature
    // Add ct0 to wcs2 and normalise, negate ct0
    core::poly<int32_t>::add_mod(r1, k*n, r1, ct0, q);
    /*for (size_t i = 0; i < k*n; i++) {
        r1[i] -= q & (static_cast<int32_t>(q - r1[i]) >> 31);
    }*/
    core::poly<int32_t>::centre(r1, q, k*n);
    /*for (size_t i = 0; i < k; i++) {
        myctx.get_ntt()->negate(reinterpret_cast<uint32_t*>(ct0 + i*n));
    }*/
    size_t num_ones = dil->make_hint(h, r1, w1_bytes, n, k);
    LOG_DEBUG_ARRAY("h", h, k*n);
    LOG_DEBUG("num_ones = " << num_ones);

    // If the number of asserted bits in h is greater than omega then restart
    if (num_ones > omega) {
        goto restart;
    }

    LOG_DEBUG_ARRAY("z", z, l*n);
    LOG_DEBUG_ARRAY("h", h, k*n);
    LOG_DEBUG_ARRAY("c", c, n);

    if (1) {
        LOG_DEBUG("Verification countermeasure");

        // Verify that the norm of z is less than or equal to gamma_1 - beta
        if (check_norm_inf(z, n, l, q, gamma_1 - beta)) {
            return false;
        }

        // Verify that the number of ones in the hint is <= omega
        if (dil->check_hint_ones(h, k, n) > omega) {
            return false;
        }

        // Create a XOF random oracle and generate the kx1 matrix w = A*z mod q
        phantom_vector<int32_t> temp(2 *n);
        /*dil->get_xof()->init(16);
        dil->get_xof()->absorb(myctx.rho(), 32);
        dil->get_xof()->final();*/
        create_rand_product(myctx, myctx.rho(), q, q_bits, w, z, n_bits, k, l, reinterpret_cast<uint32_t*>(temp.data()));
        LOG_DEBUG_ARRAY("create_rand_product() rho", myctx.rho(), 32);
        LOG_DEBUG_ARRAY("w = A*z mod q", w, k*n);

        // Calculate ct1 (NTT(t1) is pre-multiplied by 2^d)
        for (size_t i=0; i < k; i++) {
            myctx.get_ntt()->mul(ntt_temp, myctx.ntt_t1().data() + i*n, ntt_c);
            myctx.get_ntt()->inv(ntt_temp, n_bits);
            from_montgomery(myctx, t0, ntt_temp, q, n, n*i);
        }
        LOG_DEBUG_ARRAY("c * t1 * 2^d", t0, k*n);

        // A*z - c*t1.2^d mod q
        core::poly<int32_t>::sub_mod(t0, k*n, reinterpret_cast<int32_t*>(w), t0, q);
        //core::poly<int32_t>::mod_unsigned(t0, k*n, q);
        LOG_DEBUG_ARRAY("A*z - c*t1.2^d mod q", t0, k*n);

        // Use the signature hint to recreate w1 from A*z - c*t1.2^d
        dil->use_hint(w1_bytes, h, t0, n, k);
        LOG_DEBUG_ARRAY("verify w'", w1_bytes, k*n);

        // Calculate H(mu, w1) such that a sparse polynomial with 60
        // coefficients have the values 1 or -1
        dil->h_function(temp.data(), mu, w1_bytes, n, k);
        LOG_DEBUG_ARRAY("mu", mu, 64);
        LOG_DEBUG_ARRAY("H(mu, w')", temp.data(), n);
        LOG_DEBUG_ARRAY("c", c, n);
    }

    core::poly<int32_t>::centre(z, q, l*n);
    LOG_DEBUG_ARRAY("z", z, l*n);

    size_t h_bits      = 8 + ((k + 1) >> 1);
    size_t packer_bits = l*n*z_bits + omega_bits + num_ones*h_bits + 2*n;

    packing::packer pack(packer_bits);
    for (size_t i=0; i < l*n; i++) {
        pack.write_signed(z[i], z_bits, packing::RAW);
    }
    pack.write_unsigned(num_ones, omega_bits, packing::RAW);
    size_t h_idx = 0;
    while (num_ones) {
        if (h[h_idx]) {
            pack.write_unsigned(h_idx, h_bits, packing::RAW);
            num_ones--;
        }
        h_idx++;
    }
    for (size_t i=0; i < n; i++) {
        pack.write_unsigned(c[i], 2, packing::RAW);
    }

    pack.flush();
    s = pack.get();

    return true;
}

bool dilithium_signature::verify(const std::unique_ptr<user_ctx>& ctx,
                                 const phantom_vector<uint8_t>& m,
                                 const phantom_vector<uint8_t>& s)
{
    ctx_dilithium& myctx  = dynamic_cast<ctx_dilithium&>(*ctx.get());
    dilithium *dil        = myctx.get_dilithium();

    size_t   n            = dil->get_params()->n;
    size_t   n_bits       = dil->get_params()->n_bits;
    size_t   q            = dil->get_params()->q;
    uint32_t q_bits       = dil->get_params()->q_bits;
    uint32_t z_bits       = dil->get_params()->z_bits;
    uint32_t beta         = dil->get_params()->beta;
    uint32_t omega        = dil->get_params()->omega;
    uint32_t omega_bits   = dil->get_params()->omega_bits;
    uint32_t gamma_1      = dil->get_params()->gamma_1;
    size_t   l            = dil->get_params()->l;
    size_t   k            = dil->get_params()->k;
    size_t   d            = dil->get_params()->d;

    phantom_vector<uint8_t> storage_u8(64 + k * n);
    uint8_t*  mu          = storage_u8.data();
    uint8_t*  w1_bytes    = mu + 64;

    phantom_vector<uint32_t> storage_u32((5 + l + 3*k) * n);
    uint32_t* ntt_c    = reinterpret_cast<uint32_t*>(storage_u32.data());
    uint32_t* ntt_temp = ntt_c + n;
    int32_t*  z        = reinterpret_cast<int32_t*>(ntt_temp + n);
    int32_t*  h        = z + l*n;
    int32_t*  c        = h + k*n;
    int32_t*  t0       = c + n;
    int32_t*  w        = t0 + k*n;
    int32_t*  temp     = w + k*n;

    packing::unpacker unpack(s);
    for (size_t i = 0; i < l*n; i++) {
        z[i]  = unpack.read_signed(z_bits, packing::RAW);
        z[i] += q * (static_cast<uint32_t>(z[i]) >> 31);
    }
    size_t h_bits = 8 + ((k + 1) >> 1);
    size_t num_ones = unpack.read_unsigned(omega_bits, packing::RAW);
    std::fill(h, h + k * n, 0);
    for (size_t i = 0; i < num_ones; i++) {
        uint32_t tmp = unpack.read_unsigned(h_bits, packing::RAW);
        h[tmp] = 1;
    }
    for (size_t i = 0; i < n; i++) {
        uint32_t tmp = unpack.read_unsigned(2, packing::RAW);
        c[i] = (3 == tmp)? -1 : tmp;
    }

    LOG_DEBUG_ARRAY("z", z, l*n);
    LOG_DEBUG_ARRAY("h", h, k*n);
    LOG_DEBUG_ARRAY("c", c, n);

    // Verify that the norm of z is less than or equal to gamma_1 - beta
    if (check_norm_inf(z, n, l, q, gamma_1 - beta)) {
        LOG_ERROR("Norm of z is less than or equal to gamma_1 - beta");
        goto finish_error;
    }

    // Verify that the number of ones in the hint is <= omega
    if (dil->check_hint_ones(h, k, n) > omega) {
        LOG_ERROR("Number of ones in the hint is <= omega");
        goto finish_error;
    }

    // Create a XOF random oracle and generate the kx1 matrix w = A*z mod q
    /*dil->get_xof()->init(16);
    dil->get_xof()->absorb(myctx.rho(), 32);
    dil->get_xof()->final();*/
    create_rand_product(myctx, myctx.rho(), q, q_bits, reinterpret_cast<uint32_t*>(w),
        z, n_bits, k, l, reinterpret_cast<uint32_t*>(temp));

    // Convert c to Montgomery representation in the NTT domain
    to_montgomery(myctx, ntt_c, c, q, n, 0);
    myctx.get_ntt()->fwd(ntt_c, n_bits);

    // Compute c*t1.2^d mod q
    for (size_t i = 0; i < k; i++) {
        myctx.get_ntt()->mul(ntt_temp, myctx.ntt_t1().data() + i*n, ntt_c);
        myctx.get_ntt()->inv(ntt_temp, n_bits);
        from_montgomery(myctx, t0, ntt_temp, q, n, n*i);
    }

    // Compute A*z - c*t1.2^d mod q
    core::poly<int32_t>::sub_mod(t0, k*n, w, t0, q);
    LOG_DEBUG_ARRAY("A*z - c*t1.2^d mod q", t0, k*n);

    // Use the signature hint to recreate w (w') from A*z - c*t1.2^d
    dil->use_hint(w1_bytes, h, t0, n, k);
    LOG_DEBUG_ARRAY("verify w'", w1_bytes, k*n);

    // Compute μ
    LOG_DEBUG_ARRAY("rho", myctx.rho(), 32);
    dil->collision_resistant_hash_t1(myctx.rho(), myctx.t1().data(), n, k, q_bits - d, mu);
    dil->collision_resistant_hash_message(mu, m, mu);
    LOG_DEBUG_ARRAY("mu", mu, 64);

    // Calculate H(μ, w1) such that a sparse polynomial with 60
    // coefficients have the values 1 or -1
    dil->h_function(temp, mu, w1_bytes, n, k);
    LOG_DEBUG_ARRAY("H(mu, w')", temp, n);
    LOG_DEBUG_ARRAY("c", c, n);

    // Check the output of the H function against the received value
    // in the signature
    if (const_time<uint32_t>::cmp_array_not_equal(reinterpret_cast<uint32_t*>(temp), reinterpret_cast<uint32_t*>(c), n)) {
        LOG_ERROR("H(μ, w1) !=c");
        goto finish_error;
    }

    LOG_DEBUG("Verified");
    return true;

finish_error:

    return false;
}

size_t dilithium_signature::get_msg_len(const std::unique_ptr<user_ctx>& ctx) const
{
    ctx_dilithium& myctx = dynamic_cast<ctx_dilithium&>(*ctx.get());

    return myctx.get_dilithium()->get_params()->n;
}

}  // namespace schemes
}  // namespace phantom
