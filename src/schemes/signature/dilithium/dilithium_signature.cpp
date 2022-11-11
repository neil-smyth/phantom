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
        case SECURITY_STRENGTH_60:
        case SECURITY_STRENGTH_80:
        case SECURITY_STRENGTH_96:
        case SECURITY_STRENGTH_112: set = 0; break;

        case SECURITY_STRENGTH_128: set = 1; break;

        case SECURITY_STRENGTH_160:
        case SECURITY_STRENGTH_192: set = 2; break;

        case SECURITY_STRENGTH_224: set = 3; break;

        case SECURITY_STRENGTH_256: set = 4; break;

        default: {
            LOG_ERROR("Security strength is invalid", g_pkc_log_level);
            throw std::invalid_argument("Security strength is invalid");
        }
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
    return create_ctx(dilithium_signature::bits_2_set(bits), size_hint, masking);
}

std::unique_ptr<user_ctx> dilithium_signature::create_ctx(size_t set,
                                                          cpu_word_size_e size_hint,
                                                          bool masking) const
{
    std::stringstream ss;

    (void) size_hint;
    (void) masking;

    ctx_dilithium* ctx = new ctx_dilithium(set);
    if (ctx->get_set() > 9) {
        ss << "Parameter set " << ctx->get_set() << " is out of range";
        LOG_ERROR(ss.str(), g_pkc_log_level);
        throw std::invalid_argument(ss.str());
    }

    ss << "Dilithium Signature context created [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);
    return std::unique_ptr<user_ctx>(ctx);
}

// Uniform sampling of an mx1 matrix with coefficients of -eta to +eta
void dilithium_signature::uniform_rand_sample_small(dilithium *dil, const phantom_vector<uint8_t>& seed,
    int32_t eta, int32_t *s, size_t n, size_t m, uint16_t nonce) const
{
    auto xof = dil->get_xof();

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

        ctr = dil->reject_eta(s + i, n, eta, buf.data(), stream256_blockbytes * eta_nblocks);

        while (ctr < n) {
            xof->squeeze(buf.data(), stream256_blockbytes);
            ctr += dil->reject_eta(s + i + ctr, n - ctr, eta, buf.data(), stream256_blockbytes);
        }
    }
}

void dilithium_signature::uniform_random_ring_q(dilithium* dil,
                                                uint8_t *seed,
                                                uint16_t nonce,
                                                int32_t *a,
                                                size_t n,
                                                uint32_t q) const
{
    const size_t shake128_rate          = 168;
    const size_t stream128_blockbytes   = shake128_rate;
    const size_t poly_uniform_numblocks = ((768 + stream128_blockbytes - 1)/stream128_blockbytes);
    size_t i, ctr, off;
    size_t buflen = poly_uniform_numblocks * stream128_blockbytes;
    phantom_vector<uint8_t> buf(buflen + 2);
    uint8_t nonce_bytes[2] = { static_cast<uint8_t>(nonce & 0xFF),
                               static_cast<uint8_t>(nonce >> 8) };

    dil->get_xof()->init(16);
    dil->get_xof()->absorb(seed, 32);
    dil->get_xof()->absorb(nonce_bytes, 2);
    dil->get_xof()->squeeze(buf.data(), poly_uniform_numblocks * shake128_rate);

    ctr = dil->reject_uniform(a, n, buf.data(), buflen, q);

    while (ctr < n) {
        off = buflen % 3;
        for (i = 0; i < off; ++i) {
            buf[i] = buf[buflen - off + i];
        }

        dil->get_xof()->squeeze(buf.data() + off, shake128_rate);
        buflen = stream128_blockbytes + off;
        ctr += dil->reject_uniform(a + ctr, n - ctr, buf.data(), buflen, q);
    }
}

void dilithium_signature::create_rand_product(
    ctx_dilithium& ctx, uint8_t *seed, uint32_t q, uint32_t *t, int32_t *y, size_t logn,
    size_t k, size_t l, uint32_t *c) const
{
    const size_t n = 1 << logn;

    uint32_t *block = reinterpret_cast<uint32_t*>(aligned_malloc(n * sizeof(uint32_t)));
    uint32_t *yu    = reinterpret_cast<uint32_t*>(aligned_malloc(l * n * sizeof(uint32_t)));

    for (size_t i=0; i < l*n; i++) {
        y[i] += q * (static_cast<uint32_t>(y[i]) >> 31);
    }

    ctx.get_reduction().convert_to(yu, reinterpret_cast<uint32_t*>(y), l*n);

    // Compute the NTT of the input to create_rand_product() as an initial step
    for (size_t i=0; i < l; i++) {
        ctx.get_ntt()->fwd(yu + i*n, logn);
    }

    // k x l matrix multiplication of n-element rings
    for (size_t i=0; i < k; i++) {
        uniform_random_ring_q(ctx.get_dilithium(), seed, (i << 8), reinterpret_cast<int32_t*>(c), n, q);
        ctx.get_ntt()->mul(t + i*n, yu, c);

        for (size_t j=1; j < l; j++) {
            uniform_random_ring_q(ctx.get_dilithium(), seed, (i << 8) + j, reinterpret_cast<int32_t*>(c), n, q);
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

void dilithium_signature::create_A_product(
    ctx_dilithium& ctx, uint32_t *w, int32_t *A, int32_t *y, uint32_t q, size_t n, size_t n_bits,
    size_t k, size_t l, uint32_t *c) const
{
    uint32_t *yu    = reinterpret_cast<uint32_t*>(aligned_malloc(l * n * sizeof(uint32_t)));

    for (size_t i=0; i < l*n; i++) {
        y[i] += q * (static_cast<uint32_t>(y[i]) >> 31);
    }

    ctx.get_reduction().convert_to(yu, reinterpret_cast<uint32_t*>(y), l*n);

    // Compute the NTT of the input to create_rand_product() as an initial step
    for (size_t i=0; i < l; i++) {
        ctx.get_ntt()->fwd(yu + i*n, n_bits);
    }

    for (size_t i=0; i < k; i++) {
        ctx.get_ntt()->mul(w + i*n, yu, reinterpret_cast<uint32_t*>(A) + i*l*n);

        for (size_t j=1; j < l; j++) {
            ctx.get_ntt()->mul(reinterpret_cast<uint32_t*>(c), yu + j*n, reinterpret_cast<uint32_t*>(A) + (i*l + j)*n);

            for (size_t m=0; m < n; m++) {
                w[i*n + m] = ctx.get_reduction().add(w[i*n + m], c[m]);
            }
        }
        ctx.get_ntt()->inv(w + i*n, n_bits);
    }

    ctx.get_reduction().convert_from(w, w, k*n);

    aligned_free(yu);
}

void dilithium_signature::expand_A(
    ctx_dilithium& ctx, uint8_t *seed, uint32_t q, int32_t *A, size_t n,
    size_t k, size_t l) const
{
    // k x l matrix generation of n-element rings of uniform random samples
    for (size_t i=0; i < k; i++) {
        for (size_t j=0; j < l; j++) {
            uniform_random_ring_q(ctx.get_dilithium(), seed, (i << 8) + j, A + i*l*n + j*n, n, q);
        }
    }
}

bool dilithium_signature::keygen(std::unique_ptr<user_ctx>& ctx)
{
    std::stringstream ss;
    ss << "Dilithium Signature KeyGen [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_dilithium& myctx = dynamic_cast<ctx_dilithium&>(*ctx.get());

    size_t   n        = myctx.get_dilithium()->get_params()->n;
    size_t   n_bits   = myctx.get_dilithium()->get_params()->n_bits;
    uint32_t q        = myctx.get_dilithium()->get_params()->q;
    uint32_t q_bits   = myctx.get_dilithium()->get_params()->q_bits;
    uint32_t eta      = myctx.get_dilithium()->get_params()->eta;
    uint32_t l        = myctx.get_dilithium()->get_params()->l;
    uint32_t k        = myctx.get_dilithium()->get_params()->k;
    uint32_t d        = myctx.get_dilithium()->get_params()->d;

    phantom_vector<uint32_t> c(n);
    phantom_vector<uint8_t>  rho_prime(64);

    // Generate rho and K, a 256 bit random byte array to be used to seed
    myctx.get_csprng()->get_mem(myctx.rho(), 32);
    myctx.get_csprng()->get_mem(rho_prime.data(), rho_prime.size());
    myctx.get_csprng()->get_mem(myctx.K(), 32);
    LOG_DEBUG_ARRAY("rho", g_pkc_log_level, myctx.rho(), 32);
    LOG_DEBUG_ARRAY("rho_prime", g_pkc_log_level, rho_prime.data(), rho_prime.size());
    LOG_DEBUG_ARRAY("K", g_pkc_log_level, myctx.K(), 32);

    // Generate s1 and s2 from a uniform random distribution with values of
    // -eta to +eta inclusive
    myctx.s1() = phantom_vector<int32_t>(l*n);
    myctx.s2() = phantom_vector<int32_t>(k*n);
    uniform_rand_sample_small(myctx.get_dilithium(), rho_prime, eta, myctx.s1().data(), n, l, 0);
    uniform_rand_sample_small(myctx.get_dilithium(), rho_prime, eta, myctx.s2().data(), n, k, l);
    myctx.t()  = phantom_vector<int32_t>(k*n);
    LOG_DEBUG_ARRAY("s1", g_pkc_log_level, myctx.s1().data(), myctx.s1().size());
    LOG_DEBUG_ARRAY("s2", g_pkc_log_level, myctx.s2().data(), myctx.s2().size());

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
    create_rand_product(myctx, myctx.rho(), q,
                        reinterpret_cast<uint32_t*>(myctx.t().data()), myctx.s1().data(), n_bits, k, l, c.data());
    core::poly<int32_t>::add(myctx.t().data(), k*n, myctx.t().data(), myctx.s2().data());
    core::poly<int32_t>::mod_unsigned(myctx.t().data(), k*n, q);
    LOG_DEBUG_ARRAY("t", g_pkc_log_level, (uint32_t*)myctx.t().data(), myctx.t().size());

    // Truncate and round the t ring polynomial by d bits and write to the public key.
    myctx.t1() = phantom_vector<int32_t>(k*n);
    myctx.get_dilithium()->pwr_2_round(myctx.t1().data(), myctx.t().data(), n, k, d);
    LOG_DEBUG_ARRAY("t1", g_pkc_log_level, myctx.t1().data(), myctx.t1().size());
    LOG_DEBUG_ARRAY("t0", g_pkc_log_level, myctx.t().data(), myctx.t().size());

    myctx.ntt_t0() = phantom_vector<uint32_t>(k*n);
    to_montgomery(myctx, myctx.ntt_t0().data(), myctx.t().data(), q, k*n, 0);
    for (size_t i = 0; i < k; i++) {
        myctx.get_ntt()->fwd(myctx.ntt_t0().data() + i*n, n_bits);
    }

    // Create tr (associated with the private key) for use in deterministic signature generation.
    // tr is formed from the 32 bytes of rho and the bit packed representation of t1.
    myctx.get_dilithium()->collision_resistant_hash_t1(myctx.rho(), myctx.t1().data(), n, k, q_bits - d, myctx.tr());
    LOG_DEBUG_ARRAY("tr", g_pkc_log_level, myctx.tr(), 32);

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
    std::stringstream ss;
    ss << "Dilithium Signature set public key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

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
    std::stringstream ss;
    ss << "Dilithium Signature get public key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

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
    std::stringstream ss;
    ss << "Dilithium Signature set private key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

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
    std::stringstream ss;
    ss << "Dilithium Signature get private key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

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
    (void) q;
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
    std::stringstream ss;
    ss << "Dilithium Signature Sign [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_dilithium& myctx = dynamic_cast<ctx_dilithium&>(*ctx.get());
    dilithium *dil       = myctx.get_dilithium();

    size_t    n            = dil->get_params()->n;
    size_t    n_bits       = dil->get_params()->n_bits;
    size_t    q            = dil->get_params()->q;
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

    phantom_vector<uint32_t> storage_u32((3 + 2*l + 7*k + k*l) * n);
    int32_t  *c            = reinterpret_cast<int32_t*>(storage_u32.data());
    int32_t  *y            = c + n;
    int32_t  *A            = y + l*n;
    int32_t  *t0           = A + n*k*l;
    int32_t  *t1           = t0 + k*n;
    int32_t  *z            = t1 + k*n;
    int32_t  *wcs2         = z + l*n;
    int32_t  *ct0          = wcs2 + k*n;
    int32_t  *h            = ct0 + k*n;
    int32_t  *r0           = h + k*n;
    uint32_t *ntt_c        = reinterpret_cast<uint32_t*>(r0 + k*n);
    uint32_t *w            = ntt_c + n;
    uint32_t *ntt_temp     = w + k*n;

    dil->collision_resistant_hash_message(myctx.tr(), m, mu);
    LOG_DEBUG_ARRAY("mu", g_pkc_log_level, mu, 64);

    phantom_vector<uint8_t> rho_prime(64);
    if (myctx.is_deterministic()) {
        dil->collision_resistant_hash_message(myctx.K(), vec_mu, rho_prime.data());
    }
    else {
        myctx.get_csprng()->get_mem(rho_prime.data(), 64);
    }
    LOG_DEBUG_ARRAY("rho_prime", g_pkc_log_level, rho_prime.data(), 64);

    // Create the matrix A outside of the rejection loop
    expand_A(myctx, myctx.rho(), q, A, n, k, l);

restart:

    // Generate y using the deterministic ExpandMask(ρ′, κ) function
    dil->expand_mask(rho_prime.data(), kappa, gamma_1, gamma_1_bits, l, n, y);
    kappa += l;
    LOG_DEBUG_ARRAY("y", g_pkc_log_level, y, l*n);

    // w = Ay
    create_A_product(myctx, w, A, y, q, n, n_bits, k, l, (reinterpret_cast<uint32_t*>(c)));
    LOG_DEBUG_ARRAY("create_rand_product() w = Ay", g_pkc_log_level, w, k*n);

    // Generate the high order representation of w, i.e. HighOrderBits_q(w, 2*gamma_2)
    dil->high_bits(w1_bytes, w, n, k);
    LOG_DEBUG_ARRAY("w1", g_pkc_log_level, w1_bytes, k*n);

    // Calculate H(mu, w1) and use it to create sparse polynomial c with weight_of_c
    // coefficients and the values 1 or -1
    dil->h_function(c, mu, w1_bytes, n, k);
    LOG_DEBUG_ARRAY("c", g_pkc_log_level, c, n);

    // Convert c to the Montgomery and NTT domain
    to_montgomery(myctx, ntt_c, c, q, n, 0);
    myctx.get_ntt()->fwd(ntt_c, n_bits);

    // Calculate cs1 (s1 is maintained in Mont/NTT)
    for (size_t i=0; i < l; i++) {
        myctx.get_ntt()->mul(reinterpret_cast<uint32_t*>(z + n*i), myctx.ntt_s1().data() + i*n, ntt_c);
        myctx.get_ntt()->inv(reinterpret_cast<uint32_t*>(z + n*i), n_bits);
        from_montgomery(myctx, z, reinterpret_cast<const uint32_t*>(z) + n*i, q, n, n*i);
    }
    LOG_DEBUG_ARRAY("cs1", g_pkc_log_level, z, l*n);

    // Compute z = y + cs1
    core::poly<int32_t>::add_mod(z, l*n, z, y, q);
    LOG_DEBUG_ARRAY("z = y + cs1", g_pkc_log_level, z, l*n);

    // Check 1 - Verify that the norm of z = y + cs1 is less than gamma_1 - beta
    if (check_norm_inf(z, n, l, q, gamma_1 - beta)) {
        LOG_DEBUG("RESTART: || y + c * s1 || >= gamma_1 - beta", g_pkc_log_level);
        goto restart;
    }

    // Calculate cs2 (s2 is maintained in Mont/NTT)
    for (size_t i=0; i < k; i++) {
        myctx.get_ntt()->mul(ntt_temp, myctx.ntt_s2().data() + i*n, ntt_c);
        myctx.get_ntt()->inv(ntt_temp, n_bits);
        from_montgomery(myctx, wcs2, ntt_temp, q, n, n*i);
    }
    LOG_DEBUG_ARRAY("cs2", g_pkc_log_level, wcs2, k*n);

    // Calculate w - cs2
    core::poly<int32_t>::sub_mod(wcs2, k*n, reinterpret_cast<int32_t*>(w), wcs2, q);
    LOG_DEBUG_ARRAY("w - cs2", g_pkc_log_level, wcs2, k*n);

    // r0 = LowOrderBits_q(w - c*s2, 2* gamma2)
    dil->low_bits(r0, wcs2, n, k);
    core::poly<int32_t>::mod_unsigned(r0, k*n, q);
    LOG_DEBUG_ARRAY("LowBits(w - c*s2, 2* gamma2)", g_pkc_log_level, r0, k*n);

    // Check 2 - Verify that the norm of LowOrderBits_q(w - c*s2, 2*gamma_2) is
    // less than gamma_2 - beta
    if (check_norm_inf(r0, n, k, q, gamma_2 - beta)) {
        LOG_DEBUG("RESTART: || r0 || >= gamma_2 - beta", g_pkc_log_level);
        goto restart;
    }

    // Calculate ct0 (t0 is maintained in Mont/NTT)
    for (size_t i=0; i < k; i++) {
        myctx.get_ntt()->mul(ntt_temp, myctx.ntt_t0().data() + n*i, ntt_c);
        myctx.get_ntt()->inv(ntt_temp, n_bits);
        from_montgomery(myctx, ct0, ntt_temp, q, n, n*i);
    }
    core::poly<int32_t>::mod_unsigned(ct0, k*n, q);
    LOG_DEBUG_ARRAY("ct0", g_pkc_log_level, ct0, k*n);

    // Check 3 - Verify that the norm of c*t0 is less than gamma_2
    if (check_norm_inf(ct0, n, k, q, gamma_2)) {
        LOG_DEBUG("RESTART: || c*t0 || >= gamma_2", g_pkc_log_level);
        goto restart;
    }

    // Create the hint to be appended to the signature using w1 and the sum of
    // c*t0 and LowOrderBits_q(w - c*s2, 2*gamma_2)
    core::poly<int32_t>::add_mod(r0, k*n, r0, ct0, q);
    core::poly<int32_t>::centre(r0, q, k*n);
    size_t num_ones = dil->make_hint(h, r0, w1_bytes, n, k);
    LOG_DEBUG_ARRAY("h", g_pkc_log_level, h, k*n);
    LOG_DEBUG("num_ones = " << num_ones, g_pkc_log_level);

    // Check 4 - If the number of asserted bits in h is greater than omega then restart
    if (num_ones > omega) {
        LOG_DEBUG("RESTART: Hint contains too many ones", g_pkc_log_level);
        goto restart;
    }

    core::poly<int32_t>::centre(z, q, l*n);

    LOG_DEBUG_ARRAY("z", g_pkc_log_level, z, l*n);
    LOG_DEBUG_ARRAY("h", g_pkc_log_level, h, k*n);
    LOG_DEBUG_ARRAY("c", g_pkc_log_level, c, n);

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
    std::stringstream ss;
    ss << "Dilithium Signature Verify [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

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

    LOG_DEBUG_ARRAY("z", g_pkc_log_level, z, l*n);
    LOG_DEBUG_ARRAY("h", g_pkc_log_level, h, k*n);
    LOG_DEBUG_ARRAY("c", g_pkc_log_level, c, n);

    // Verify that the norm of z is less than or equal to gamma_1 - beta
    if (check_norm_inf(z, n, l, q, gamma_1 - beta)) {
        LOG_ERROR("Norm of z is less than or equal to gamma_1 - beta", g_pkc_log_level);
        goto finish_error;
    }

    // Verify that the number of ones in the hint is <= omega
    if (dil->check_hint_ones(h, k, n) > omega) {
        LOG_ERROR("Number of ones in the hint is <= omega", g_pkc_log_level);
        goto finish_error;
    }

    // Create a XOF random oracle and generate the kx1 matrix w = A*z mod q
    create_rand_product(myctx, myctx.rho(), q, reinterpret_cast<uint32_t*>(w),
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
    LOG_DEBUG_ARRAY("A*z - c*t1.2^d mod q", g_pkc_log_level, t0, k*n);

    // Use the signature hint to recreate w (w') from A*z - c*t1.2^d
    dil->use_hint(w1_bytes, h, t0, n, k);
    LOG_DEBUG_ARRAY("verify w'", g_pkc_log_level, w1_bytes, k*n);

    // Compute μ
    LOG_DEBUG_ARRAY("rho", g_pkc_log_level, myctx.rho(), 32);
    dil->collision_resistant_hash_t1(myctx.rho(), myctx.t1().data(), n, k, q_bits - d, mu);
    dil->collision_resistant_hash_message(mu, m, mu);
    LOG_DEBUG_ARRAY("mu", g_pkc_log_level, mu, 64);

    // Calculate H(μ, w1) such that a sparse polynomial with 60
    // coefficients have the values 1 or -1
    dil->h_function(temp, mu, w1_bytes, n, k);
    LOG_DEBUG_ARRAY("H(mu, w')", g_pkc_log_level, temp, n);
    LOG_DEBUG_ARRAY("c", g_pkc_log_level, c, n);

    // Check the output of the H function against the received value
    // in the signature
    if (const_time<uint32_t>::cmp_array_not_equal(reinterpret_cast<uint32_t*>(temp),
                                                  reinterpret_cast<uint32_t*>(c),
                                                  n)) {
        LOG_ERROR("H(μ, w1) !=c", g_pkc_log_level);
        goto finish_error;
    }

    LOG_DEBUG("Verified", g_pkc_log_level);
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
