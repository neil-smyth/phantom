/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "ibe/dlp/ibe_dlp.hpp"

#include <algorithm>

#include "ntru/ntru_master_tree.hpp"
#include "logging/logger.hpp"
#include "core/poly.hpp"
#include "packing/packer.hpp"
#include "packing/unpacker.hpp"
#include "packing/stream.hpp"
#include "sampling/gaussian_sampler.hpp"
#include "crypto/xof_sha3.hpp"
#include "fft/fft.hpp"
#include "fft/fft_poly.hpp"
#include "ntru/ldl.hpp"
#include "ntru/ntru.hpp"


namespace phantom {
namespace schemes {


const ibe_dlp_set_t ctx_ibe_dlp::m_params[2] = {
    {
        0, 9, 512, 0x403001, 0x77402FFF, 23, 18, 0x201800, 990, 0, 2121218, 427446
    },
    {
        1, 10, 1024, 0x403001, 0x77402FFF, 23, 17, 0x201800, 1332, 0, 2121218, 427446
    }
};


size_t ibe_dlp::bits_2_set(security_strength_e bits)
{
    // Select the most appropriate parameter set for the given security strength
    size_t set = 0;
    switch (bits)
    {
        case SECURITY_STRENGTH_60:
        case SECURITY_STRENGTH_80:  set = 0; break;

        case SECURITY_STRENGTH_96:
        case SECURITY_STRENGTH_112:
        case SECURITY_STRENGTH_128:
        case SECURITY_STRENGTH_160: set = 1; break;
        default: {
            LOG_ERROR("Security strength is invalid", g_pkc_log_level);
            throw std::invalid_argument("Security strength is invalid");
        }
    }

    return set;
}

ibe_dlp::ibe_dlp()
{
}

ibe_dlp::~ibe_dlp()
{
}

std::unique_ptr<user_ctx> ibe_dlp::create_ctx(security_strength_e bits,
                                              cpu_word_size_e size_hint,
                                              bool masking) const
{
    return create_ctx(ibe_dlp::bits_2_set(bits), size_hint, masking);
}

std::unique_ptr<user_ctx> ibe_dlp::create_ctx(size_t set,
                                              cpu_word_size_e size_hint,
                                              bool masking) const
{
    ctx_ibe_dlp* ctx = new ctx_ibe_dlp(set);
    std::stringstream ss;

    (void) size_hint;
    (void) masking;

    if (ctx->get_set() > 1) {
        ss << "Parameter set " << ctx->get_set() << " is out of range";
        LOG_ERROR(ss.str(), g_pkc_log_level);
        throw std::invalid_argument(ss.str());
    }

    ss << "IBE-DLP context created [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);
    return std::unique_ptr<user_ctx>(ctx);
}

bool ibe_dlp::keygen(std::unique_ptr<user_ctx>& ctx)
{
    std::stringstream ss;
    ss << "IBE-DLP KeyGen [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_ibe_dlp& myctx = dynamic_cast<ctx_ibe_dlp&>(*ctx.get());

    size_t   n    = ctx_ibe_dlp::m_params[myctx.get_set()].n;
    size_t   logn = ctx_ibe_dlp::m_params[myctx.get_set()].logn;
    uint32_t q    = ctx_ibe_dlp::m_params[myctx.get_set()].q;

    myctx.f()     = phantom_vector<int32_t>(n);
    myctx.g()     = phantom_vector<int32_t>(n);
    myctx.F()     = phantom_vector<int32_t>(n);
    myctx.G()     = phantom_vector<int32_t>(n);
    myctx.h()     = phantom_vector<int32_t>(n);
    myctx.h_ntt() = phantom_vector<uint32_t>(n);

    // Obtain f and g using Gaussian sampling and solve the NTRU equation to
    // obtain F and G
    ibe_dlp::gen_keypair(ctx, myctx.f().data(), myctx.g().data(), myctx.F().data(), myctx.G().data(),
        myctx.h().data(), myctx.h_ntt().data());

    // Create a master tree for use in Extract
    ntru::ntru_master_tree::create_master_tree(&myctx.master_tree(), q, logn,
        myctx.f().data(), myctx.g().data(), myctx.F().data(), myctx.G().data());

    return true;
}

int32_t ibe_dlp::gen_keypair(std::unique_ptr<user_ctx>& ctx,
    int32_t* f, int32_t* g, int32_t* F, int32_t* G, int32_t* h, uint32_t* h_ntt)
{
    ctx_ibe_dlp& myctx = dynamic_cast<ctx_ibe_dlp&>(*ctx.get());

    uint32_t q    = ctx_ibe_dlp::m_params[myctx.get_set()].q;
    size_t   n    = ctx_ibe_dlp::m_params[myctx.get_set()].n;
    size_t   logn = ctx_ibe_dlp::m_params[myctx.get_set()].logn;

    int32_t num_retries = 0;

    // Set standard deviation of Gaussian distribution
    double bd = 1.17 * sqrt(static_cast<double>(q));
    double thresh  = bd * bd;

    ntru::ntru problem(logn, q, &myctx.get_reduction(), myctx.get_ntt());

    // Obtain f and g using Gaussian sampling
restart:
    // If f and g are already provided as inputs as we are recreating F and G
    // then do not sample new distributions
    for (size_t i = 0; i < n; i++) {
        f[i] = myctx.get_gaussian()->get_signed_sample();
        g[i] = myctx.get_gaussian()->get_signed_sample();
    }

    // Calculate the GramSchmidt norm
    double gs_norm = ntru::ntru_master_tree::gram_schmidt_norm(f, g, q, logn, bd, thresh);
    if (std::isnan(gs_norm)) {
        num_retries++;
        goto restart;
    }

    // Check whether norm is small enough - if not, repeat
    if (gs_norm > thresh) {
        num_retries++;
        goto restart;
    }

    // Solve the NTRU equation to obtain F and G
    if (!problem.solve(f, g, F, G)) {
        num_retries++;
        goto restart;
    }

    // Compute the public key h = g/f mod q
    if (!problem.gen_public(h, h_ntt, f, g)) {
        num_retries++;
        goto restart;
    }

    return num_retries;
}

bool ibe_dlp::set_public_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k)
{
    std::stringstream ss;
    ss << "IBE-DLP set public key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_ibe_dlp& myctx = dynamic_cast<ctx_ibe_dlp&>(*ctx.get());

    size_t   n      = ctx_ibe_dlp::m_params[myctx.get_set()].n;
    size_t   q_bits = ctx_ibe_dlp::m_params[myctx.get_set()].q_bits;
    size_t   logn   = ctx_ibe_dlp::m_params[myctx.get_set()].logn;

    myctx.h()     = phantom_vector<int32_t>(n);
    myctx.h_ntt() = phantom_vector<uint32_t>(n);

    int32_t*  h     = myctx.h().data();
    uint32_t* h_ntt = myctx.h_ntt().data();

    // Read the packed public key from k into h
    packing::unpacker up(k);
    for (size_t i = 0; i < n; i++) {
        h[i] = up.read_unsigned(q_bits, packing::RAW);
    }

    // Obtain NTT(h)
    uint32_t* uh = reinterpret_cast<uint32_t*>(h);
    myctx.get_reduction().convert_to(h_ntt, uh, n);
    myctx.get_ntt()->fwd(h_ntt, logn);

    return true;
}

bool ibe_dlp::get_public_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k)
{
    std::stringstream ss;
    ss << "IBE-DLP set public key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_ibe_dlp& myctx = dynamic_cast<ctx_ibe_dlp&>(*ctx.get());

    size_t   n      = ctx_ibe_dlp::m_params[myctx.get_set()].n;
    size_t   q_bits = ctx_ibe_dlp::m_params[myctx.get_set()].q_bits;
    int32_t* h      = myctx.h().data();

    // Write the packed public key from h into the vector k
    packing::packer pack(q_bits * n);
    for (size_t i = 0; i < n; i++) {
        pack.write_unsigned(h[i], q_bits, packing::RAW);
    }
    k = pack.serialize();

    return true;
}

bool ibe_dlp::set_private_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k)
{
    std::stringstream ss;
    ss << "IBE-DLP set private key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_ibe_dlp& myctx = dynamic_cast<ctx_ibe_dlp&>(*ctx.get());

    size_t n = ctx_ibe_dlp::m_params[myctx.get_set()].n;
    double q = ctx_ibe_dlp::m_params[myctx.get_set()].q;
    uint32_t q_bits_1;
    uint32_t q_bits_2;
    q_bits_1 = 6 * 1.17 * sqrt(q / static_cast<double>(2*n));
    q_bits_1 = 1 + core::bit_manipulation::log2_ceil(q_bits_1);
    q_bits_2 = 5 + q_bits_1;

    // Initialize the private key vectors (f,g,F,G) with the appropriate depth
    myctx.f() = phantom_vector<int32_t>(n);
    myctx.g() = phantom_vector<int32_t>(n);
    myctx.F() = phantom_vector<int32_t>(n);
    myctx.G() = phantom_vector<int32_t>(n);

    // Read the packed private key from k into (f,g,F,G)
    packing::unpacker up(k);
    for (size_t i = n; i--;) {
        myctx.f()[i] = up.read_signed(q_bits_1, packing::RAW);
    }
    for (size_t i = n; i--;) {
        myctx.g()[i] = up.read_signed(q_bits_1, packing::RAW);
    }
    for (size_t i = n; i--;) {
        myctx.F()[i] = up.read_signed(q_bits_2, packing::RAW);
    }
    for (size_t i = n; i--;) {
        myctx.G()[i] = up.read_signed(q_bits_2, packing::RAW);
    }

    return true;
}

bool ibe_dlp::get_private_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k)
{
    std::stringstream ss;
    ss << "IBE-DLP get private key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_ibe_dlp& myctx = dynamic_cast<ctx_ibe_dlp&>(*ctx.get());

    size_t n = ctx_ibe_dlp::m_params[myctx.get_set()].n;
    double q = ctx_ibe_dlp::m_params[myctx.get_set()].q;
    uint32_t q_bits_1;
    uint32_t q_bits_2;
    q_bits_1 = 6 * 1.17 * sqrt(q / static_cast<double>(2*n));
    q_bits_1 = 1 + core::bit_manipulation::log2_ceil(q_bits_1);
    q_bits_2 = 5 + q_bits_1;

    // Write the packed private key from (f,g,F,G) into the vector k
    packing::packer pack(2 * (q_bits_1 + q_bits_2) * n);
    for (size_t i = 0; i < n; i++) {
        pack.write_signed(myctx.f()[i], q_bits_1, packing::RAW);
    }
    for (size_t i = 0; i < n; i++) {
        pack.write_signed(myctx.g()[i], q_bits_1, packing::RAW);
    }
    for (size_t i = 0; i < n; i++) {
        pack.write_signed(myctx.F()[i], q_bits_2, packing::RAW);
    }
    for (size_t i = 0; i < n; i++) {
        pack.write_signed(myctx.G()[i], q_bits_2, packing::RAW);
    }
    k = pack.serialize();

    return true;
}

size_t ibe_dlp::get_msg_len(const std::unique_ptr<user_ctx>& ctx) const
{
    ctx_ibe_dlp& myctx = dynamic_cast<ctx_ibe_dlp&>(*ctx.get());

    return ctx_ibe_dlp::m_params[myctx.get_set()].n >> 3;
}

void ibe_dlp::id_function(crypto::xof_sha3 *xof, const uint8_t *id, size_t id_len, size_t logn, uint32_t q, int32_t *c)
{
    const size_t   n      = 1 << logn;
    const uint32_t q_bits = core::bit_manipulation::log2_ceil(q);
    const uint32_t mask   = (1 << q_bits) - 1;
    uint8_t* c_u8 = reinterpret_cast<uint8_t*>(c);

    // Use a XOF to convert the identity into an n-element array of 32-bit words
    xof->init(16);
    xof->absorb(id, id_len);
    xof->final();
    xof->squeeze(c_u8, n * sizeof(int32_t));

    // Generate polynomial coefficients mod q from the XOF
    for (size_t i = 0; i < n; i++) {
        c[i] &= mask;
        c[i] -= const_time<uint32_t>::if_lte(q, c[i], q);
    }
}

bool ibe_dlp::load_user_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& id,
    const phantom_vector<uint8_t>& key)
{
    ctx_ibe_dlp& myctx = dynamic_cast<ctx_ibe_dlp&>(*ctx.get());

    uint32_t q      = ctx_ibe_dlp::m_params[myctx.get_set()].q;
    uint32_t q_bits = ctx_ibe_dlp::m_params[myctx.get_set()].q_bits;
    size_t   n      = ctx_ibe_dlp::m_params[myctx.get_set()].n;
    size_t   logn   = ctx_ibe_dlp::m_params[myctx.get_set()].logn;

    (void) id;

    // Read the packed user secret key into s2
    myctx.s2() = phantom_vector<int32_t>(n);
    packing::unpacker unpack(key);
    for (size_t i = 0; i < n; i++) {
        myctx.s2()[i] = unpack.read_signed(q_bits, packing::RAW);
    }

    // Precomputation of NTT(s2)
    myctx.s2_ntt() = phantom_vector<uint32_t>(myctx.s2().data(), myctx.s2().data() + n);
    for (size_t i = 0; i < n; i++) {
        myctx.s2_ntt()[i] += (myctx.s2_ntt()[i] >> 31) * q;
    }
    myctx.get_reduction().convert_to(myctx.s2_ntt().data(), myctx.s2_ntt().data(), n);
    myctx.get_ntt()->fwd(myctx.s2_ntt().data(), logn);

    return true;
}

bool ibe_dlp::extract(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& id,
    phantom_vector<uint8_t>& key)
{
    ctx_ibe_dlp& myctx = dynamic_cast<ctx_ibe_dlp&>(*ctx.get());

    uint32_t q      = ctx_ibe_dlp::m_params[myctx.get_set()].q;
    uint32_t q_bits = ctx_ibe_dlp::m_params[myctx.get_set()].q_bits;
    size_t   n      = ctx_ibe_dlp::m_params[myctx.get_set()].n;
    size_t   logn   = ctx_ibe_dlp::m_params[myctx.get_set()].logn;

    // Translate the identity into an n-element array of 32-bit integers
    phantom_vector<int32_t> c(n);
    id_function(myctx.get_xof(), id.data(), id.size(), logn, q, c.data());

    // Pre-compute NTT(c)
    uint32_t* uc = reinterpret_cast<uint32_t*>(c.data());
    myctx.get_ntt()->inv(uc, logn);
    myctx.get_reduction().convert_from(uc, uc, n);

    // Generate the secret key s2
    phantom_vector<int32_t> s2(n);
    const double *sk = myctx.master_tree().data();
    ntru::ntru_master_tree::gaussian_sample_with_tree(myctx.get_csprng(),
        sk, logn, q, c.data(), 0, nullptr, s2.data());

    // Write the packed user secret key from s2 into the n-element vector key
    packing::packer pack(n * q_bits);
    for (size_t i = 0; i < n; i++) {
        pack.write_signed(s2[i], q_bits, packing::RAW);
    }
    key = pack.serialize();

    return true;
}

void ibe_dlp::k_function(crypto::xof_sha3 *xof, uint8_t *k, size_t n)
{
    xof->init(16);
    xof->absorb(k, n);
    xof->final();
    xof->squeeze(k, n >> 3);
}

void ibe_dlp::uniform_random_ring_q(crypto::xof_sha3 *xof, std::shared_ptr<csprng> prng,
    int32_t *a, size_t n, uint32_t q, size_t q_bits)
{
    phantom_vector<uint8_t> seed(32);

    // Generate a 32 byte random seed
    prng->get_mem(seed.data(), 32);

    // Use the seed to initialize a XOF
    xof->init(16);
    xof->absorb(seed.data(), 32);
    xof->final();

    // Iteratively sample random 32-bit identity-derived words from the XOF
    // and assign to the output polynomial ring
    alignas(DEFAULT_MEM_ALIGNMENT) union {
        uint32_t u32;
        uint8_t  u8[4];
    } u;
    uint32_t mask = (1 << q_bits) - 1;
    size_t ctr = 0;
    while (ctr < n) {
        xof->squeeze(u.u8, sizeof(uint32_t));

        uint32_t v = u.u32 & mask;
        uint32_t lessthan = core::const_time_enabled<uint32_t>::cmp_lessthan(v, q);
        a[ctr] = core::const_time_enabled<uint32_t>::if_condition_is_true(lessthan, v) |
                 core::const_time_enabled<uint32_t>::if_condition_is_false(lessthan, a[ctr]);
        ctr += lessthan;
    }
}

void ibe_dlp::sign_h_function(crypto::xof_sha3 *xof, int32_t *a, const int32_t* x,
    const phantom_vector<uint8_t> m, size_t n)
{
    alignas(DEFAULT_MEM_ALIGNMENT) uint8_t block[64];

    xof->init(16);
    xof->absorb(reinterpret_cast<const uint8_t*>(x), 4*n);
    xof->absorb(m.data(), m.size());
    xof->final();

    size_t ctr = 0;
    size_t pos = 256;
    while (ctr < n) {
        if (256 == pos) {
            xof->squeeze(block, 64 * sizeof(uint8_t));
            pos = 0;
        }

        int32_t v = block[pos >> 2] & 0x3;
        block[pos >> 2] >>= 2;

        uint32_t select = (3 != v);
        a[ctr] = core::const_time_enabled<uint32_t>::if_condition_is_true(select, v - 1) |
                 core::const_time_enabled<uint32_t>::if_condition_is_false(select, a[ctr]);
        ctr += select;
        pos++;
    }
}

bool ibe_dlp::sign(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t> m, phantom_vector<uint8_t>& s)
{
    ctx_ibe_dlp& myctx = dynamic_cast<ctx_ibe_dlp&>(*ctx.get());

    uint32_t q      = ctx_ibe_dlp::m_params[myctx.get_set()].q;
    uint32_t q_bits = ctx_ibe_dlp::m_params[myctx.get_set()].q_bits;
    size_t   n      = ctx_ibe_dlp::m_params[myctx.get_set()].n;
    size_t   logn   = ctx_ibe_dlp::m_params[myctx.get_set()].logn;

    int32_t* tmp    = reinterpret_cast<int32_t*>(aligned_malloc(sizeof(int32_t) * 3 * n));
    int32_t* y1     = tmp;
    int32_t* y2     = y1 + n;
    int32_t* y3     = y2 + n;

    const uint32_t* h_ntt   = myctx.h_ntt().data();

    for (size_t i = 0; i < n; i++) {
        y1[i] = myctx.get_gaussian()->get_signed_sample();
        y2[i] = myctx.get_gaussian()->get_signed_sample();
        y3[i] = y2[i];
    }

    core::poly<int32_t>::mod_unsigned(y3, n, q);
    uint32_t* uy3 = reinterpret_cast<uint32_t*>(y3);
    myctx.get_reduction().convert_to(uy3, uy3, n);
    myctx.get_ntt()->fwd(uy3, logn);
    myctx.get_ntt()->mul(uy3, uy3, h_ntt);
    myctx.get_ntt()->inv(uy3, logn);
    myctx.get_reduction().convert_from(uy3, uy3, n);

    core::poly<int32_t>::add_single(y3, n, y1);
    core::poly<int32_t>::centre(y3, q, n);

    sign_h_function(myctx.get_xof(), y3, y3, m, n);

    int32_t *s1 = myctx.s1().data();
    int32_t *s2 = myctx.s2().data();

    for (size_t i = 0; i < n; i++) {
        y1[i] += y3[i] * s1[i];
        y2[i] += y3[i] * s2[i];
    }
    core::poly<int32_t>::centre(y1, q, n);
    core::poly<int32_t>::centre(y2, q, n);

    packing::packer pack_enc(2 * n * q_bits + 2 * n);
    for (size_t i = 0; i < n; i++) {
        pack_enc.write_signed(y1[i], q_bits, packing::RAW);
    }
    for (size_t i = 0; i < n; i++) {
        pack_enc.write_signed(y2[i], q_bits, packing::RAW);
    }
    for (size_t i = 0; i < n; i++) {
        pack_enc.write_signed(y3[i], 2, packing::RAW);
    }

    // Extracting buffer
    s = pack_enc.serialize();

    aligned_free(tmp);

    return true;
}

bool ibe_dlp::verify(std::unique_ptr<user_ctx>& ctx,
                     const phantom_vector<uint8_t>& id,
                     const phantom_vector<uint8_t> m,
                     const phantom_vector<uint8_t> s)
{
    ctx_ibe_dlp& myctx = dynamic_cast<ctx_ibe_dlp&>(*ctx.get());

    uint32_t q      = ctx_ibe_dlp::m_params[myctx.get_set()].q;
    uint32_t q_bits = ctx_ibe_dlp::m_params[myctx.get_set()].q_bits;
    size_t   n      = ctx_ibe_dlp::m_params[myctx.get_set()].n;
    size_t   logn   = ctx_ibe_dlp::m_params[myctx.get_set()].logn;

    // Unpack the signature into z1, z2 and u
    phantom_vector<int32_t> z1(n), z2(n), u(n);

    packing::unpacker unpack(s);
    for (size_t i=0; i < n; i++) {
        z1[i]  = unpack.read_signed(q_bits, packing::HUFFMAN);
    }
    for (size_t i=0; i < n; i++) {
        z2[i] = unpack.read_signed(q_bits, packing::HUFFMAN);
    }
    for (size_t i=0; i < n; i++) {
        u[i] = unpack.read_signed(2, packing::RAW);
    }

    core::poly<int32_t>::mod_unsigned(z2.data(), n, q);
    uint32_t* uz2 = reinterpret_cast<uint32_t*>(z2.data());
    myctx.get_reduction().convert_to(uz2, uz2, n);
    myctx.get_ntt()->fwd(uz2, logn);
    myctx.get_ntt()->mul(uz2, uz2, myctx.h_ntt().data());
    myctx.get_ntt()->inv(uz2, logn);
    myctx.get_reduction().convert_from(uz2, uz2, n);

    core::poly<int32_t>::add_single(z2.data(), n, z1.data());
    core::poly<int32_t>::centre(z2.data(), q, n);

    phantom_vector<int32_t> c(n);
    id_function(myctx.get_xof(), id.data(), id.size(), logn, q, c.data());
    uint32_t* uc = reinterpret_cast<uint32_t*>(c.data());
    myctx.get_ntt()->inv(uc, logn);
    myctx.get_reduction().convert_from(uc, uc, n);

    for (size_t i = 0; i < n; i++) {
        z2[i] += c[i] * u[i];
    }
    core::poly<int32_t>::centre(z2.data(), q, n);

    sign_h_function(myctx.get_xof(), z2.data(), z2.data(), m, n);

    // Compare the received and generated c polynomials
    if (const_time<int32_t>::cmp_array_not_equal(z2.data(), u.data(), n)) {
        std::stringstream ss;
        ss << "Signature mismatch [" << ctx->get_uuid() << "]";
        LOG_WARNING(ss.str(), g_pkc_log_level);
        return false;
    }

    return true;
}

bool ibe_dlp::encrypt(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& id,
    const phantom_vector<uint8_t>& from, phantom_vector<uint8_t>& to)
{
    ctx_ibe_dlp& myctx = dynamic_cast<ctx_ibe_dlp&>(*ctx.get());

    uint32_t q      = ctx_ibe_dlp::m_params[myctx.get_set()].q;
    uint32_t q_bits = ctx_ibe_dlp::m_params[myctx.get_set()].q_bits;
    size_t   n      = ctx_ibe_dlp::m_params[myctx.get_set()].n;
    size_t   logn   = ctx_ibe_dlp::m_params[myctx.get_set()].logn;
    uint32_t scale  = ctx_ibe_dlp::m_params[myctx.get_set()].scale;
    uint32_t l      = ctx_ibe_dlp::m_params[myctx.get_set()].l;
    size_t   flen   = from.size();


    if (flen != (n >> 3)) {
        return false;
    }

    // Obtain pointers to the public key (NTT domain version)
    const uint32_t* h_ntt   = myctx.h_ntt().data();

    // Obtain pointers to temporary storage variables
    int32_t* tmp      = reinterpret_cast<int32_t*>(aligned_malloc(sizeof(int32_t) * 7 * n));
    int32_t* e1       = tmp;
    int32_t* e2       = tmp +     n;
    int32_t* e3       = tmp + 2 * n;
    int32_t* enc_k    = tmp + 3 * n;
    int32_t* u        = tmp + 4 * n;
    int32_t* v        = tmp + 5 * n;
    int32_t* c        = tmp + 6 * n;
    uint8_t* k        = reinterpret_cast<uint8_t*>(aligned_malloc(sizeof(uint8_t) * n));

    // Translate the ID into a polynomial in the NTT domain using a random oracle
    id_function(myctx.get_xof(), id.data(), id.size(), logn, q, c);
    uint32_t* uc = reinterpret_cast<uint32_t*>(c);

    // Generate the random variable k and encode the key
    for (size_t i = 0; i < n; i += 32) {
        uint32_t rnd32 = myctx.get_csprng()->get<uint32_t>();
        for (size_t j = 0; j < 32; j++) {
            k[i+j] = rnd32 & 0x1;
            rnd32 >>= 1;

            enc_k[i+j] = k[i+j] * scale;
        }
    }

    // Obtain uniform random values (e1,e2,r) <= {-1,0,1}^N
    uint32_t select;
    for (size_t i = 0; i < n; i++) {
        int32_t rand_bits = myctx.get_csprng()->get_bits(6);

        e1[i] = rand_bits & 0x1;
        rand_bits >>= 1;

        select = rand_bits & 0x1;
        e1[i] = core::const_time_enabled<uint32_t>::if_condition_is_true(select, -e1[i]) |
                core::const_time_enabled<uint32_t>::if_condition_is_false(select, e1[i]);
        rand_bits >>= 1;

        e2[i] = rand_bits & 0x1;
        rand_bits >>= 1;

        select = rand_bits & 0x1;
        e2[i] = core::const_time_enabled<uint32_t>::if_condition_is_true(select, -e2[i]) |
                core::const_time_enabled<uint32_t>::if_condition_is_false(select, e2[i]);
        rand_bits >>= 1;

        e3[i] = rand_bits & 0x1;
        rand_bits >>= 1;

        select = rand_bits;
        e3[i] = core::const_time_enabled<uint32_t>::if_condition_is_true(select, -e3[i]) |
                core::const_time_enabled<uint32_t>::if_condition_is_false(select, e3[i]);
    }

    // NTT multiplications e3 * h and e3 * H(id)
    core::poly<int32_t>::mod_unsigned(e3, n, q);
    uint32_t* ue3 = reinterpret_cast<uint32_t*>(e3);
    uint32_t* uu  = reinterpret_cast<uint32_t*>(u);
    myctx.get_reduction().convert_to(ue3, ue3, n);
    myctx.get_ntt()->fwd(ue3, logn);
    myctx.get_ntt()->mul(uu, ue3, h_ntt);
    myctx.get_ntt()->inv(uu, logn);
    myctx.get_reduction().convert_from(uu, uu, n);

    uint32_t* uv = reinterpret_cast<uint32_t*>(v);
    myctx.get_ntt()->mul(uv, ue3, uc);
    myctx.get_ntt()->inv(uv, logn);
    myctx.get_reduction().convert_from(uv, uv, n);

    // u = e3 * h + e1
    core::poly<int32_t>::add_single(u, n, e1);
    core::poly<int32_t>::centre(u, q, n);

    // v = e3 * H(id) + e2 + enc_k
    core::poly<int32_t>::add_single(v, n, e2);
    core::poly<int32_t>::add_single(v, n, enc_k);
    core::poly<int32_t>::centre(v, q, n);

    // Bit compression of the v polynomial by truncating l bits
    for (size_t i = 0; i < n; i++) {
        v[i] >>= l;
    }

    // Generate the one-time-pad H'(k) using a random oracle
    k_function(myctx.get_xof(), k, n);

    // Packing of the ciphertext message (u,v,c)
    packing::packer pack_enc(n * (q_bits + q_bits - l) + flen * 8);
    for (size_t i = 0; i < n; i++) {
        pack_enc.write_signed(u[i], q_bits, packing::RAW);
    }
    for (size_t i = 0; i < n; i++) {
        pack_enc.write_signed(v[i], q_bits - l, packing::RAW);
    }
    for (size_t i = 0; i < flen; i++) {
        k[i] ^= from.data()[i];
        pack_enc.write_unsigned(k[i], 8, packing::RAW);
    }

    // Extracting buffer
    to = pack_enc.serialize();

    // Reset the temporary memory
    aligned_free(tmp);
    aligned_free(k);

    return true;
}

bool ibe_dlp::decrypt(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t> from, phantom_vector<uint8_t>& to)
{
    ctx_ibe_dlp& myctx = dynamic_cast<ctx_ibe_dlp&>(*ctx.get());

    // Assign values to commonly used variables
    uint32_t q      = ctx_ibe_dlp::m_params[myctx.get_set()].q;
    uint32_t q2     = q >> 1;
    uint32_t q4     = q >> 2;
    uint32_t q_bits = ctx_ibe_dlp::m_params[myctx.get_set()].q_bits;
    size_t   n      = ctx_ibe_dlp::m_params[myctx.get_set()].n;
    size_t   logn   = ctx_ibe_dlp::m_params[myctx.get_set()].logn;
    uint32_t l      = ctx_ibe_dlp::m_params[myctx.get_set()].l;
    size_t   flen   = n >> 3;

    // Obtain pointers to temporary storage variables
    int32_t* u = reinterpret_cast<int32_t*>(aligned_malloc(sizeof(int32_t) * 2 * n));
    int32_t* v = u + n;
    uint8_t* k = reinterpret_cast<uint8_t*>(aligned_malloc(sizeof(uint8_t) * 2 * n));

    // Decompress the ciphertext (u,v,c)
    packing::unpacker unpack(from);
    for (size_t i = 0; i < n; i++) {
        u[i] = unpack.read_signed(q_bits, packing::RAW);
    }
    for (size_t i = 0; i < n; i++) {
        v[i] = unpack.read_signed(q_bits - l, packing::RAW);
    }
    for (size_t i = 0; i < n; i++) {
        v[i] <<= l;
    }

    // Derive the key k from the input message u and v polynomials
    // t = (v - ⌊ u * s2 ⌉) mod q
    //   = e3*H(id) + e2 + K - (e3*h + e1) * s2
    //   = e3*s1 + e2 + K - e1*s2
    //    as v = e3 * H(id) + e2 + K
    //       u = e3 * h + e1
    //
    // The trapdoor:  s1 + h * s2 = H(id)
    //
    // Therefore t is approximately equal to K with additive noise e3*s1 + e2 - e1*s2.
    // If the noise polynomial has small coefficients wrt q then the message coordinates
    // where m=0 will be close to 0, but when m=1 they will be close to q/2.
    //
    // k = (t + q/4) >= q/2 AND (t + q/4) < q
    core::poly<int32_t>::mod_unsigned(u, n, q);
    uint32_t* uu = reinterpret_cast<uint32_t*>(u);
    myctx.get_reduction().convert_to(uu, uu, n);
    myctx.get_ntt()->fwd(uu, logn);
    myctx.get_ntt()->mul(uu, uu, myctx.s2_ntt().data());
    myctx.get_ntt()->inv(uu, logn);
    myctx.get_reduction().convert_from(uu, uu, n);
    core::poly<int32_t>::centre(u, q, n);

    core::poly<int32_t>::sub_single(v, n, u);
    core::poly<int32_t>::mod_unsigned(v, n, q);

    for (size_t i = 0; i < n; i++) {
        uint32_t v_rnd = v[i] + q4;
        k[i] = const_time<uint32_t>::if_gte(v_rnd, q2, 1) &
               const_time<uint32_t>::cmp_lessthan(v_rnd, q);
    }

    // Generate the one-time-pad H'(k) using a random oracle
    k_function(myctx.get_xof(), k, n);

    // Create the output byte stream as m = c ^ H'(k)
    packing::packer pack_dec(n);
    for (size_t i = 0; i < flen; i++) {
        uint32_t temp = unpack.read_unsigned(8, packing::RAW);
        temp ^= k[i];
        pack_dec.write_unsigned(temp, 8, packing::RAW);
    }

    // Extracting buffer
    to = pack_dec.serialize();

    // Reset the temporary memory
    aligned_free(u);
    aligned_free(k);

    return true;
}

}  // namespace schemes
}  // namespace phantom
