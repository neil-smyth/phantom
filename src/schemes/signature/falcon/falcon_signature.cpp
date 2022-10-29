/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "schemes/signature/falcon/falcon_signature.hpp"
#include "schemes/signature/falcon/ctx_falcon.hpp"
#include "ntru/ntru_master_tree.hpp"
#include "ntru/ntru.hpp"
#include "logging/logger.hpp"
#include "core/const_time.hpp"
#include "core/poly.hpp"
#include "packing/packer.hpp"
#include "packing/unpacker.hpp"
#include "packing/stream.hpp"


namespace phantom {
namespace schemes {


const falcon_set_t ctx_falcon::m_params[2] = {
    {
        0, 12289, 12289 - 2, 14, 512, 9, 0x403001, 0x77402FFF, 4091, 10952
    },
    {
        1, 12289, 12289 - 2, 14, 1024, 10, 0x403001, 0x77402FFF, 4091, 10952
    }
};

size_t falcon_signature::bits_2_set(security_strength_e bits)
{
    // Select the most appropriate parameter set for the given security strength
    size_t set = 0;
    switch (bits)
    {
        case SECURITY_STRENGTH_60:
        case SECURITY_STRENGTH_80:
        case SECURITY_STRENGTH_96:
        case SECURITY_STRENGTH_112:
        case SECURITY_STRENGTH_128: set = 0; break;

        case SECURITY_STRENGTH_160: set = 1; break;

        default: throw std::invalid_argument("Security strength is invalid");
    }

    return set;
}

falcon_signature::falcon_signature()
{
}

falcon_signature::~falcon_signature()
{
}

std::unique_ptr<user_ctx> falcon_signature::create_ctx(security_strength_e bits,
                                                       cpu_word_size_e size_hint,
                                                       bool masking) const
{
    ctx_falcon* ctx = new ctx_falcon(falcon_signature::bits_2_set(bits));
    if (ctx->get_set() > 1) {
        throw std::invalid_argument("Parameter set is out of range");
    }
    return std::unique_ptr<user_ctx>(ctx);
}

std::unique_ptr<user_ctx> falcon_signature::create_ctx(size_t set,
                                                       cpu_word_size_e size_hint,
                                                       bool masking) const
{
    ctx_falcon* ctx = new ctx_falcon(set);
    if (ctx->get_set() > 1) {
        throw std::invalid_argument("Parameter set is out of range");
    }
    return std::unique_ptr<user_ctx>(ctx);
}

bool falcon_signature::keygen(std::unique_ptr<user_ctx>& ctx)
{
    ctx_falcon& myctx = dynamic_cast<ctx_falcon&>(*ctx.get());

    size_t   n    = ctx_falcon::m_params[myctx.get_set()].n;
    size_t   logn = ctx_falcon::m_params[myctx.get_set()].n_bits;
    uint32_t q    = ctx_falcon::m_params[myctx.get_set()].q;

    myctx.f()     = phantom_vector<int32_t>(n);
    myctx.g()     = phantom_vector<int32_t>(n);
    myctx.F()     = phantom_vector<int32_t>(n);
    myctx.G()     = phantom_vector<int32_t>(n);
    myctx.h()     = phantom_vector<int32_t>(n);
    myctx.h_ntt() = phantom_vector<uint32_t>(n);

    gen_keypair(ctx, myctx.f().data(), myctx.g().data(), myctx.F().data(), myctx.G().data(),
        myctx.h().data(), myctx.h_ntt().data());
    ntru::ntru_master_tree::create_master_tree(&myctx.master_tree(), q, logn,
        myctx.f().data(), myctx.g().data(), myctx.F().data(), myctx.G().data());

    return true;
}

void falcon_signature::set_logging(log_level_e logging)
{
}

const uint8_t max_fg_bits[] = {
    0, /* unused */
    8,
    8,
    8,
    8,
    8,
    7,
    7,
    6,
    6,
    5
};

int32_t falcon_signature::gen_keypair(std::unique_ptr<user_ctx>& ctx,
    int32_t* f, int32_t* g, int32_t* F, int32_t* G, int32_t* h, uint32_t* h_ntt)
{
    ctx_falcon& myctx = dynamic_cast<ctx_falcon&>(*ctx.get());

    uint32_t q    = ctx_falcon::m_params[myctx.get_set()].q;
    size_t   n    = ctx_falcon::m_params[myctx.get_set()].n;
    size_t   logn = ctx_falcon::m_params[myctx.get_set()].n_bits;

    int32_t retval = 0, num_retries = 0;

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

    int lim = 1 << (max_fg_bits[logn] - 1);
    for (size_t u = 0; u < n; u ++) {
        if (f[u] >= lim || f[u] <= -lim || g[u] >= lim || g[u] <= -lim) {
            lim = -1;
            break;
        }
    }
    if (lim < 0) {
        goto restart;
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

    /*fprintf(stderr, "f:\n");
    for (size_t i=0; i<(1 << logn); i++) {
        fprintf(stderr, "%d, ", f[i]);
        if (15 == (15&i)) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "g:\n");
    for (size_t i=0; i<(1 << logn); i++) {
        fprintf(stderr, "%d, ", g[i]);
        if (15 == (15&i)) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "F:\n");
    for (size_t i=0; i<(1 << logn); i++) {
        fprintf(stderr, "%d, ", F[i]);
        if (15 == (15&i)) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "G:\n");
    for (size_t i=0; i<(1 << logn); i++) {
        fprintf(stderr, "%d, ", G[i]);
        if (15 == (15&i)) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");*/

    // Compute the public key h = g/f mod q
    if (!problem.gen_public(h, h_ntt, f, g)) {
        num_retries++;
        goto restart;
    }

    retval = num_retries;

    return retval;
}

bool falcon_signature::set_public_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& key)
{
    ctx_falcon& myctx = dynamic_cast<ctx_falcon&>(*ctx.get());

    size_t   n      = ctx_falcon::m_params[myctx.get_set()].n;
    size_t   q_bits = ctx_falcon::m_params[myctx.get_set()].q_bits;
    size_t   logn   = ctx_falcon::m_params[myctx.get_set()].n_bits;

    myctx.h()     = phantom_vector<int32_t>(n);
    myctx.h_ntt() = phantom_vector<uint32_t>(n);

    int32_t*  h     = myctx.h().data();
    uint32_t* h_ntt = myctx.h_ntt().data();

    packing::unpacker up(key);
    for (size_t i = 0; i < n; i++) {
        h[i] = up.read_unsigned(q_bits, packing::RAW);
    }

    // Obtain NTT(f) and NTT(g)
    uint32_t* uh = reinterpret_cast<uint32_t*>(h);
    myctx.get_reduction().convert_to(h_ntt, uh, n);
    myctx.get_ntt()->fwd(h_ntt, logn);

    return true;
}

bool falcon_signature::get_public_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& key)
{
    ctx_falcon& myctx = dynamic_cast<ctx_falcon&>(*ctx.get());

    size_t   n      = ctx_falcon::m_params[myctx.get_set()].n;
    size_t   q_bits = ctx_falcon::m_params[myctx.get_set()].q_bits;
    int32_t* h      = myctx.h().data();

    key.clear();

    packing::packer pack(q_bits * n);
    for (size_t i = 0; i < n; i++) {
        pack.write_unsigned(h[i], q_bits, packing::RAW);
    }

    pack.flush();
    key = pack.get();

    return true;
}

bool falcon_signature::set_private_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& key)
{
    ctx_falcon& myctx = dynamic_cast<ctx_falcon&>(*ctx.get());

    size_t n = ctx_falcon::m_params[myctx.get_set()].n;
    double q = ctx_falcon::m_params[myctx.get_set()].q;
    uint32_t q_bits_1, q_bits_2;
    q_bits_1 = 6 * 1.17 * sqrt(q / static_cast<double>(2*n));
    q_bits_1 = 1 + core::bit_manipulation::log2_ceil(q_bits_1);
    q_bits_2 = 5 + q_bits_1;

    for (size_t i = n; i--;) {
        myctx.f()[i] = 0;
        myctx.g()[i] = 0;
        myctx.F()[i] = 0;
        myctx.G()[i] = 0;
    }

    myctx.f() = phantom_vector<int32_t>(n);
    myctx.g() = phantom_vector<int32_t>(n);
    myctx.F() = phantom_vector<int32_t>(n);
    myctx.G() = phantom_vector<int32_t>(n);

    packing::unpacker up(key);
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

bool falcon_signature::get_private_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& key)
{
    ctx_falcon& myctx = dynamic_cast<ctx_falcon&>(*ctx.get());

    size_t n = ctx_falcon::m_params[myctx.get_set()].n;
    double q = ctx_falcon::m_params[myctx.get_set()].q;
    uint32_t q_bits_1, q_bits_2;
    q_bits_1 = 6 * 1.17 * sqrt(q / static_cast<double>(2*n));
    q_bits_1 = 1 + core::bit_manipulation::log2_ceil(q_bits_1);
    q_bits_2 = 5 + q_bits_1;

    key.clear();

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

    pack.flush();
    key = pack.get();

    return true;
}

void falcon_signature::id_function(crypto::xof_sha3 *xof, const uint8_t *id, size_t id_len,
    size_t logn, uint32_t q, int32_t *c)
{
    const size_t   n      = 1 << logn;
    const uint32_t q_bits = core::bit_manipulation::log2_ceil(q);
    const uint32_t mask   = (1 << q_bits) - 1;
    uint8_t* c_u8 = reinterpret_cast<uint8_t*>(c);

    xof->init(16);
    xof->absorb(id, id_len);
    xof->final();
    xof->squeeze(c_u8, n * sizeof(int32_t));

    // Generate polynomial coefficients mod q from the CSPRNG
    for (size_t i = 0; i < n; i++) {
        c[i] &= mask;
        c[i] -= const_time<uint32_t>::if_lte(q, c[i], q);
    }
}

void falcon_signature::sign_h_function(crypto::xof_sha3 *xof, int32_t *a, const int32_t* x,
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

bool falcon_signature::sign(const std::unique_ptr<user_ctx>& ctx,
                            const phantom_vector<uint8_t>& m,
                            phantom_vector<uint8_t>& s)
{
    ctx_falcon& myctx = dynamic_cast<ctx_falcon&>(*ctx.get());

    uint32_t q      = ctx_falcon::m_params[myctx.get_set()].q;
    uint32_t q_bits = ctx_falcon::m_params[myctx.get_set()].q_bits;
    size_t   n      = ctx_falcon::m_params[myctx.get_set()].n;
    size_t   logn   = ctx_falcon::m_params[myctx.get_set()].n_bits;

    int32_t* tmp    = reinterpret_cast<int32_t*>(aligned_malloc(sizeof(int32_t) * 3 * n));
    int32_t* s1     = tmp;
    int32_t* s2     = s1 + n;
    int32_t* msg    = s2 + n;

    for (size_t i = 0; i < n; i++) {
        msg[i] = m[i];
    }

    const double* sk = myctx.master_tree().data();
    ntru::ntru_master_tree::gaussian_sample_with_tree(myctx.get_csprng(), sk, logn, q, msg, 0, s1, s2);

    core::poly<int32_t>::centre(s1, q, n);
    core::poly<int32_t>::centre(s2, q, n);

    packing::packer pack_enc(2 * n * q_bits);
    for (size_t i = 0; i < n; i++) {
        pack_enc.write_signed(s1[i], q_bits, packing::RAW);
    }
    for (size_t i = 0; i < n; i++) {
        pack_enc.write_signed(s2[i], q_bits, packing::RAW);
    }

    // Extracting buffer
    pack_enc.flush();
    s = pack_enc.get();

    aligned_free(tmp);

    return true;
}

bool falcon_signature::verify(const std::unique_ptr<user_ctx>& ctx,
                              const phantom_vector<uint8_t>& m,
                              const phantom_vector<uint8_t>& s)
{
    ctx_falcon& myctx = dynamic_cast<ctx_falcon&>(*ctx.get());

    uint32_t q      = ctx_falcon::m_params[myctx.get_set()].q;
    uint32_t q_bits = ctx_falcon::m_params[myctx.get_set()].q_bits;
    size_t   n      = ctx_falcon::m_params[myctx.get_set()].n;
    size_t   logn   = ctx_falcon::m_params[myctx.get_set()].n_bits;

    // Unpack the signature into z1, z2 and u
    phantom_vector<int32_t> s1(n), s2(n);

    packing::unpacker unpack(s);
    for (size_t i=0; i < n; i++) {
        s1[i] = unpack.read_signed(q_bits, packing::HUFFMAN);
    }
    for (size_t i=0; i < n; i++) {
        s2[i] = unpack.read_signed(q_bits, packing::HUFFMAN);
    }

    core::poly<int32_t>::mod_unsigned(s2.data(), n, q);
    uint32_t* us2 = reinterpret_cast<uint32_t*>(s2.data());
    myctx.get_reduction().convert_to(us2, us2, n);
    myctx.get_ntt()->fwd(us2, logn);
    myctx.get_ntt()->mul(us2, us2, myctx.h_ntt().data());
    myctx.get_ntt()->inv(us2, logn);
    myctx.get_reduction().convert_from(us2, us2, n);

    core::poly<int32_t>::sub_single(s1.data(), n, s2.data());
    core::poly<int32_t>::centre(s1.data(), q, n);

    return true;
}

size_t falcon_signature::get_msg_len(const std::unique_ptr<user_ctx>& ctx) const
{
    ctx_falcon& myctx = dynamic_cast<ctx_falcon&>(*ctx.get());

    return ctx_falcon::m_params[myctx.get_set()].n >> 4;
}

}  // namespace schemes
}  // namespace phantom
