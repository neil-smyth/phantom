/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "schemes/pke/kyber/kyber_pke.hpp"
#include "schemes/kem/kyber/kyber_indcpa.hpp"
#include "sampling/uniform_sampler.hpp"
#include "logging/logger.hpp"
#include "core/poly.hpp"
#include "packing/packer.hpp"
#include "packing/unpacker.hpp"
#include "packing/stream.hpp"
#include "crypto/xof_sha3.hpp"


namespace phantom {
namespace schemes {


kyber_pke::kyber_pke()
{
}

kyber_pke::~kyber_pke()
{
}

std::unique_ptr<user_ctx> kyber_pke::create_ctx(security_strength_e bits,
                                                cpu_word_size_e size_hint,
                                                bool masking) const
{
    ctx_kyber_pke* ctx = new ctx_kyber_pke(kyber_indcpa::bits_2_set(bits));
    if (ctx->get_set() > 2) {
        throw std::invalid_argument("Parameter set is out of range");
    }
    return std::unique_ptr<user_ctx>(ctx);
}

std::unique_ptr<user_ctx> kyber_pke::create_ctx(size_t set,
                                                cpu_word_size_e size_hint,
                                                bool masking) const
{
    ctx_kyber_pke* ctx = new ctx_kyber_pke(set);
    if (ctx->get_set() > 2) {
        throw std::invalid_argument("Parameter set is out of range");
    }
    return std::unique_ptr<user_ctx>(ctx);
}

void kyber_pke::set_logging(log_level_e logging)
{
}

bool kyber_pke::keygen(std::unique_ptr<user_ctx>& ctx)
{
    LOG_DEBUG("Kyber KeyGen\n");

    ctx_kyber_pke& myctx = dynamic_cast<ctx_kyber_pke&>(*ctx.get());

    size_t   n       = kyber_indcpa::m_params[myctx.get_set()].n;
    size_t   k       = kyber_indcpa::m_params[myctx.get_set()].k;

    myctx.s()     = phantom_vector<int16_t>(k*n);
    myctx.t()     = phantom_vector<int16_t>(k*n);
    myctx.t_ntt() = phantom_vector<int16_t>(k*n);
    myctx.pke()->keygen(myctx.rho(), myctx.s().data(), myctx.t_ntt().data());

    /*for (size_t i = 0; i < k*n; i++) {
        int16_t tmp = myctx.t()[i];
        tmp += q & (tmp >> 15);
        myctx.t_ntt()[i] = myctx.pke()->get_reduction().convert_to(tmp);
    }
    for (size_t i = 0; i < k; i++) {
        myctx.pke()->get_ntt()->fwd(myctx.t_ntt().data() + i*n, n_bits);
    }*/

    myctx.pke()->get_prng()->get_mem(myctx.z(), 32);
    LOG_DEBUG_ARRAY("z", myctx.z(), 32);

    return true;
}

bool kyber_pke::set_public_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k)
{
    ctx_kyber_pke& myctx = dynamic_cast<ctx_kyber_pke&>(*ctx.get());

    size_t   n       = kyber_indcpa::m_params[myctx.get_set()].n;
    size_t   k_param = kyber_indcpa::m_params[myctx.get_set()].k;
    uint16_t d_t     = kyber_indcpa::m_params[myctx.get_set()].d_t;

    myctx.t_ntt() = phantom_vector<int16_t>(k_param * n);

    packing::unpacker up(k);
    for (size_t i = 0; i < k_param * n; i++) {
        myctx.t_ntt()[i] = up.read_signed(d_t, packing::RAW);
    }
    for (size_t i = 0; i < 32; i++) {
        myctx.rho()[i] = up.read_unsigned(8, packing::RAW);
    }

    return true;
}

bool kyber_pke::get_public_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k)
{
    ctx_kyber_pke& myctx = dynamic_cast<ctx_kyber_pke&>(*ctx.get());

    size_t   n       = kyber_indcpa::m_params[myctx.get_set()].n;
    size_t   k_param = kyber_indcpa::m_params[myctx.get_set()].k;
    uint16_t d_t     = kyber_indcpa::m_params[myctx.get_set()].d_t;

    k.clear();

    packing::packer pack(d_t * k_param * n + 32 * 8);
    for (size_t i = 0; i < k_param * n; i++) {
        pack.write_signed(myctx.t_ntt()[i], d_t, packing::RAW);
    }
    for (size_t i = 0; i < 32; i++) {
        pack.write_unsigned(myctx.rho()[i], 8, packing::RAW);
    }

    pack.flush();
    k = pack.get();

    return true;
}

bool kyber_pke::set_private_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k)
{
    ctx_kyber_pke& myctx = dynamic_cast<ctx_kyber_pke&>(*ctx.get());

    size_t   n         = kyber_indcpa::m_params[myctx.get_set()].n;
    uint16_t eta1_bits = kyber_indcpa::m_params[myctx.get_set()].eta1_bits;

    myctx.s() = phantom_vector<int16_t>(n);

    packing::unpacker up(k);
    for (size_t i = 0; i < n; i++) {
        myctx.s()[i] = up.read_unsigned(eta1_bits, packing::RAW);
    }

    return true;
}

bool kyber_pke::get_private_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k)
{
    ctx_kyber_pke& myctx = dynamic_cast<ctx_kyber_pke&>(*ctx.get());

    size_t   n         = kyber_indcpa::m_params[myctx.get_set()].n;
    uint16_t eta1_bits = kyber_indcpa::m_params[myctx.get_set()].eta1_bits;

    k.clear();

    packing::packer pack(eta1_bits * n);
    for (size_t i = 0; i < n; i++) {
        pack.write_unsigned(myctx.s()[i], eta1_bits, packing::RAW);
    }

    k = pack.get();

    return true;
}

bool kyber_pke::encrypt(const std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t> pt,
            phantom_vector<uint8_t>& ct)
{
    LOG_DEBUG("Kyber PKE Encrypt\n");

    ctx_kyber_pke& myctx = dynamic_cast<ctx_kyber_pke&>(*ctx.get());

    const size_t   n       = kyber_indcpa::m_params[myctx.get_set()].n;
    const uint16_t du_bits = kyber_indcpa::m_params[myctx.get_set()].d_u + 1;
    const uint16_t dv_bits = kyber_indcpa::m_params[myctx.get_set()].d_v + 1;
    const size_t   k       = kyber_indcpa::m_params[myctx.get_set()].k;

    phantom_vector<uint8_t> coins(32);
    myctx.pke()->get_prng()->get_mem(coins.data(), 32);

    // Kyber CPA Encryption of the public key
    int16_t *u = reinterpret_cast<int16_t*>(aligned_malloc((k + 1) * n * sizeof(int16_t)));
    int16_t *v = u + k * n;
    myctx.pke()->enc(u, v, myctx.t_ntt().data(), myctx.rho(), coins.data(), k, pt.data());
    LOG_DEBUG_ARRAY("u", u, k*n);
    LOG_DEBUG_ARRAY("v", v, n);

    // Ciphertext
    packing::packer pack_ct(k * n * du_bits + n * dv_bits);
    for (size_t i = 0; i < k*n; i++) {
        pack_ct.write_unsigned(u[i], du_bits, packing::RAW);
    }
    for (size_t i = 0; i < n; i++) {
        pack_ct.write_unsigned(v[i], dv_bits, packing::RAW);
    }
    pack_ct.flush();
    ct = pack_ct.get();

    aligned_free(u);

    return true;
}

bool kyber_pke::decrypt(const std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t> ct,
            phantom_vector<uint8_t>& pt)
{
    LOG_DEBUG("Kyber PKE Decrypt\n");

    ctx_kyber_pke& myctx = dynamic_cast<ctx_kyber_pke&>(*ctx.get());

    const size_t n       = kyber_indcpa::m_params[myctx.get_set()].n;
    const size_t du_bits = kyber_indcpa::m_params[myctx.get_set()].d_u + 1;
    const size_t dv_bits = kyber_indcpa::m_params[myctx.get_set()].d_v + 1;
    const size_t k       = kyber_indcpa::m_params[myctx.get_set()].k;

    alignas(DEFAULT_MEM_ALIGNMENT) uint8_t m[32];

    int16_t *u   = reinterpret_cast<int16_t*>(aligned_malloc((k + 1) * n * sizeof(int16_t)));
    int16_t *v   = u + k * n;

    // Consume the input ciphertext
    packing::unpacker unpack(ct);
    for (size_t i = 0; i < k*n; i++) {
        u[i] = unpack.read_unsigned(du_bits, packing::RAW);
    }
    for (size_t i = 0; i < n; i++) {
        v[i] = unpack.read_unsigned(dv_bits, packing::RAW);
    }

    LOG_DEBUG_ARRAY("u", u, k*n);
    LOG_DEBUG_ARRAY("v", v, n);

    // Generate the 256-bit random value to be encapsulated
    int16_t *s = myctx.s().data();
    myctx.pke()->dec(u, v, s, k, m);
    LOG_DEBUG_ARRAY("m", m, 32);

    packing::packer pack_pt(32*8);
    for (size_t i = 0; i < 32; i++) {
        pack_pt.write_unsigned(m[i], 8, packing::RAW);
    }
    pack_pt.flush();
    pt = pack_pt.get();

    aligned_free(u);

    return true;
}

size_t kyber_pke::get_msg_len(const std::unique_ptr<user_ctx>& ctx) const
{
    ctx_kyber_pke& myctx = dynamic_cast<ctx_kyber_pke&>(*ctx.get());

    return kyber_indcpa::m_params[myctx.get_set()].n;
}

}  // namespace schemes
}  // namespace phantom
