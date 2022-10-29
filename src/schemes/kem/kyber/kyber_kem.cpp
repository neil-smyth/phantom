/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "schemes/kem/kyber/kyber_kem.hpp"

#include <algorithm>

#include "sampling/uniform_sampler.hpp"
#include "logging/logger.hpp"
#include "core/poly.hpp"
#include "packing/packer.hpp"
#include "packing/unpacker.hpp"
#include "packing/stream.hpp"
#include "crypto/xof_sha3.hpp"


namespace phantom {
namespace schemes {


kyber_kem::kyber_kem()
{
}

kyber_kem::~kyber_kem()
{
}

std::unique_ptr<user_ctx> kyber_kem::create_ctx(security_strength_e bits,
                                                cpu_word_size_e size_hint,
                                                bool masking) const
{
    return create_ctx(kyber_indcpa::bits_2_set(bits), size_hint, masking);
}

std::unique_ptr<user_ctx> kyber_kem::create_ctx(size_t set,
                                                cpu_word_size_e size_hint,
                                                bool masking) const
{
    std::stringstream ss;
    ctx_kyber* ctx = new ctx_kyber(set);
    if (ctx->get_set() > 2) {
        ss << "Parameter set " << ctx->get_set() << " is out of range";
        LOG_ERROR(ss.str(), g_pkc_log_level);
        throw std::invalid_argument(ss.str());
    }

    ss << "Kyber KEM context created [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);
    return std::unique_ptr<user_ctx>(ctx);
}

bool kyber_kem::keygen(std::unique_ptr<user_ctx>& ctx)
{
    std::stringstream ss;
    ss << "Kyber KEM KeyGen [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_kyber& myctx = dynamic_cast<ctx_kyber&>(*ctx.get());

    size_t   n       = kyber_indcpa::m_params[myctx.get_set()].n;
    size_t   k       = kyber_indcpa::m_params[myctx.get_set()].k;

    myctx.s()     = phantom_vector<int16_t>(k*n);
    myctx.t()     = phantom_vector<int16_t>(k*n);
    myctx.t_ntt() = phantom_vector<int16_t>(k*n);
    myctx.get_pke()->keygen(myctx.rho(), myctx.s().data(), myctx.t_ntt().data());

    myctx.get_pke()->get_prng()->get_mem(myctx.z(), 32);
    LOG_DEBUG_ARRAY("z", g_pkc_log_level, myctx.z(), 32);

    return true;
}

bool kyber_kem::set_public_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k)
{
    std::stringstream ss;
    ss << "Kyber KEM set public key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_kyber& myctx = dynamic_cast<ctx_kyber&>(*ctx.get());

    size_t   n       = kyber_indcpa::m_params[myctx.get_set()].n;
    uint16_t d_t     = kyber_indcpa::m_params[myctx.get_set()].d_t;
    size_t   k_param = kyber_indcpa::m_params[myctx.get_set()].k;

    myctx.t()     = phantom_vector<int16_t>(k_param*n);
    myctx.t_ntt() = phantom_vector<int16_t>(k_param*n);

    packing::unpacker up(k);
    for (size_t i = 0; i < k_param*n; i++) {
        myctx.t_ntt()[i] = up.read_signed(d_t, packing::RAW);
    }
    for (size_t i = 0; i < 32; i++) {
        myctx.rho()[i] = up.read_unsigned(8, packing::RAW);
    }

    return true;
}

bool kyber_kem::get_public_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k)
{
    std::stringstream ss;
    ss << "Kyber KEM get public key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_kyber& myctx = dynamic_cast<ctx_kyber&>(*ctx.get());

    size_t   n       = kyber_indcpa::m_params[myctx.get_set()].n;
    size_t   k_param = kyber_indcpa::m_params[myctx.get_set()].k;
    uint16_t d_t     = kyber_indcpa::m_params[myctx.get_set()].d_t;

    k.clear();

    packing::packer pack(d_t * k_param * n + 32 * 8);
    for (size_t i = 0; i < k_param*n; i++) {
        pack.write_signed(myctx.t_ntt()[i], d_t, packing::RAW);
    }
    for (size_t i = 0; i < 32; i++) {
        pack.write_unsigned(myctx.rho()[i], 8, packing::RAW);
    }

    pack.flush();
    k = pack.get();

    return true;
}

bool kyber_kem::set_private_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k)
{
    std::stringstream ss;
    ss << "Kyber KEM set set_private_key key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_kyber& myctx = dynamic_cast<ctx_kyber&>(*ctx.get());

    size_t   n         = kyber_indcpa::m_params[myctx.get_set()].n;
    uint16_t eta1_bits = kyber_indcpa::m_params[myctx.get_set()].eta1_bits;

    myctx.s() = phantom_vector<int16_t>(n);

    packing::unpacker up(k);
    for (size_t i = 0; i < n; i++) {
        myctx.s()[i] = up.read_signed(eta1_bits, packing::RAW);
    }

    return true;
}

bool kyber_kem::get_private_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k)
{
    std::stringstream ss;
    ss << "Kyber KEM get set_private_key key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_kyber& myctx = dynamic_cast<ctx_kyber&>(*ctx.get());

    size_t   n         = kyber_indcpa::m_params[myctx.get_set()].n;
    uint16_t eta1_bits = kyber_indcpa::m_params[myctx.get_set()].eta1_bits;

    k.clear();

    packing::packer pack(eta1_bits * n);
    for (size_t i = 0; i < n; i++) {
        pack.write_signed(myctx.s()[i], eta1_bits, packing::RAW);
    }

    pack.flush();
    k = pack.get();

    return true;
}

void kyber_kem::h_function(crypto::xof_sha3* xof, const uint8_t *K, const int16_t *u,
    const int16_t *v, const uint8_t *d, size_t n, size_t k, uint8_t *md)
{
    uint8_t *b = reinterpret_cast<uint8_t*>(aligned_malloc((k + 1)*n*2 + 32*2));
    uint8_t *p = b;

    // Add K to the hash
    std::copy(K, K + 32, p);
    p += 32;

    // Add u to the hash
    for (size_t i = 0; i < k*n; i++) {
#if PLATFORM_BYTE_ORDER == IS_BIG_ENDIAN
        *p++ = *u >> 8;
        *p++ = *u++ & 0xff;
#else
        *p++ = *u & 0xff;
        *p++ = *u++ >> 8;
#endif
    }

    // Add v to the hash
    for (size_t i = 0; i < n; i++) {
#if PLATFORM_BYTE_ORDER == IS_BIG_ENDIAN
        *p++ = *v >> 8;
        *p++ = *v++ & 0xff;
#else
        *p++ = *v & 0xff;
        *p++ = *v++ >> 8;
#endif
    }

    // Add d to the hash
    std::copy(d, d + 32, p);

    // Initialise the XOF function
    xof->init(16);

    // Update the XOF with the message bytes
    xof->absorb(b, (k + 1)*n*2 + 32*2);
    xof->final();

    // Create num_weight_bytes sign bits in an array of bytes
    xof->squeeze(md, 32);

    // Free intermediate memory
    aligned_free(b);
}

void kyber_kem::g_function(crypto::xof_sha3* xof, const uint8_t *rho, const int16_t *t,
    const uint8_t *m, size_t n, size_t k,
    uint8_t *K, uint8_t *r, uint8_t *d)
{
    uint8_t *b = reinterpret_cast<uint8_t*>(aligned_malloc(k*n*2 + 32 + 32));
    uint8_t *p = b;

    // Add rho to the hash
    std::copy(rho, rho + 32, p);
    p += 32;

    // Add t to the hash
    for (size_t i = 0; i < k*n; i++) {
#if PLATFORM_BYTE_ORDER == IS_BIG_ENDIAN
        *p++ = *t >> 8;
        *p++ = *t++ & 0xFF;
#else
        *p++ = *t & 0xFF;
        *p++ = *t++ >> 8;
#endif
    }

    // Add the message to the hash
    std::copy(m, m + 32, p);

    // Initialise the XOF function
    xof->init(16);

    // Update the XOF with the message bytes
    xof->absorb(b, k*n*2 + 32 + 32);
    xof->final();

    // Create num_weight_bytes sign bits in an array of bytes
    xof->squeeze(K, 32);
    xof->squeeze(r, 32);
    xof->squeeze(d, 32);

    // Free intermediate memory
    aligned_free(b);
}

bool kyber_kem::encapsulate(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& pk,
    phantom_vector<uint8_t>& c, phantom_vector<uint8_t>& key)
{
    std::stringstream ss;
    ss << "Kyber KEM Encapsulation [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_kyber& myctx = dynamic_cast<ctx_kyber&>(*ctx.get());

    size_t   n       = kyber_indcpa::m_params[myctx.get_set()].n;
    uint16_t du_bits = kyber_indcpa::m_params[myctx.get_set()].d_u + 1;
    uint16_t dv_bits = kyber_indcpa::m_params[myctx.get_set()].d_v + 1;
    size_t   k       = kyber_indcpa::m_params[myctx.get_set()].k;

    set_public_key(ctx, pk);

    // Generate the 256-bit random value to be encapsulated
    key = phantom_vector<uint8_t>(32);
    phantom_vector<uint8_t> storage(4 * 32);
    uint8_t* Khat = storage.data();
    uint8_t* r = Khat + 32;
    uint8_t* d = r + 32;
    uint8_t* m = d + 32;
    uint8_t* K = key.data();
    myctx.get_pke()->get_prng()->get_mem(m, 32);
    LOG_DEBUG_ARRAY("z", g_pkc_log_level, m, 32);

    LOG_DEBUG_ARRAY("rho", g_pkc_log_level, myctx.rho(), 32);
    LOG_DEBUG_ARRAY("encapsulate NTT(t)", g_pkc_log_level, myctx.t_ntt().data(), k*n);
    LOG_DEBUG_ARRAY("KEM encapsulate m", g_pkc_log_level, m, 32);

    // Hash the public key with m to create (Khat,r,d)
    g_function(myctx.get_pke()->get_xof(), myctx.rho(), myctx.t_ntt().data(), m, n, k, Khat, r, d);
    LOG_DEBUG_ARRAY("Khat", g_pkc_log_level, Khat, 32);
    LOG_DEBUG_ARRAY("r", g_pkc_log_level, r, 32);
    LOG_DEBUG_ARRAY("d", g_pkc_log_level, d, 32);

    // Kyber CPA Encryption of the public key
    int16_t *u = reinterpret_cast<int16_t*>(aligned_malloc((k + 1) * n * sizeof(int16_t)));
    int16_t *v = u + k * n;
    myctx.get_pke()->enc(u, v, myctx.t_ntt().data(), myctx.rho(), r, k, m);
    LOG_DEBUG_ARRAY("u", g_pkc_log_level, u, k*n);
    LOG_DEBUG_ARRAY("v", g_pkc_log_level, v, n);
    LOG_DEBUG_ARRAY("d", g_pkc_log_level, d, 32);

    // K = H(Khat, c), where c = (u, v, d)
    h_function(myctx.get_pke()->get_xof(), Khat, u, v, d, n, k, K);
    LOG_DEBUG_ARRAY("K", g_pkc_log_level, K, 32);

    // Ciphertext
    packing::packer pack_c(k * n * du_bits + n * dv_bits + 32*8);
    for (size_t i = 0; i < k*n; i++) {
        pack_c.write_unsigned(u[i], du_bits, packing::RAW);
    }
    for (size_t i = 0; i < n; i++) {
        pack_c.write_unsigned(v[i], dv_bits, packing::RAW);
    }
    for (size_t i = 0; i < 32; i++) {
        pack_c.write_unsigned(d[i], 8, packing::RAW);
    }
    pack_c.flush();
    c = pack_c.get();

    // The key is directly output as the variable K

    aligned_free(u);

    return true;
}

bool kyber_kem::decapsulate(std::unique_ptr<user_ctx>& ctx,
                            const phantom_vector<uint8_t>& c,
                            phantom_vector<uint8_t>& key)
{
    std::stringstream ss;
    ss << "Kyber KEM Decapsulation [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_kyber& myctx = dynamic_cast<ctx_kyber&>(*ctx.get());

    size_t   n       = kyber_indcpa::m_params[myctx.get_set()].n;
    size_t   n_bits  = kyber_indcpa::m_params[myctx.get_set()].n_bits;
    size_t   du_bits = kyber_indcpa::m_params[myctx.get_set()].d_u + 1;
    size_t   dv_bits = kyber_indcpa::m_params[myctx.get_set()].d_v + 1;
    size_t   k       = kyber_indcpa::m_params[myctx.get_set()].k;

    key = phantom_vector<uint8_t>(32);
    uint8_t* K = key.data();

    phantom_vector<uint8_t> storage(64 + 32 + 32 + 32);
    uint8_t* d    = storage.data();
    uint8_t* Khat = d + 64;
    uint8_t* r    = Khat + 32;
    uint8_t* m    = r + 32;

    int16_t *u   = reinterpret_cast<int16_t*>(aligned_malloc(2 * (k + 1) * n * sizeof(int16_t)));
    int16_t *v   = u + k * n;
    int16_t *p16 = v + n;
    uint8_t *p8  = d + 32;

    // Consume the input ciphertext
    packing::unpacker unpack(c);
    for (size_t i = 0; i < k*n; i++) {
        u[i] = p16[i] = unpack.read_unsigned(du_bits, packing::RAW);
    }
    for (size_t i = 0; i < n; i++) {
        v[i] = p16[i + k*n] = unpack.read_unsigned(dv_bits, packing::RAW);
    }
    for (size_t i = 0; i < 32; i++) {
        d[i] = p8[i] = unpack.read_unsigned(n_bits, packing::RAW);
    }

    LOG_DEBUG_ARRAY("u", g_pkc_log_level, u, k*n);
    LOG_DEBUG_ARRAY("v", g_pkc_log_level, v, n);
    LOG_DEBUG_ARRAY("d", g_pkc_log_level, d, 32);

    // Generate the 256-bit random value to be encapsulated
    int16_t *s = myctx.s().data();
    LOG_DEBUG_ARRAY("decapsulate s", g_pkc_log_level, s, 32);
    myctx.get_pke()->dec(u, v, s, k, m);

    LOG_DEBUG_ARRAY("rho", g_pkc_log_level, myctx.rho(), 32);
    LOG_DEBUG_ARRAY("decapsulate NTT(t)", g_pkc_log_level, myctx.t_ntt().data(), k*n);
    LOG_DEBUG_ARRAY("KEM decapsulate m", g_pkc_log_level, m, 32);

    // Hash the public key and m and create a (K,r,d)
    g_function(myctx.get_pke()->get_xof(), myctx.rho(), myctx.t_ntt().data(), m, n, k, Khat, r, d);
    LOG_DEBUG_ARRAY("Khat", g_pkc_log_level, Khat, 32);
    LOG_DEBUG_ARRAY("r", g_pkc_log_level, r, 32);
    LOG_DEBUG_ARRAY("d", g_pkc_log_level, d, 32);

    // Kyber CPA Encryption of the public key
    myctx.get_pke()->enc(u, v, myctx.t_ntt().data(), myctx.rho(), r, k, m);
    LOG_DEBUG_ARRAY("u", g_pkc_log_level, u, k*n);
    LOG_DEBUG_ARRAY("v", g_pkc_log_level, v, n);

    LOG_DEBUG_ARRAY("Original u", g_pkc_log_level, p16, k*n);
    LOG_DEBUG_ARRAY("Original v", g_pkc_log_level, p16 + k*n, n);
    LOG_DEBUG_ARRAY("Original d", g_pkc_log_level, p8, 32);

    uint16_t cond = static_cast<uint16_t>(const_time<int16_t>::cmp_array_not_equal(u, p16, (k + 1) * n));
    cond |= static_cast<uint16_t>(const_time<uint8_t>::cmp_array_not_equal(d, p8, 32));
    if (cond) {
        LOG_DEBUG("Signature mismatch", g_pkc_log_level);
        h_function(myctx.get_pke()->get_xof(), myctx.z(), u, v, d, n, k, K);
        return false;
    }
    else {
        // K = H(K_bar, c), where c = (u, v, d)
        h_function(myctx.get_pke()->get_xof(), Khat, u, v, d, n, k, K);
        LOG_DEBUG_ARRAY("K", g_pkc_log_level, K, 32);
    }

    // The key is directly output as the variable K

    aligned_free(u);

    return true;
}

size_t kyber_kem::get_msg_len(const std::unique_ptr<user_ctx>& ctx) const
{
    ctx_kyber& myctx = dynamic_cast<ctx_kyber&>(*ctx.get());

    return kyber_indcpa::m_params[myctx.get_set()].n;
}

}  // namespace schemes
}  // namespace phantom
