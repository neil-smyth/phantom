/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "schemes/pke/saber/saber_pke.hpp"
#include "schemes/pke/saber/ctx_saber_pke.hpp"
#include "sampling/uniform_sampler.hpp"
#include "logging/logger.hpp"
#include "core/poly.hpp"
#include "packing/packer.hpp"
#include "packing/unpacker.hpp"
#include "packing/stream.hpp"
#include "crypto/xof_sha3.hpp"


namespace phantom {
namespace schemes {


saber_pke::saber_pke()
{
}

saber_pke::~saber_pke()
{
}

std::unique_ptr<user_ctx> saber_pke::create_ctx(security_strength_e bits,
                                                cpu_word_size_e size_hint,
                                                bool masking) const
{
    return create_ctx(saber_indcpa::bits_2_set(bits), size_hint, masking);
}

std::unique_ptr<user_ctx> saber_pke::create_ctx(size_t set,
                                                cpu_word_size_e size_hint,
                                                bool masking) const
{
    std::stringstream ss;

    (void) size_hint;
    (void) masking;

    ctx_saber_pke* ctx = new ctx_saber_pke(set);
    if (ctx->get_set() > 2) {
        ss << "Parameter set " << ctx->get_set() << " is out of range";
        LOG_ERROR(ss.str(), g_pkc_log_level);
        throw std::invalid_argument(ss.str());
    }

    ss << "SABER PKE context created [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);
    return std::unique_ptr<user_ctx>(ctx);
}

bool saber_pke::keygen(std::unique_ptr<user_ctx>& ctx)
{
    std::stringstream ss;
    ss << "SABER PKE KeyGen [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_saber_pke& myctx = dynamic_cast<ctx_saber_pke&>(*ctx.get());

    size_t l   = saber_indcpa::m_params[myctx.get_set()].l;
    size_t eq  = saber_indcpa::m_params[myctx.get_set()].eq;
    size_t ep  = saber_indcpa::m_params[myctx.get_set()].ep;

    myctx.pk() = phantom_vector<uint8_t>(l*ep*(SABER_N/8) + 32);
    myctx.sk() = phantom_vector<uint8_t>(l*eq*(SABER_N/8));
    myctx.pke()->keygen(myctx.pk(), myctx.sk());

    return true;
}

bool saber_pke::set_public_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k)
{
    std::stringstream ss;
    ss << "SABER PKE set public key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_saber_pke& myctx = dynamic_cast<ctx_saber_pke&>(*ctx.get());

    size_t l   = saber_indcpa::m_params[myctx.get_set()].l;
    size_t ep  = saber_indcpa::m_params[myctx.get_set()].ep;

    myctx.pk() = phantom_vector<uint8_t>(l*ep*(SABER_N/8) + 32);

    packing::unpacker up(k);
    for (size_t i = 0; i < l*ep*(SABER_N/8) + 32; i++) {
        myctx.pk()[i] = up.read_unsigned(8, packing::RAW);
    }

    return true;
}

bool saber_pke::get_public_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k)
{
    std::stringstream ss;
    ss << "SABER PKE get public key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_saber_pke& myctx = dynamic_cast<ctx_saber_pke&>(*ctx.get());

    size_t l   = saber_indcpa::m_params[myctx.get_set()].l;
    size_t ep  = saber_indcpa::m_params[myctx.get_set()].ep;

    k.clear();

    packing::packer pack((l*ep*(SABER_N/8) + 32) * 8);
    for (size_t i = 0; i < 32; i++) {
        pack.write_unsigned(myctx.pk()[i], 8, packing::RAW);
    }

    k = pack.get();

    return true;
}

bool saber_pke::set_private_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k)
{
    std::stringstream ss;
    ss << "SABER PKE set private key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_saber_pke& myctx = dynamic_cast<ctx_saber_pke&>(*ctx.get());

    size_t l   = saber_indcpa::m_params[myctx.get_set()].l;
    size_t eq  = saber_indcpa::m_params[myctx.get_set()].eq;

    myctx.sk() = phantom_vector<uint8_t>(l*eq*(SABER_N/8));

    packing::unpacker up(k);
    for (size_t i = 0; i < l*eq*(SABER_N/8); i++) {
        myctx.sk()[i] = up.read_unsigned(8, packing::RAW);
    }

    return true;
}

bool saber_pke::get_private_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k)
{
    std::stringstream ss;
    ss << "SABER PKE get private key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_saber_pke& myctx = dynamic_cast<ctx_saber_pke&>(*ctx.get());

    size_t l   = saber_indcpa::m_params[myctx.get_set()].l;
    size_t eq  = saber_indcpa::m_params[myctx.get_set()].eq;

    k.clear();

    packing::packer pack((l*eq*(SABER_N/8)) * 8);
    for (size_t i = 0; i < l*eq*(SABER_N/8); i++) {
        pack.write_unsigned(myctx.pk()[i], 8, packing::RAW);
    }

    k = pack.get();

    return true;
}

bool saber_pke::encrypt(const std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t> pt,
            phantom_vector<uint8_t>& ct)
{
    std::stringstream ss;
    ss << "SABER PKE Encrypt [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_saber_pke& myctx = dynamic_cast<ctx_saber_pke&>(*ctx.get());

    phantom_vector<uint8_t> seed(32);
    myctx.pke()->get_prng()->get_mem(seed.data(), 32);

    // saber CPA Encryption of the public key
    phantom_vector<uint8_t> ct_vec;
    phantom_vector<uint8_t> pt_vec(pt.size());
    for (size_t i=0; i < pt.size(); i++) {
        pt_vec[i] = pt[i];
    }
    myctx.pke()->enc(myctx.pk(), pt_vec, seed.data(), ct_vec);

    // Ciphertext
    packing::packer pack_ct(ct_vec.size() * 8);
    for (size_t i = 0; i < ct_vec.size(); i++) {
        pack_ct.write_unsigned(ct_vec[i], 8, packing::RAW);
    }
    pack_ct.flush();
    ct = pack_ct.get();

    return true;
}

bool saber_pke::decrypt(const std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t> ct,
            phantom_vector<uint8_t>& pt)
{
    std::stringstream ss;
    ss << "SABER PKE Decrypt [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_saber_pke& myctx = dynamic_cast<ctx_saber_pke&>(*ctx.get());

    // saber CPA Encryption of the public key
    phantom_vector<uint8_t> pt_vec(SABRE_MSG_LEN);
    phantom_vector<uint8_t> ct_vec(ct.size());
    for (size_t i=0; i < ct.size(); i++) {
        ct_vec[i] = ct[i];
    }
    myctx.pke()->dec(myctx.sk(), ct_vec, pt_vec.data());

    // Ciphertext
    packing::packer pack_pt(pt_vec.size()*8);
    for (size_t i = 0; i < pt_vec.size(); i++) {
        pack_pt.write_unsigned(pt_vec[i], 8, packing::RAW);
    }
    pack_pt.flush();
    pt = pack_pt.get();

    return true;
}

size_t saber_pke::get_msg_len(const std::unique_ptr<user_ctx>& ctx) const
{
    (void) ctx;
    return SABRE_MSG_LEN;
}

}  // namespace schemes
}  // namespace phantom
