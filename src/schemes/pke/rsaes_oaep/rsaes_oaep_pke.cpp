/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                            *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "schemes/pke/rsaes_oaep/rsaes_oaep_pke.hpp"
#include "rsa/ctx_rsa.hpp"
#include "rsa/rsa_cryptosystem_oaep.hpp"
#include "sampling/uniform_sampler.hpp"
#include "logging/logger.hpp"
#include "core/poly.hpp"
#include "packing/packer.hpp"
#include "packing/unpacker.hpp"
#include "packing/stream.hpp"
#include "crypto/xof_sha3.hpp"


namespace phantom {
namespace schemes {

template<typename T>
using rsa_oaep = phantom::rsa::rsa_cryptosystem_oaep<T>;

const phantom::rsa::rsa_set_t rsaes_oaep_pke::m_params[5] = {
    {0,  HASH_SHA2_224, 1024,  "65537"},
    {1,  HASH_SHA2_224, 1536,  "65537"},
    {2,  HASH_SHA2_256, 2048,  "65537"},
    {3,  HASH_SHA2_256, 3072,  "65537"},
    {4,  HASH_SHA2_256, 4096,  "65537"},
    /*{4,  HASH_SHA2_256, 5120,  "65537"},
    {5,  HASH_SHA2_256, 6144,  "65537"},
    {6,  HASH_SHA2_256, 7168,  "65537"},
    {7,  HASH_SHA2_384, 8192,  "65537"},
    {8,  HASH_SHA2_384, 9216,  "65537"},
    {9,  HASH_SHA2_384, 10240, "65537"},
    {10, HASH_SHA2_384, 11264, "65537"},
    {11, HASH_SHA2_384, 12288, "65537"},
    {12, HASH_SHA2_384, 13312, "65537"},
    {13, HASH_SHA2_384, 14336, "65537"},
    {14, HASH_SHA2_512, 15360, "65537"},
    {15, HASH_SHA2_512, 16384, "65537"},*/
};

size_t rsaes_oaep_pke::bits_2_set(security_strength_e bits)
{
    // Select the most appropriate parameter set for the given security strength
    size_t set = 0;
    switch (bits)
    {
        case SECURITY_STRENGTH_60:
        case SECURITY_STRENGTH_80:  set = 0; break;
        case SECURITY_STRENGTH_96:  set = 1; break;

        case SECURITY_STRENGTH_112: set = 2; break;
        case SECURITY_STRENGTH_128: set = 3; break;

        case SECURITY_STRENGTH_160: set = 4; break;

        default: {
            LOG_ERROR("Security strength is invalid", g_pkc_log_level);
            throw std::invalid_argument("Security strength is invalid");
        }
    }

    return set;
}


rsaes_oaep_pke::rsaes_oaep_pke()
{
}

rsaes_oaep_pke::~rsaes_oaep_pke()
{
}

std::unique_ptr<user_ctx> rsaes_oaep_pke::create_ctx(security_strength_e bits,
                                                     cpu_word_size_e size_hint,
                                                     bool masking) const
{
    return create_ctx(bits_2_set(bits), size_hint, masking);
}

std::unique_ptr<user_ctx> rsaes_oaep_pke::create_ctx(size_t set,
                                                     cpu_word_size_e size_hint,
                                                     bool masking) const
{
    std::stringstream ss;

    // Obtain the hash from the parameter set
    hash_alg_e hash = static_cast<hash_alg_e>((set >> 8) & 0x1f);

    user_ctx* ctx;
    switch (size_hint)
    {
        case CPU_WORD_SIZE_16:
            ctx = new phantom::rsa::ctx_rsa_tmpl<uint16_t>(PKC_PKE_RSAES_OAEP, hash, 2,
                                                           set, &m_params[0], 16, masking);
            break;
        case CPU_WORD_SIZE_32:
            ctx = new phantom::rsa::ctx_rsa_tmpl<uint32_t>(PKC_PKE_RSAES_OAEP, hash, 2,
                                                           set, &m_params[0], 16, masking);
            break;
#if defined(IS_64BIT)
        case CPU_WORD_SIZE_64:
            ctx = new phantom::rsa::ctx_rsa_tmpl<uint64_t>(PKC_PKE_RSAES_OAEP, hash, 2,
                                                           set, &m_params[0], 16, masking);
            break;
#endif
        default: {
            ss << "size_hint " << set << " is out of range";  // NOLINT
            LOG_ERROR(ss.str(), g_pkc_log_level);
            throw std::invalid_argument(ss.str());
        }
    }

    if ((ctx->get_set() & 0xff) > 5) {
        ss << "Parameter set " << ctx->get_set() << " is out of range";
        LOG_ERROR(ss.str(), g_pkc_log_level);
        throw std::invalid_argument(ss.str());
    }

    ss << "RSAES OAEP PKE context created [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);
    return std::unique_ptr<user_ctx>(ctx);
}

bool rsaes_oaep_pke::keygen(std::unique_ptr<user_ctx>& ctx)
{
    std::stringstream ss;
    ss << "RSAES OAEP PKE KeyGen [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    phantom::rsa::ctx_rsa& myctx = dynamic_cast<phantom::rsa::ctx_rsa&>(*ctx.get());

    switch (myctx.get_wordsize())
    {
        case 16:
        {
            phantom::rsa::ctx_rsa_tmpl<uint16_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint16_t>&>(myctx);
            ctx.e() = core::mpz<uint16_t>("3", 10);
            return ctx.pke()->keygen(ctx);
        } break;
        case 32:
        {
            phantom::rsa::ctx_rsa_tmpl<uint32_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint32_t>&>(myctx);
            ctx.e() = core::mpz<uint32_t>("3", 10);
            return ctx.pke()->keygen(ctx);
        } break;
#if defined(IS_64BIT)
        case 64:
        {
            phantom::rsa::ctx_rsa_tmpl<uint64_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint64_t>&>(myctx);
            ctx.e() = core::mpz<uint64_t>("3", 10);
            return ctx.pke()->keygen(ctx);
        } break;
#endif
    }

    return false;
}

bool rsaes_oaep_pke::set_public_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k)
{
    std::stringstream ss;
    ss << "RSAES OAEP PKE set public key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    phantom::rsa::ctx_rsa& myctx = dynamic_cast<phantom::rsa::ctx_rsa&>(*ctx.get());

    switch (myctx.get_wordsize())
    {
        case 16:
        {
            phantom::rsa::ctx_rsa_tmpl<uint16_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint16_t>&>(myctx);
            ctx.pke()->set_public_key(ctx, k);
        } break;
        case 32:
        {
            phantom::rsa::ctx_rsa_tmpl<uint32_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint32_t>&>(myctx);
            ctx.pke()->set_public_key(ctx, k);
        } break;
#if defined(IS_64BIT)
        case 64:
        {
            phantom::rsa::ctx_rsa_tmpl<uint64_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint64_t>&>(myctx);
            ctx.pke()->set_public_key(ctx, k);
        } break;
#endif
    }

    return true;
}

bool rsaes_oaep_pke::get_public_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k)
{
    std::stringstream ss;
    ss << "RSAES OAEP PKE get public key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    phantom::rsa::ctx_rsa& myctx = dynamic_cast<phantom::rsa::ctx_rsa&>(*ctx.get());

    switch (myctx.get_wordsize())
    {
        case 16:
        {
            phantom::rsa::ctx_rsa_tmpl<uint16_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint16_t>&>(myctx);
            ctx.pke()->get_public_key(ctx, k);
        } break;
        case 32:
        {
            phantom::rsa::ctx_rsa_tmpl<uint32_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint32_t>&>(myctx);
            ctx.pke()->get_public_key(ctx, k);
        } break;
#if defined(IS_64BIT)
        case 64:
        {
            phantom::rsa::ctx_rsa_tmpl<uint64_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint64_t>&>(myctx);
            ctx.pke()->get_public_key(ctx, k);
        } break;
#endif
    }

    return true;
}

bool rsaes_oaep_pke::set_private_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k)
{
    std::stringstream ss;
    ss << "RSAES OAEP PKE set private key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    phantom::rsa::ctx_rsa& myctx = dynamic_cast<phantom::rsa::ctx_rsa&>(*ctx.get());

    switch (myctx.get_wordsize())
    {
        case 16:
        {
            phantom::rsa::ctx_rsa_tmpl<uint16_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint16_t>&>(myctx);
            ctx.pke()->set_private_key(ctx, k);
        } break;
        case 32:
        {
            phantom::rsa::ctx_rsa_tmpl<uint32_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint32_t>&>(myctx);
            ctx.pke()->set_private_key(ctx, k);
        } break;
#if defined(IS_64BIT)
        case 64:
        {
            phantom::rsa::ctx_rsa_tmpl<uint64_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint64_t>&>(myctx);
            ctx.pke()->set_private_key(ctx, k);
        } break;
#endif
    }

    return true;
}

bool rsaes_oaep_pke::get_private_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k)
{
    std::stringstream ss;
    ss << "RSAES OAEP PKE get private key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    phantom::rsa::ctx_rsa& myctx = dynamic_cast<phantom::rsa::ctx_rsa&>(*ctx.get());

    switch (myctx.get_wordsize())
    {
        case 16:
        {
            phantom::rsa::ctx_rsa_tmpl<uint16_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint16_t>&>(myctx);
            ctx.pke()->get_private_key(ctx, k);
        } break;
        case 32:
        {
            phantom::rsa::ctx_rsa_tmpl<uint32_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint32_t>&>(myctx);
            ctx.pke()->get_private_key(ctx, k);
        } break;
#if defined(IS_64BIT)
        case 64:
        {
            phantom::rsa::ctx_rsa_tmpl<uint64_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint64_t>&>(myctx);
            ctx.pke()->get_private_key(ctx, k);
        } break;
#endif
    }

    return true;
}

bool rsaes_oaep_pke::encrypt(const std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t> pt,
            phantom_vector<uint8_t>& ct)
{
    std::stringstream ss;
    ss << "RSAES OAEP PKE Encrypt [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    phantom::rsa::ctx_rsa& myctx = dynamic_cast<phantom::rsa::ctx_rsa&>(*ctx.get());

    switch (myctx.get_wordsize())
    {
        case 16:
        {
            phantom::rsa::ctx_rsa_tmpl<uint16_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint16_t>&>(myctx);
            return reinterpret_cast<rsa_oaep<uint16_t>*>(ctx.pke())->rsaes_oaep_encrypt(ctx, pt, ct);
        } break;
        case 32:
        {
            phantom::rsa::ctx_rsa_tmpl<uint32_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint32_t>&>(myctx);
            return reinterpret_cast<rsa_oaep<uint32_t>*>(ctx.pke())->rsaes_oaep_encrypt(ctx, pt, ct);
        } break;
#if defined(IS_64BIT)
        case 64:
        {
            phantom::rsa::ctx_rsa_tmpl<uint64_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint64_t>&>(myctx);
            return reinterpret_cast<rsa_oaep<uint64_t>*>(ctx.pke())->rsaes_oaep_encrypt(ctx, pt, ct);
        } break;
#endif
    }

    return false;
}

bool rsaes_oaep_pke::decrypt(const std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t> ct,
            phantom_vector<uint8_t>& pt)
{
    std::stringstream ss;
    ss << "RSAES OAEP PKE Decrypt [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    phantom::rsa::ctx_rsa& myctx = dynamic_cast<phantom::rsa::ctx_rsa&>(*ctx.get());

    switch (myctx.get_wordsize())
    {
        case 16:
        {
            phantom::rsa::ctx_rsa_tmpl<uint16_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint16_t>&>(myctx);
            return reinterpret_cast<rsa_oaep<uint16_t>*>(ctx.pke())->rsaes_oaep_decrypt(ctx, ct, pt);
        } break;
        case 32:
        {
            phantom::rsa::ctx_rsa_tmpl<uint32_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint32_t>&>(myctx);
            return reinterpret_cast<rsa_oaep<uint32_t>*>(ctx.pke())->rsaes_oaep_decrypt(ctx, ct, pt);
        } break;
#if defined(IS_64BIT)
        case 64:
        {
            phantom::rsa::ctx_rsa_tmpl<uint64_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint64_t>&>(myctx);
            return reinterpret_cast<rsa_oaep<uint64_t>*>(ctx.pke())->rsaes_oaep_decrypt(ctx, ct, pt);
        } break;
#endif
    }

    return false;
}

size_t rsaes_oaep_pke::get_msg_len(const std::unique_ptr<user_ctx>& ctx) const
{
    phantom::rsa::ctx_rsa& myctx = dynamic_cast<phantom::rsa::ctx_rsa&>(*ctx.get());

    return (rsaes_oaep_pke::m_params[myctx.get_set()].n_bits + 7) >> 3;
}

}  // namespace schemes
}  // namespace phantom
