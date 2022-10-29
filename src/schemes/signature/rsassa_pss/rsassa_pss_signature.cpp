/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                            *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "schemes/signature/rsassa_pss/rsassa_pss_signature.hpp"
#include "rsa/rsa_cryptosystem_rsassa_pss.hpp"
#include "logging/logger.hpp"
#include "packing/packer.hpp"
#include "packing/unpacker.hpp"
#include "packing/stream.hpp"


namespace phantom {
namespace schemes {

template <typename T>
using rsa_ssa_pss = phantom::rsa::rsa_cryptosystem_rsassa_pss<T>;

const phantom::rsa::rsa_set_t rsassa_pss_signature::m_params[5] = {
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

size_t rsassa_pss_signature::bits_2_set(security_strength_e bits)
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

        default: throw std::invalid_argument("Security strength is invalid");
    }

    return set;
}


rsassa_pss_signature::rsassa_pss_signature()
{
}

rsassa_pss_signature::~rsassa_pss_signature()
{
}

std::unique_ptr<user_ctx> rsassa_pss_signature::create_ctx(security_strength_e bits,
                                                           cpu_word_size_e size_hint,
                                                           bool masking) const
{
    size_t set = bits_2_set(bits);
    return create_ctx(set, size_hint, masking);
}

std::unique_ptr<user_ctx> rsassa_pss_signature::create_ctx(size_t set,
                                                           cpu_word_size_e size_hint,
                                                           bool masking) const
{
    // Obtain the hash from the parameter set
    hash_alg_e hash = static_cast<hash_alg_e>((set >> 8) & 0x1f);

    user_ctx* ctx;
    switch (size_hint)
    {
        case CPU_WORD_SIZE_16:
            ctx = new phantom::rsa::ctx_rsa_tmpl<uint16_t>(PKC_SIG_RSASSA_PSS, hash, 16,
                                                           set, &m_params[0], 16, masking);
            break;
        case CPU_WORD_SIZE_32:
            ctx = new phantom::rsa::ctx_rsa_tmpl<uint32_t>(PKC_SIG_RSASSA_PSS, hash, 16,
                                                           set, &m_params[0], 16, masking);
            break;
#if defined(IS_64BIT)
        case CPU_WORD_SIZE_64:
            ctx = new phantom::rsa::ctx_rsa_tmpl<uint64_t>(PKC_SIG_RSASSA_PSS, hash, 16,
                                                           set, &m_params[0], 16, masking);
            break;
#endif
        default: throw std::invalid_argument("size_hint set is out of range");
    }

    if ((ctx->get_set() & 0xff) > 5) {
        throw std::invalid_argument("Parameter set is out of range");
    }
    return std::unique_ptr<user_ctx>(ctx);
}

bool rsassa_pss_signature::keygen(std::unique_ptr<user_ctx>& ctx)
{
    LOG_DEBUG("RSA KeyGen\n");

    phantom::rsa::ctx_rsa& myctx = dynamic_cast<phantom::rsa::ctx_rsa&>(*ctx.get());

    switch (myctx.get_wordsize())
    {
        case 16:
        {
            phantom::rsa::ctx_rsa_tmpl<uint16_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint16_t>&>(myctx);
            return ctx.pke()->keygen(ctx);
        } break;
        case 32:
        {
            phantom::rsa::ctx_rsa_tmpl<uint32_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint32_t>&>(myctx);
            return ctx.pke()->keygen(ctx);
        } break;
#if defined(IS_64BIT)
        case 64:
        {
            phantom::rsa::ctx_rsa_tmpl<uint64_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint64_t>&>(myctx);
            return ctx.pke()->keygen(ctx);
        } break;
#endif
    }

    return false;
}

bool rsassa_pss_signature::set_public_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k)
{
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

bool rsassa_pss_signature::get_public_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k)
{
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

bool rsassa_pss_signature::set_private_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k)
{
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

bool rsassa_pss_signature::get_private_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k)
{
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

bool rsassa_pss_signature::sign(const std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& m,
            phantom_vector<uint8_t>& s)
{
    LOG_DEBUG("RSA RSASSA-PSS Sign\n");

    phantom::rsa::ctx_rsa& myctx = dynamic_cast<phantom::rsa::ctx_rsa&>(*ctx.get());

    switch (myctx.get_wordsize())
    {
        case 16:
        {
            phantom::rsa::ctx_rsa_tmpl<uint16_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint16_t>&>(myctx);
            return reinterpret_cast<rsa_ssa_pss<uint16_t>*>(ctx.pke())->rsassa_pss_sign(ctx, m, s);
        } break;
        case 32:
        {
            phantom::rsa::ctx_rsa_tmpl<uint32_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint32_t>&>(myctx);
            return reinterpret_cast<rsa_ssa_pss<uint32_t>*>(ctx.pke())->rsassa_pss_sign(ctx, m, s);
        } break;
#if defined(IS_64BIT)
        case 64:
        {
            phantom::rsa::ctx_rsa_tmpl<uint64_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint64_t>&>(myctx);
            return reinterpret_cast<rsa_ssa_pss<uint64_t>*>(ctx.pke())->rsassa_pss_sign(ctx, m, s);
        } break;
#endif
    }

    return false;
}

bool rsassa_pss_signature::verify(const std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& m,
            const phantom_vector<uint8_t>& s)
{
    LOG_DEBUG("RSA RSASSA-PSS Verify\n");

    phantom::rsa::ctx_rsa& myctx = dynamic_cast<phantom::rsa::ctx_rsa&>(*ctx.get());

    switch (myctx.get_wordsize())
    {
        case 16:
        {
            phantom::rsa::ctx_rsa_tmpl<uint16_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint16_t>&>(myctx);
            return reinterpret_cast<rsa_ssa_pss<uint16_t>*>(ctx.pke())->rsassa_pss_verify(ctx, m, s);
        } break;
        case 32:
        {
            phantom::rsa::ctx_rsa_tmpl<uint32_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint32_t>&>(myctx);
            return reinterpret_cast<rsa_ssa_pss<uint32_t>*>(ctx.pke())->rsassa_pss_verify(ctx, m, s);
        } break;
#if defined(IS_64BIT)
        case 64:
        {
            phantom::rsa::ctx_rsa_tmpl<uint64_t>& ctx = dynamic_cast<phantom::rsa::ctx_rsa_tmpl<uint64_t>&>(myctx);
            return reinterpret_cast<rsa_ssa_pss<uint64_t>*>(ctx.pke())->rsassa_pss_verify(ctx, m, s);
        } break;
#endif
    }

    return false;
}

size_t rsassa_pss_signature::get_msg_len(const std::unique_ptr<user_ctx>& ctx) const
{
    phantom::rsa::ctx_rsa& myctx = dynamic_cast<phantom::rsa::ctx_rsa&>(*ctx.get());

    return (rsassa_pss_signature::m_params[myctx.get_set()].n_bits + 7) >> 3;
}

}  // namespace schemes
}  // namespace phantom
