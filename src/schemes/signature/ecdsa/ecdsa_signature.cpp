/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "schemes/signature/ecdsa/ecdsa_signature.hpp"
#include "schemes/signature/ecdsa/ctx_ecdsa.hpp"
#include "logging/logger.hpp"
#include "ecc/curves.hpp"
#include "crypto/hash_sha2.hpp"
#include "crypto/random_seed.hpp"
#include "packing/packer.hpp"
#include "packing/unpacker.hpp"
#include "packing/stream.hpp"


namespace phantom {
namespace schemes {


size_t ecdsa_signature::bits_2_set(security_strength_e bits)
{
    // Select the most appropriate parameter set for the given security strength
    size_t set = 0;
    switch (bits)
    {
        case SECURITY_STRENGTH_60:
        case SECURITY_STRENGTH_80:
        case SECURITY_STRENGTH_96:  set = 0; break;

        case SECURITY_STRENGTH_112: set = 1; break;

        case SECURITY_STRENGTH_128: set = 2; break;

        case SECURITY_STRENGTH_160:
        case SECURITY_STRENGTH_192: set = 3; break;

        case SECURITY_STRENGTH_256: set = 4; break;

        default: throw std::invalid_argument("Security strength is invalid");
    }

    return set;
}

ecdsa_signature::ecdsa_signature()
{
    m_prng = std::shared_ptr<csprng>(csprng::make(0x10000000, random_seed::seed_cb));
}

ecdsa_signature::~ecdsa_signature()
{
}

std::unique_ptr<user_ctx> ecdsa_signature::create_ctx(security_strength_e bits,
                                                      cpu_word_size_e size_hint,
                                                      bool masking) const
{
    user_ctx* ctx;
    switch (size_hint)
    {
        case CPU_WORD_SIZE_16: ctx = new ctx_ecdsa_tmpl<uint16_t>(bits_2_set(bits)); break;
        case CPU_WORD_SIZE_32: ctx = new ctx_ecdsa_tmpl<uint32_t>(bits_2_set(bits)); break;
#if defined(IS_64BIT)
        case CPU_WORD_SIZE_64: ctx = new ctx_ecdsa_tmpl<uint64_t>(bits_2_set(bits)); break;
#endif
        default: throw std::invalid_argument("size_hint set is out of range");;
    }

    if (ctx->get_set() > 14) {
        delete ctx;
        throw std::invalid_argument("Parameter set is out of range");
    }
    return std::unique_ptr<user_ctx>(ctx);
}

std::unique_ptr<user_ctx> ecdsa_signature::create_ctx(size_t set,
                                                      cpu_word_size_e size_hint,
                                                      bool masking) const
{
    user_ctx* ctx;
    switch (size_hint)
    {
        case CPU_WORD_SIZE_16: ctx = new ctx_ecdsa_tmpl<uint16_t>(set); break;
        case CPU_WORD_SIZE_32: ctx = new ctx_ecdsa_tmpl<uint32_t>(set); break;
#if defined(IS_64BIT)
        case CPU_WORD_SIZE_64: ctx = new ctx_ecdsa_tmpl<uint64_t>(set); break;
#endif
        default: throw std::invalid_argument("size_hint set is out of range");;
    }

    if (ctx->get_set() > 14) {
        delete ctx;
        throw std::invalid_argument("Parameter set is out of range");
    }
    return std::unique_ptr<user_ctx>(ctx);
}

bool ecdsa_signature::keygen(std::unique_ptr<user_ctx>& ctx)
{
    ctx_ecdsa& myctx = dynamic_cast<ctx_ecdsa&>(*ctx.get());

restart:
    switch (myctx.get_wordsize())
    {
        case 16:
        {
            ctx_ecdsa_tmpl<uint16_t>& ctx = dynamic_cast<ctx_ecdsa_tmpl<uint16_t>&>(myctx);
            if (!keygen_tmpl<uint16_t>(ctx)) {
                goto restart;
            }
        } break;

        case 32:
        {
            ctx_ecdsa_tmpl<uint32_t>& ctx = dynamic_cast<ctx_ecdsa_tmpl<uint32_t>&>(myctx);
            if (!keygen_tmpl<uint32_t>(ctx)) {
                goto restart;
            }
        } break;

#if defined(IS_64BIT)
        case 64:
        {
            ctx_ecdsa_tmpl<uint64_t>& ctx = dynamic_cast<ctx_ecdsa_tmpl<uint64_t>&>(myctx);
            if (!keygen_tmpl<uint64_t>(ctx)) {
                goto restart;
            }
        } break;
#endif

        default: return false;
    }

    return true;
}

bool ecdsa_signature::set_public_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& key)
{
    ctx_ecdsa& myctx = dynamic_cast<ctx_ecdsa&>(*ctx.get());

    switch (myctx.get_wordsize())
    {
        case 16:
        {
            ctx_ecdsa_tmpl<uint16_t>& ctx = dynamic_cast<ctx_ecdsa_tmpl<uint16_t>&>(myctx);
            return set_public_key_tmpl<uint16_t>(ctx, key);
        } break;

        case 32:
        {
            ctx_ecdsa_tmpl<uint32_t>& ctx = dynamic_cast<ctx_ecdsa_tmpl<uint32_t>&>(myctx);
            return set_public_key_tmpl<uint32_t>(ctx, key);
        } break;

#if defined(IS_64BIT)
        case 64:
        {
            ctx_ecdsa_tmpl<uint64_t>& ctx = dynamic_cast<ctx_ecdsa_tmpl<uint64_t>&>(myctx);
            return set_public_key_tmpl<uint64_t>(ctx, key);
        } break;
#endif

        default: return false;
    }
}

bool ecdsa_signature::get_public_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& key)
{
    ctx_ecdsa& myctx = dynamic_cast<ctx_ecdsa&>(*ctx.get());

    switch (myctx.get_wordsize())
    {
        case 16:
        {
            ctx_ecdsa_tmpl<uint16_t>& ctx = dynamic_cast<ctx_ecdsa_tmpl<uint16_t>&>(myctx);
            return get_public_key_tmpl<uint16_t>(ctx, key);
        } break;

        case 32:
        {
            ctx_ecdsa_tmpl<uint32_t>& ctx = dynamic_cast<ctx_ecdsa_tmpl<uint32_t>&>(myctx);
            return get_public_key_tmpl<uint32_t>(ctx, key);
        } break;

#if defined(IS_64BIT)
        case 64:
        {
            ctx_ecdsa_tmpl<uint64_t>& ctx = dynamic_cast<ctx_ecdsa_tmpl<uint64_t>&>(myctx);
            return get_public_key_tmpl<uint64_t>(ctx, key);
        } break;
#endif

        default: return false;
    }
}

bool ecdsa_signature::set_private_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& key)
{
    ctx_ecdsa& myctx = dynamic_cast<ctx_ecdsa&>(*ctx.get());

    uint8_t* sk = myctx.sk().data();
    size_t   n  = myctx.n();

    packing::unpacker up(key);
    for (size_t i = 0; i < n; i++) {
        sk[i] = up.read_unsigned(8, packing::RAW);
    }

    return true;
}

bool ecdsa_signature::get_private_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& key)
{
    ctx_ecdsa& myctx = dynamic_cast<ctx_ecdsa&>(*ctx.get());

    uint8_t* sk = myctx.sk().data();
    size_t   n  = myctx.n();

    key.clear();

    packing::packer pack(8 * n);
    for (size_t i = 0; i < n; i++) {
        pack.write_unsigned(sk[i], 8, packing::RAW);
    }

    pack.flush();
    key = pack.get();

    return true;
}

size_t ecdsa_signature::get_msg_len(const std::unique_ptr<user_ctx>& ctx) const
{
    ctx_ecdsa& myctx = dynamic_cast<ctx_ecdsa&>(*ctx.get());

    return myctx.n();
}

bool ecdsa_signature::sign(const std::unique_ptr<user_ctx>& ctx,
                           const phantom_vector<uint8_t>& m,
                           phantom_vector<uint8_t>& s)
{
    ctx_ecdsa& myctx = dynamic_cast<ctx_ecdsa&>(*ctx.get());

    switch (myctx.get_wordsize())
    {
        case 16:
        {
            ctx_ecdsa_tmpl<uint16_t>& ctx = dynamic_cast<ctx_ecdsa_tmpl<uint16_t>&>(myctx);
            if (!sign_calc<uint16_t>(ctx, m, s)) {
                return false;
            }
        } break;

        case 32:
        {
            ctx_ecdsa_tmpl<uint32_t>& ctx = dynamic_cast<ctx_ecdsa_tmpl<uint32_t>&>(myctx);
            if (!sign_calc<uint32_t>(ctx, m, s)) {
                return false;
            }
        } break;

#if defined(IS_64BIT)
        case 64:
        {
            ctx_ecdsa_tmpl<uint64_t>& ctx = dynamic_cast<ctx_ecdsa_tmpl<uint64_t>&>(myctx);
            if (!sign_calc<uint64_t>(ctx, m, s)) {
                return false;
            }
        } break;
#endif

        default: return false;
    }

    return true;
}

bool ecdsa_signature::verify(const std::unique_ptr<user_ctx>& ctx,
                             const phantom_vector<uint8_t>& m,
                             const phantom_vector<uint8_t>& s)
{
    ctx_ecdsa& myctx = dynamic_cast<ctx_ecdsa&>(*ctx.get());

    switch (myctx.get_wordsize())
    {
        case 16:
        {
            ctx_ecdsa_tmpl<uint16_t>& ctx = dynamic_cast<ctx_ecdsa_tmpl<uint16_t>&>(myctx);
            if (!verify_calc<uint16_t>(ctx, m, s)) {
                return false;
            }
        } break;

        case 32:
        {
            ctx_ecdsa_tmpl<uint32_t>& ctx = dynamic_cast<ctx_ecdsa_tmpl<uint32_t>&>(myctx);
            if (!verify_calc<uint32_t>(ctx, m, s)) {
                return false;
            }
        } break;

#if defined(IS_64BIT)
        case 64:
        {
            ctx_ecdsa_tmpl<uint64_t>& ctx = dynamic_cast<ctx_ecdsa_tmpl<uint64_t>&>(myctx);
            if (!verify_calc<uint64_t>(ctx, m, s)) {
                return false;
            }
        } break;
#endif
    }

    return true;
}

}  // namespace schemes
}  // namespace phantom
