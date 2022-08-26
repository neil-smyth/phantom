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

const phantom::rsa::rsa_set_t rsaes_oaep_pke::m_params[17] = {
    {0, 512},
    {1, 1024},
    {2, 2048},
    {3, 3072},
    {4, 4096},
    {5, 5120},
    {6, 6144},
    {7, 7168},
    {8, 8192},
    {9, 9216},
    {10, 10240},
    {11, 11264},
    {12, 12288},
    {13, 13312},
    {14, 14336},
    {15, 15360},
    {16, 16384},
};

size_t rsaes_oaep_pke::bits_2_set(security_strength_e bits)
{
    // Select the most appropriate parameter set for the given security strength
    size_t set = 0;
    switch (bits)
    {
        case SECURITY_STRENGTH_60:
        case SECURITY_STRENGTH_80:
        case SECURITY_STRENGTH_96:  set = 0; break;

        case SECURITY_STRENGTH_112:
        case SECURITY_STRENGTH_128: set = 1; break;

        case SECURITY_STRENGTH_160: set = 2; break;

        default: throw std::invalid_argument("Security strength is invalid");
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
    user_ctx* ctx;
    switch (size_hint)
    {
        case CPU_WORD_SIZE_16: ctx = new phantom::rsa::ctx_rsa_tmpl<uint16_t>(bits_2_set(bits), masking); break;
        case CPU_WORD_SIZE_32: ctx = new phantom::rsa::ctx_rsa_tmpl<uint32_t>(bits_2_set(bits), masking); break;
#if defined(IS_64BIT)
        case CPU_WORD_SIZE_64: ctx = new phantom::rsa::ctx_rsa_tmpl<uint64_t>(bits_2_set(bits), masking); break;
#endif
        default: throw std::invalid_argument("size_hint set is out of range");;
    }

    if ((ctx->get_set() & 0xff) > 5) {
        throw std::invalid_argument("Parameter set is out of range");
    }
    return std::unique_ptr<user_ctx>(ctx);
}

std::unique_ptr<user_ctx> rsaes_oaep_pke::create_ctx(size_t set,
                                                     cpu_word_size_e size_hint,
                                                     bool masking) const
{
    user_ctx* ctx;
    switch (size_hint)
    {
        case CPU_WORD_SIZE_16: ctx = new phantom::rsa::ctx_rsa_tmpl<uint16_t>(set, masking); break;
        case CPU_WORD_SIZE_32: ctx = new phantom::rsa::ctx_rsa_tmpl<uint32_t>(set, masking); break;
#if defined(IS_64BIT)
        case CPU_WORD_SIZE_64: ctx = new phantom::rsa::ctx_rsa_tmpl<uint64_t>(set, masking); break;
#endif
        default: throw std::invalid_argument("size_hint set is out of range");;
    }

    if ((ctx->get_set() & 0xff) > 5) {
        throw std::invalid_argument("Parameter set is out of range");
    }
    return std::unique_ptr<user_ctx>(ctx);
}

bool rsaes_oaep_pke::keygen(std::unique_ptr<user_ctx>& ctx)
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

bool rsaes_oaep_pke::set_public_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k)
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

bool rsaes_oaep_pke::get_public_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k)
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

bool rsaes_oaep_pke::set_private_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k)
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

bool rsaes_oaep_pke::get_private_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k)
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

bool rsaes_oaep_pke::encrypt(const std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t> pt,
            phantom_vector<uint8_t>& ct)
{
    LOG_DEBUG("RSA PKE Encrypt\n");

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
    LOG_DEBUG("RSA PKE Decrypt\n");

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
