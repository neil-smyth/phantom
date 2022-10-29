/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "schemes/signature/eddsa/eddsa_signature.hpp"

#include <string>

#include "schemes/signature/eddsa/ctx_eddsa.hpp"
#include "logging/logger.hpp"
#include "ecc/curves.hpp"
#include "crypto/hash_sha2.hpp"
#include "crypto/random_seed.hpp"
#include "packing/packer.hpp"
#include "packing/unpacker.hpp"
#include "packing/stream.hpp"


namespace phantom {
namespace schemes {


size_t eddsa_signature::bits_2_set(security_strength_e bits)
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

        case SECURITY_STRENGTH_160:
        case SECURITY_STRENGTH_192:
        case SECURITY_STRENGTH_224: set = 1; break;

        case SECURITY_STRENGTH_256:
        case SECURITY_STRENGTH_288:
        case SECURITY_STRENGTH_320:
        default: {
            LOG_ERROR("Security strength is invalid", g_pkc_log_level);
            throw std::invalid_argument("Security strength is invalid");
        }
    }

    return set;
}

eddsa_signature::eddsa_signature()
{
    m_prng = std::shared_ptr<csprng>(csprng::make(0x10000000, random_seed::seed_cb));
    m_hash = std::unique_ptr<crypto::hash>(new crypto::hash_sha2());
    m_xof  = std::unique_ptr<crypto::xof_sha3>(new crypto::xof_sha3());
}

eddsa_signature::~eddsa_signature()
{
}

std::unique_ptr<user_ctx> eddsa_signature::create_ctx(security_strength_e bits,
                                                      cpu_word_size_e size_hint,
                                                      bool masking) const
{
    return create_ctx(eddsa_signature::bits_2_set(bits), size_hint, masking);
}

std::unique_ptr<user_ctx> eddsa_signature::create_ctx(size_t set,
                                                      cpu_word_size_e size_hint,
                                                      bool masking) const
{
    std::stringstream ss;
    user_ctx* ctx;

    (void) masking;

    switch (size_hint)
    {
        case CPU_WORD_SIZE_16: ctx = new ctx_eddsa_tmpl<uint16_t>(set); break;
        case CPU_WORD_SIZE_32: ctx = new ctx_eddsa_tmpl<uint32_t>(set); break;
#if defined(IS_64BIT)
        case CPU_WORD_SIZE_64: ctx = new ctx_eddsa_tmpl<uint64_t>(set); break;
#endif
        default: {
            ss << "size_hint " << set << " is out of range";  // NOLINT
            LOG_ERROR(ss.str(), g_pkc_log_level);
            throw std::invalid_argument(ss.str());
        }
    }

    if (ctx->get_set() > 4) {
        delete ctx;
        ss << "Parameter set " << ctx->get_set() << " is out of range";
        LOG_ERROR(ss.str(), g_pkc_log_level);
        throw std::invalid_argument(ss.str());
    }

    ss << "EdDSA Signature context created [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);
    return std::unique_ptr<user_ctx>(ctx);
}

bool eddsa_signature::keygen(std::unique_ptr<user_ctx>& ctx)
{
    std::stringstream ss;
    ss << "EdDSA Signature KeyGen [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_eddsa& myctx = dynamic_cast<ctx_eddsa&>(*ctx.get());

restart:
    switch (myctx.get_wordsize())
    {
        case 16:
        {
            ctx_eddsa_tmpl<uint16_t>& ctx = dynamic_cast<ctx_eddsa_tmpl<uint16_t>&>(myctx);
            if (!keygen_tmpl<uint16_t>(ctx)) {
                goto restart;
            }
        } break;

        case 32:
        {
            ctx_eddsa_tmpl<uint32_t>& ctx = dynamic_cast<ctx_eddsa_tmpl<uint32_t>&>(myctx);
            if (!keygen_tmpl<uint32_t>(ctx)) {
                goto restart;
            }
        } break;

#if defined(IS_64BIT)
        case 64:
        {
            ctx_eddsa_tmpl<uint64_t>& ctx = dynamic_cast<ctx_eddsa_tmpl<uint64_t>&>(myctx);
            if (!keygen_tmpl<uint64_t>(ctx)) {
                goto restart;
            }
        } break;
#endif

        default: return false;
    }

    return true;
}

bool eddsa_signature::set_public_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& key)
{
    std::stringstream ss;
    ss << "EdDSA Signature set public key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_eddsa& myctx = dynamic_cast<ctx_eddsa&>(*ctx.get());

    switch (myctx.get_wordsize())
    {
        case 16:
        {
            ctx_eddsa_tmpl<uint16_t>& ctx = dynamic_cast<ctx_eddsa_tmpl<uint16_t>&>(myctx);
            return set_public_key_tmpl<uint16_t>(ctx, key);
        } break;

        case 32:
        {
            ctx_eddsa_tmpl<uint32_t>& ctx = dynamic_cast<ctx_eddsa_tmpl<uint32_t>&>(myctx);
            return set_public_key_tmpl<uint32_t>(ctx, key);
        } break;

#if defined(IS_64BIT)
        case 64:
        {
            ctx_eddsa_tmpl<uint64_t>& ctx = dynamic_cast<ctx_eddsa_tmpl<uint64_t>&>(myctx);
            return set_public_key_tmpl<uint64_t>(ctx, key);
        } break;
#endif

        default: return false;
    }
}

bool eddsa_signature::get_public_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& key)
{
    std::stringstream ss;
    ss << "EdDSA Signature get public key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_eddsa& myctx = dynamic_cast<ctx_eddsa&>(*ctx.get());

    switch (myctx.get_wordsize())
    {
        case 16:
        {
            ctx_eddsa_tmpl<uint16_t>& ctx = dynamic_cast<ctx_eddsa_tmpl<uint16_t>&>(myctx);
            key = ctx.A();
            return true;
        } break;

        case 32:
        {
            ctx_eddsa_tmpl<uint32_t>& ctx = dynamic_cast<ctx_eddsa_tmpl<uint32_t>&>(myctx);
            key = ctx.A();
            return true;
        } break;

#if defined(IS_64BIT)
        case 64:
        {
            ctx_eddsa_tmpl<uint64_t>& ctx = dynamic_cast<ctx_eddsa_tmpl<uint64_t>&>(myctx);
            key = ctx.A();
            return true;
        } break;
#endif

        default: return false;
    }
}

bool eddsa_signature::set_private_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& key)
{
    std::stringstream ss;
    ss << "EdDSA Signature set private key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_eddsa& myctx = dynamic_cast<ctx_eddsa&>(*ctx.get());

    myctx.sk() = key;

    switch (myctx.get_wordsize())
    {
        case 16:
        {
            ctx_eddsa_tmpl<uint16_t>& ctx = dynamic_cast<ctx_eddsa_tmpl<uint16_t>&>(myctx);
            return secret_expand<uint16_t>(ctx, myctx.sk());
        } break;

        case 32:
        {
            ctx_eddsa_tmpl<uint32_t>& ctx = dynamic_cast<ctx_eddsa_tmpl<uint32_t>&>(myctx);
            return secret_expand<uint32_t>(ctx, myctx.sk());
        } break;

#if defined(IS_64BIT)
        case 64:
        {
            ctx_eddsa_tmpl<uint64_t>& ctx = dynamic_cast<ctx_eddsa_tmpl<uint64_t>&>(myctx);
            return secret_expand<uint64_t>(ctx, myctx.sk());
        } break;
#endif

        default: return false;
    }

    return true;
}

bool eddsa_signature::get_private_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& key)
{
    std::stringstream ss;
    ss << "EdDSA Signature get private key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_eddsa& myctx = dynamic_cast<ctx_eddsa&>(*ctx.get());

    uint8_t* sk = myctx.sk().data();
    size_t num_bits  = myctx.get_curve_bits();
    size_t num_bytes = (num_bits + 7 + 1) >> 3;

    key.clear();

    packing::packer pack(8 * num_bytes);
    for (size_t i = 0; i < num_bytes; i++) {
        pack.write_unsigned(sk[i], 8, packing::RAW);
    }

    pack.flush();
    key = pack.get();

    return true;
}

size_t eddsa_signature::get_msg_len(const std::unique_ptr<user_ctx>& ctx) const
{
    ctx_eddsa& myctx = dynamic_cast<ctx_eddsa&>(*ctx.get());

    return myctx.n();
}

bool eddsa_signature::sign(const std::unique_ptr<user_ctx>& ctx,
                           const phantom_vector<uint8_t>& m,
                           phantom_vector<uint8_t>& s)
{
    phantom_vector<uint8_t> c;
    return sign(ctx, m, s, c);
}

bool eddsa_signature::sign(const std::unique_ptr<user_ctx>& ctx,
                           const phantom_vector<uint8_t>& m,
                           phantom_vector<uint8_t>& s,
                           const phantom_vector<uint8_t>& c)
{
    std::stringstream ss;
    ss << "EdDSA Signature Sign [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_eddsa& myctx = dynamic_cast<ctx_eddsa&>(*ctx.get());

    switch (myctx.get_wordsize())
    {
        case 16:
        {
            ctx_eddsa_tmpl<uint16_t>& ctx = dynamic_cast<ctx_eddsa_tmpl<uint16_t>&>(myctx);
            if (!sign_calc<uint16_t>(ctx, m, s, c)) {
                return false;
            }
        } break;

        case 32:
        {
            ctx_eddsa_tmpl<uint32_t>& ctx = dynamic_cast<ctx_eddsa_tmpl<uint32_t>&>(myctx);
            if (!sign_calc<uint32_t>(ctx, m, s, c)) {
                return false;
            }
        } break;

#if defined(IS_64BIT)
        case 64:
        {
            ctx_eddsa_tmpl<uint64_t>& ctx = dynamic_cast<ctx_eddsa_tmpl<uint64_t>&>(myctx);
            if (!sign_calc<uint64_t>(ctx, m, s, c)) {
                return false;
            }
        } break;
#endif

        default: return false;
    }

    return true;
}

bool eddsa_signature::verify(const std::unique_ptr<user_ctx>& ctx,
                             const phantom_vector<uint8_t>& m,
                             const phantom_vector<uint8_t>& s)
{
    phantom_vector<uint8_t> c;
    return verify(ctx, m, s, c);
}

bool eddsa_signature::verify(const std::unique_ptr<user_ctx>& ctx,
                             const phantom_vector<uint8_t>& m,
                             const phantom_vector<uint8_t>& s,
    const phantom_vector<uint8_t>& c)
{
    std::stringstream ss;
    ss << "EdDSA Signature Verify [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_eddsa& myctx = dynamic_cast<ctx_eddsa&>(*ctx.get());

    switch (myctx.get_wordsize())
    {
        case 16:
        {
            ctx_eddsa_tmpl<uint16_t>& ctx = dynamic_cast<ctx_eddsa_tmpl<uint16_t>&>(myctx);
            if (!verify_calc<uint16_t>(ctx, m, s, c)) {
                return false;
            }
        } break;

        case 32:
        {
            ctx_eddsa_tmpl<uint32_t>& ctx = dynamic_cast<ctx_eddsa_tmpl<uint32_t>&>(myctx);
            if (!verify_calc<uint32_t>(ctx, m, s, c)) {
                return false;
            }
        } break;

#if defined(IS_64BIT)
        case 64:
        {
            ctx_eddsa_tmpl<uint64_t>& ctx = dynamic_cast<ctx_eddsa_tmpl<uint64_t>&>(myctx);
            if (!verify_calc<uint64_t>(ctx, m, s, c)) {
                return false;
            }
        } break;
#endif
    }

    return true;
}

phantom_vector<uint8_t> eddsa_signature::gen_F(bool is_ed25519, bool phflag)
{
    phantom_vector<uint8_t> F;

    if (is_ed25519) {
        return F;
    }

    F.resize(1);
    F[0] = phflag;

    return F;
}

void eddsa_signature::gen_ph_hash(bool enable_sha512,
                                  phantom_vector<uint8_t>& out,
                                  const phantom_vector<uint8_t>& m,
                                  bool pure_eddsa)
{
    if (pure_eddsa) {
        out = m;
    }
    else {
        if (enable_sha512) {
            out.resize(64);

            m_hash->init(64);
            m_hash->update(m.data(), m.size());
            m_hash->final(out.data());
        }
        else {
            out.resize(64);

            m_xof->init(32);
            m_xof->absorb(m.data(), m.size());
            m_xof->final();
            m_xof->squeeze(out.data(), 64);
        }
    }
}

void eddsa_signature::gen_r_hash(bool enable_sha512, phantom_vector<uint8_t>& out, const phantom_vector<uint8_t>& dom,
    const phantom_vector<uint8_t>& prefix, const phantom_vector<uint8_t>& ph_m)
{
    if (enable_sha512) {
        out.resize(64);

        m_hash->init(64);
        m_hash->update(dom.data(), dom.size());
        m_hash->update(prefix.data(), prefix.size());
        m_hash->update(ph_m.data(), ph_m.size());
        m_hash->final(out.data());
    }
    else {
        out.resize(114);

        m_xof->init(32);
        m_xof->absorb(dom.data(), dom.size());
        m_xof->absorb(prefix.data(), prefix.size());
        m_xof->absorb(ph_m.data(), ph_m.size());
        m_xof->final();
        m_xof->squeeze(out.data(), 114);
    }
}

void eddsa_signature::gen_k_hash(bool enable_sha512, phantom_vector<uint8_t>& out,
    const phantom_vector<uint8_t>& dom, const phantom_vector<uint8_t>& r,
    const phantom_vector<uint8_t>& a, const phantom_vector<uint8_t>& ph_m)
{
    if (enable_sha512) {
        out.resize(64);

        m_hash->init(64);
        m_hash->update(dom.data(), dom.size());
        m_hash->update(r.data(), r.size());
        m_hash->update(a.data(), a.size());
        m_hash->update(ph_m.data(), ph_m.size());
        m_hash->final(out.data());
    }
    else {
        out.resize(114);

        m_xof->init(32);
        m_xof->absorb(dom.data(), dom.size());
        m_xof->absorb(r.data(), r.size());
        m_xof->absorb(a.data(), a.size());
        m_xof->absorb(ph_m.data(), ph_m.size());
        m_xof->final();
        m_xof->squeeze(out.data(), 114);
    }
}

phantom_vector<uint8_t> eddsa_signature::dom(bool blank,
                                             bool ed448,
                                             const phantom_vector<uint8_t>& x,
                                             const phantom_vector<uint8_t>& y)
{
    assert(x.size() <= 255);
    assert(y.size() <= 255);

    static const std::string dom2_ascii = "SigEd25519 no Ed25519 collisions";
    static const std::string dom4_ascii = "SigEd448";

    const std::string& ascii = ed448 ? dom4_ascii : dom2_ascii;

    phantom_vector<uint8_t> out;
    if (!blank) {
        out = phantom_vector<uint8_t>(ascii.begin(), ascii.end());
        out.insert(out.end(), x.begin(), x.end());
        out.push_back(y.size());
        out.insert(out.end(), y.begin(), y.end());
    }

    return out;
}

}  // namespace schemes
}  // namespace phantom
