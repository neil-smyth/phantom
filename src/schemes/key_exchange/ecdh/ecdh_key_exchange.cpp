/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "schemes/key_exchange/ecdh/ecdh_key_exchange.hpp"

#include <iterator>

#include "sampling/uniform_sampler.hpp"
#include "logging/logger.hpp"
#include "packing/packer.hpp"
#include "packing/unpacker.hpp"
#include "packing/stream.hpp"
#include "ecc/curves.hpp"
#include "ecc/ecc.hpp"
#include "crypto/random_seed.hpp"

#include "ecc/prime_point.hpp"
#include "ecc/weierstrass_prime_affine.hpp"
#include "ecc/weierstrass_prime_jacobian.hpp"
#include "ecc/weierstrass_prime_projective.hpp"
#include "ecc/binary_point.hpp"
#include "ecc/weierstrass_binary_affine.hpp"
#include "ecc/weierstrass_binary_projective.hpp"
#include "ecc/weierstrass_binary_jacobian.hpp"


namespace phantom {
namespace schemes {

#define MACHINE_WORDS(x)    ((x + machine::bits_per_word() - 1) / machine::bits_per_word())


size_t ecdh_key_exchange::bits_2_set(security_strength_e bits)
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

        default: {
            LOG_ERROR("Security strength is invalid", g_pkc_log_level);
            throw std::invalid_argument("Security strength is invalid");
        }
    }

    return set;
}

ecdh_key_exchange::ecdh_key_exchange()
{
    m_prng = std::shared_ptr<csprng>(csprng::make(0x10000000, random_seed::seed_cb));
}

ecdh_key_exchange::~ecdh_key_exchange()
{
}

std::unique_ptr<user_ctx> ecdh_key_exchange::create_ctx(security_strength_e bits,
                                                        cpu_word_size_e size_hint,
                                                        bool masking) const
{
    return create_ctx(ecdh_key_exchange::bits_2_set(bits), size_hint, masking);
}

std::unique_ptr<user_ctx> ecdh_key_exchange::create_ctx(size_t set,
                                                        cpu_word_size_e size_hint,
                                                        bool masking) const
{
    std::stringstream ss;
    user_ctx* ctx;

    (void)masking;

    switch (size_hint)
    {
        case CPU_WORD_SIZE_16: ctx = new ctx_ecdh_tmpl<uint16_t>(set); break;
        case CPU_WORD_SIZE_32: ctx = new ctx_ecdh_tmpl<uint32_t>(set); break;
#if defined(IS_64BIT)
        case CPU_WORD_SIZE_64: ctx = new ctx_ecdh_tmpl<uint64_t>(set); break;
#endif
        default: {
            ss << "size_hint " << set << " is out of range";  // NOLINT
            LOG_ERROR(ss.str(), g_pkc_log_level);
            throw std::invalid_argument(ss.str());
        }
    }

    if (ctx->get_set() > 16) {
        delete ctx;

        ss << "Parameter set " << ctx->get_set() << " is out of range";
        LOG_ERROR(ss.str(), g_pkc_log_level);
        throw std::invalid_argument(ss.str());
    }

    ss << "ECDH context created [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);
    return std::unique_ptr<user_ctx>(ctx);
}

bool ecdh_key_exchange::keygen(std::unique_ptr<user_ctx>& ctx)
{
    (void) ctx;
    LOG_WARNING("Illegal call", g_pkc_log_level);
    return false;
}

bool ecdh_key_exchange::set_public_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k)
{
    (void) ctx;
    (void) k;
    LOG_WARNING("Illegal call", g_pkc_log_level);
    return false;
}

bool ecdh_key_exchange::get_public_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k)
{
    (void) ctx;
    (void) k;
    LOG_WARNING("Illegal call", g_pkc_log_level);
    return false;
}

bool ecdh_key_exchange::set_private_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k)
{
    (void) ctx;
    (void) k;
    LOG_WARNING("Illegal call", g_pkc_log_level);
    return false;
}

bool ecdh_key_exchange::get_private_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k)
{
    (void) ctx;
    (void) k;
    LOG_WARNING("Illegal call", g_pkc_log_level);
    return false;
}

size_t ecdh_key_exchange::get_msg_len(const std::unique_ptr<user_ctx>& ctx) const
{
    ctx_ecdh& myctx = dynamic_cast<ctx_ecdh&>(*ctx.get());

    return myctx.n();
}

template<class T>
static bool ecc_diffie_hellman(ctx_ecdh& myctx, const elliptic::point<T>& p_base,
    phantom_vector<uint8_t>& m, bool final_flag)
{
    const phantom_vector<uint8_t>& secret = myctx.sk();

    // Obtain common array lengths
    size_t num_bytes = myctx.get_curve_bytes();

    ctx_ecdh_tmpl<T>& ctx = dynamic_cast<ctx_ecdh_tmpl<T>&>(myctx);

    std::unique_ptr<core::mp<T>> x, y;
    if (elliptic::field_e::WEIERSTRASS_BINARY_FIELD == ctx.field()) {
        x = std::unique_ptr<core::mp<T>>(new core::mp_gf2n<T>("0", ctx.get_modulus(), 16));
        y = std::unique_ptr<core::mp<T>>(new core::mp_gf2n<T>("0", ctx.get_modulus(), 16));
    }
    else {
        x = std::unique_ptr<core::mp<T>>(new core::mpz<T>());
        y = std::unique_ptr<core::mp<T>>(new core::mpz<T>());
    }

    if (final_flag) {
        ctx.setup_final(p_base);

        // Perform a scalar point multiplication from the base point using the random secret
        ctx.scalar_point_mul_final(secret);

        // Translate the output point (coordinates are MP variables) to the output byte stream
        ctx.get_result_final(x.get(), y.get());
    }
    else {
        // Perform a scalar point multiplication from the base point using the random secret
        ctx.scalar_point_mul_init(secret);

        // Translate the output point (coordinates are MP variables) to the output byte stream
        ctx.get_result_init(x.get(), y.get());

        /*if (field_e::BINARY_FIELD == ctx.field()) {
            const core::mp_gf2n<T>& gf2n_x = dynamic_cast<const core::mp_gf2n<T>&>(*x.get());
            const core::mp_gf2n<T>& gf2n_y = dynamic_cast<const core::mp_gf2n<T>&>(*y.get());

            std::cout << "result x = " << gf2n_x.get_str(16) << std::endl;
            std::cout << "       y = " << gf2n_y.get_str(16) << std::endl;
        }*/
    }

    phantom_vector<uint8_t> x_msg, y_msg;
    x->get_bytes(x_msg);
    if (!final_flag) {
        y->get_bytes(y_msg);
    }

    m = x_msg;
    m.resize(num_bytes);
    if (!final_flag) {
        m.insert(m.end(), y_msg.begin(), y_msg.end());
        m.resize(num_bytes * 2);
    }

    return true;
}

template<class T>
static bool curve25519_key_exchange_finalization(ctx_ecdh& myctx, const phantom_vector<uint8_t>& x_bytes,
    const phantom_vector<uint8_t>& y_bytes, phantom_vector<uint8_t>& shared_key)
{
    ctx_ecdh_tmpl<T>& ctx = dynamic_cast<ctx_ecdh_tmpl<T>&>(myctx);

    core::mpz<T> g_x, g_y;
    g_x.set_bytes(x_bytes);
    g_y.set_bytes(y_bytes);

    std::unique_ptr<elliptic::point<T>> q = std::unique_ptr<elliptic::point<T>>(
        new elliptic::montgomery_prime_affine<T>(ctx.get_configuration(), g_x, g_y));
    return ecc_diffie_hellman<T>(myctx, *q.get(), shared_key, true);
}

template<class T>
static bool prime_key_exchange_finalization(ctx_ecdh& myctx, const phantom_vector<uint8_t>& x_bytes,
    const phantom_vector<uint8_t>& y_bytes, phantom_vector<uint8_t>& shared_key)
{
    ctx_ecdh_tmpl<T>& ctx = dynamic_cast<ctx_ecdh_tmpl<T>&>(myctx);

    core::mpz<T> g_x, g_y;
    g_x.set_bytes(x_bytes);
    g_y.set_bytes(y_bytes);

    std::unique_ptr<elliptic::point<T>> q = std::unique_ptr<elliptic::point<T>>(
        new elliptic::weierstrass_prime_affine<T>(ctx.get_configuration(), g_x, g_y));
    return ecc_diffie_hellman<T>(myctx, *q.get(), shared_key, true);
}

template<class T>
static bool binary_key_exchange_finalization(ctx_ecdh& myctx, const phantom_vector<uint8_t>& x_bytes,
    const phantom_vector<uint8_t>& y_bytes, phantom_vector<uint8_t>& shared_key)
{
    ctx_ecdh_tmpl<T>& ctx = dynamic_cast<ctx_ecdh_tmpl<T>&>(myctx);

    core::mp_gf2n<T> g_x("0", ctx.get_modulus(), 16);
    core::mp_gf2n<T> g_y("0", ctx.get_modulus(), 16);
    g_x.set_bytes(x_bytes);
    g_y.set_bytes(y_bytes);

    std::unique_ptr<elliptic::point<T>> q = std::unique_ptr<elliptic::point<T>>(
        new elliptic::weierstrass_binary_affine<T>(ctx.get_configuration(), g_x, g_y));
    return ecc_diffie_hellman<T>(myctx, *q.get(), shared_key, true);
}

bool ecdh_key_exchange::key_exchange_setup(std::unique_ptr<user_ctx>& ctx)
{
    ctx_ecdh& myctx = dynamic_cast<ctx_ecdh&>(*ctx.get());

    // Perform a scalar point multiplication from the base point using the random secret
    switch (myctx.get_wordsize())
    {
        case 16:
        {
            ctx_ecdh_tmpl<uint16_t>& ctx = dynamic_cast<ctx_ecdh_tmpl<uint16_t>&>(myctx);
            ctx.setup_init(ctx.get_base());
        } break;

        case 32:
        {
            ctx_ecdh_tmpl<uint32_t>& ctx = dynamic_cast<ctx_ecdh_tmpl<uint32_t>&>(myctx);
            ctx.setup_init(ctx.get_base());
        } break;

#if defined(IS_64BIT)
        case 64:
        {
            ctx_ecdh_tmpl<uint64_t>& ctx = dynamic_cast<ctx_ecdh_tmpl<uint64_t>&>(myctx);
            ctx.setup_init(ctx.get_base());
        } break;
#endif

        default: return false;
    }

    return true;
}

bool ecdh_key_exchange::key_exchange_init(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& m)
{
    ctx_ecdh& myctx = dynamic_cast<ctx_ecdh&>(*ctx.get());

    size_t num_bits  = myctx.get_curve_bits();
    size_t num_bytes = myctx.get_curve_bytes();

    myctx.sk() = phantom_vector<uint8_t>(num_bytes);

    m_prng->get_mem(myctx.sk().data(), num_bytes);
    myctx.sk()[num_bytes-1] &= ~uint8_t(0) >> (num_bytes*8 - num_bits);

    if (myctx.get_set() == 15) {  // Curve25519
        myctx.sk()[0]  &= 248;
        myctx.sk()[31] &= 127;
        myctx.sk()[31] |= 64;
    }
    else if (myctx.get_set() == 16) {  // Curve448
        myctx.sk()[0]  &= 252;
        myctx.sk()[55] |= 128;
    }

    switch (myctx.get_wordsize())
    {
        case 16:
        {
            ctx_ecdh_tmpl<uint16_t>& ctx = dynamic_cast<ctx_ecdh_tmpl<uint16_t>&>(myctx);
            return ecc_diffie_hellman<uint16_t>(myctx, ctx.get_base(), m, false);
        } break;

        case 32:
        {
            ctx_ecdh_tmpl<uint32_t>& ctx = dynamic_cast<ctx_ecdh_tmpl<uint32_t>&>(myctx);
            return ecc_diffie_hellman<uint32_t>(myctx, ctx.get_base(), m, false);
        } break;

#if defined(IS_64BIT)
        case 64:
        {
            ctx_ecdh_tmpl<uint64_t>& ctx = dynamic_cast<ctx_ecdh_tmpl<uint64_t>&>(myctx);
            return ecc_diffie_hellman<uint64_t>(myctx, ctx.get_base(), m, false);
        } break;
#endif

        default: throw std::runtime_error("cpu_word_size is illegal");
    }
}

bool ecdh_key_exchange::key_exchange_final(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& m,
    phantom_vector<uint8_t>& shared_key)
{
    ctx_ecdh& myctx = dynamic_cast<ctx_ecdh&>(*ctx.get());

    size_t num_bytes = myctx.get_curve_bytes();

    if (m.size() != 2 * num_bytes) {
        return false;
    }

    phantom_vector<uint8_t> x_bytes(m.cbegin(), m.cbegin() + num_bytes);
    phantom_vector<uint8_t> y_bytes(m.cbegin() + num_bytes, m.cend());

    switch (myctx.get_wordsize())
    {
        case 16:
        {
            if (elliptic::field_e::MONTGOMERY_PRIME_FIELD == myctx.field()) {
                return curve25519_key_exchange_finalization<uint16_t>(myctx, x_bytes, y_bytes, shared_key);
            }
            else if (elliptic::field_e::WEIERSTRASS_PRIME_FIELD == myctx.field()) {
                return prime_key_exchange_finalization<uint16_t>(myctx, x_bytes, y_bytes, shared_key);
            }
            else {
                return binary_key_exchange_finalization<uint16_t>(myctx, x_bytes, y_bytes, shared_key);
            }
        } break;

        case 32:
        {
            if (elliptic::field_e::MONTGOMERY_PRIME_FIELD == myctx.field()) {
                return curve25519_key_exchange_finalization<uint32_t>(myctx, x_bytes, y_bytes, shared_key);
            }
            else if (elliptic::field_e::WEIERSTRASS_PRIME_FIELD == myctx.field()) {
                return prime_key_exchange_finalization<uint32_t>(myctx, x_bytes, y_bytes, shared_key);
            }
            else {
                return binary_key_exchange_finalization<uint32_t>(myctx, x_bytes, y_bytes, shared_key);
            }
        } break;

#if defined(IS_64BIT)
        case 64:
        {
            if (elliptic::field_e::MONTGOMERY_PRIME_FIELD == myctx.field()) {
                return curve25519_key_exchange_finalization<uint64_t>(myctx, x_bytes, y_bytes, shared_key);
            }
            else if (elliptic::field_e::WEIERSTRASS_PRIME_FIELD == myctx.field()) {
                return prime_key_exchange_finalization<uint64_t>(myctx, x_bytes, y_bytes, shared_key);
            }
            else {
                return binary_key_exchange_finalization<uint64_t>(myctx, x_bytes, y_bytes, shared_key);
            }
        } break;
#endif

        default: throw std::runtime_error("cpu_word_size is illegal");
    }

    return false;
}

}  // namespace schemes
}  // namespace phantom
