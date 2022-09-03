/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "./phantom.hpp"
#include "./config.hpp"

#include "schemes/ibe/dlp/ibe_dlp.hpp"
#include "schemes/kem/kyber/kyber_kem.hpp"
#include "schemes/kem/saber/saber_kem.hpp"
#include "schemes/key_exchange/ecdh/ecdh_key_exchange.hpp"
#include "schemes/signature/dilithium/dilithium_signature.hpp"
#include "schemes/signature/falcon/falcon_signature.hpp"
#include "schemes/signature/ecdsa/ecdsa_signature.hpp"
#include "schemes/signature/eddsa/eddsa_signature.hpp"
#include "schemes/signature/rsassa_pss/rsassa_pss_signature.hpp"
#include "schemes/pke/kyber/kyber_pke.hpp"
#include "schemes/pke/saber/saber_pke.hpp"
#include "schemes/pke/rsaes_oaep/rsaes_oaep_pke.hpp"
#include "crypto/aes.hpp"
#include "crypto/aes_ctr.hpp"
#include "crypto/aes_gcm.hpp"
#include "crypto/fpe.hpp"
#include "crypto/shamirs_secret_sharing.hpp"

namespace phantom {

#define STRINGIFY(s)    #s
#ifndef PHANTOM_BUILD_VERSION
#define PHANTOM_BUILD_VERSION           "Unknown"
#endif

#define COMPILATION_BUILD_DATE     __DATE__ " " __TIME__

#define COMPILER_VERSION_STRING(major, minor, patch) STRINGIFY(major) "." STRINGIFY(minor) "." STRINGIFY(patch)

#ifdef __clang__
#define COMPILER_VERSION "Clang " COMPILER_VERSION_STRING(__clang_major__, __clang_minor__, __clang_patchlevel__)
#else
#ifdef __GNUC__
#define COMPILER_VERSION "GNU C++ " COMPILER_VERSION_STRING(__GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__)
#else
#ifdef _MSC_VER
#define COMPILER_VERSION "Microsoft Visual C++ (MSVC) " STRINGIFY(_MSC_FULL_VER)
#else
#define COMPILER_VERSION "Unknown compiler"
#endif
#endif
#endif

#define BUILDTM_YEAR (\
         __DATE__[7] == '?' ? 1900 \
    : (((__DATE__[7] - '0') * 1000) \
    +   (__DATE__[8] - '0') * 100 \
    +   (__DATE__[9] - '0') * 10 \
    +   __DATE__[10] - '0'))

#define BUILDTM_MONTH (\
      __DATE__ [2] == '?' ? 1 \
    : __DATE__ [2] == 'n' ? (__DATE__ [1] == 'a' ? 1 : 6) \
    : __DATE__ [2] == 'b' ? 2 \
    : __DATE__ [2] == 'r' ? (__DATE__ [0] == 'M' ? 3 : 4) \
    : __DATE__ [2] == 'y' ? 5 \
    : __DATE__ [2] == 'l' ? 7 \
    : __DATE__ [2] == 'g' ? 8 \
    : __DATE__ [2] == 'p' ? 9 \
    : __DATE__ [2] == 't' ? 10 \
    : __DATE__ [2] == 'v' ? 11 \
    :                       12)

#define BUILDTM_DAY (\
        __DATE__[4] == '?' ? 1 \
    : ((__DATE__[4] == ' ' ? 0 : \
      ((__DATE__[4] - '0') * 10)) + __DATE__[5] - '0'))

const std::string build_info::version()
{
    return PHANTOM_BUILD_VERSION;
}

const std::string build_info::build_date()
{
    int size_s = std::snprintf(nullptr,  // flawfinder: ignore
                               0,
                               "%04d-%02d-%02dT%s",
                               BUILDTM_YEAR,
                               BUILDTM_MONTH,
                               BUILDTM_DAY,
                               __TIME__) + 1;
    auto size = static_cast<size_t>(size_s);
    std::unique_ptr<char[]> buf( new char[ size ] );
    std::snprintf(buf.get(),  // flawfinder: ignore
                  size,
                  "%04d-%02d-%02dT%s",
                  BUILDTM_YEAR,
                  BUILDTM_MONTH,
                  BUILDTM_DAY,
                  __TIME__);
    return std::string(buf.get(), buf.get() + size - 1);
}

const std::string build_info::compiler()
{
    return COMPILER_VERSION;
}


pkc::pkc(pkc_e type)
{
    switch (type)
    {
#if defined(ENABLE_SIGNATURE_DILITHIUM)
        case PKC_SIG_DILITHIUM:
            m_scheme = std::unique_ptr<scheme>(new schemes::dilithium_signature());
            break;
#endif
#if defined(ENABLE_SIGNATURE_FALCON)
        case PKC_SIG_FALCON:
            m_scheme = std::unique_ptr<scheme>(new schemes::falcon_signature());
            break;
#endif
#if defined(ENABLE_SIGNATURE_ECDSA)
        case PKC_SIG_ECDSA:
            m_scheme = std::unique_ptr<scheme>(new schemes::ecdsa_signature());
            break;
#endif
#if defined(ENABLE_SIGNATURE_EDDSA)
        case PKC_SIG_EDDSA:
            m_scheme = std::unique_ptr<scheme>(new schemes::eddsa_signature());
            break;
#endif
#if defined(ENABLE_SIGNATURE_RSASSA_PSS)
        case PKC_SIG_RSASSA_PSS:
            m_scheme = std::unique_ptr<scheme>(new schemes::rsassa_pss_signature());
            break;
#endif
#if defined(ENABLE_KEM_KYBER)
        case PKC_KEM_KYBER:
            m_scheme = std::unique_ptr<scheme>(new schemes::kyber_kem());
            break;
#endif
#if defined(ENABLE_KEM_SABER)
        case PKC_KEM_SABER:
            m_scheme = std::unique_ptr<scheme>(new schemes::saber_kem());
            break;
#endif
#if defined(ENABLE_KEY_EXCHANGE_ECDH)
        case PKC_KEY_ECDH:
            m_scheme = std::unique_ptr<scheme>(new schemes::ecdh_key_exchange());
            break;
#endif
#if defined(ENABLE_PKE_KYBER)
        case PKC_PKE_KYBER:
            m_scheme = std::unique_ptr<scheme>(new schemes::kyber_pke());
            break;
#endif
#if defined(ENABLE_PKE_SABER)
        case PKC_PKE_SABER:
            m_scheme = std::unique_ptr<scheme>(new schemes::saber_pke());
            break;
#endif
#if defined(ENABLE_PKE_RSAES_OAEP)
        case PKC_PKE_RSAES_OAEP:
            m_scheme = std::unique_ptr<scheme>(new schemes::rsaes_oaep_pke());
            break;
#endif
#ifdef ENABLE_IBE_DLP
        case PKC_IBE_DLP:
            m_scheme = std::unique_ptr<scheme>(new schemes::ibe_dlp());
            break;
#endif
        default:
            throw std::invalid_argument("Unsupported scheme");
    }
}

pkc::~pkc()
{
}

std::unique_ptr<user_ctx> pkc::create_ctx(security_strength_e strength,
                                          cpu_word_size_e size_hint,
                                          bool masking) const
{
    return m_scheme->create_ctx(strength, size_hint, masking);
}

std::unique_ptr<user_ctx> pkc::create_ctx(size_t set,
                                          cpu_word_size_e size_hint,
                                          bool masking) const
{
    return m_scheme->create_ctx(set, size_hint, masking);
}

bool pkc::keygen(std::unique_ptr<user_ctx>& ctx)
{
    return m_scheme->keygen(ctx);
}

bool pkc::set_public_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k)
{
    return m_scheme->set_public_key(ctx, k);
}

bool pkc::get_public_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k)
{
    return m_scheme->get_public_key(ctx, k);
}

bool pkc::set_private_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k)
{
    return m_scheme->set_private_key(ctx, k);
}

bool pkc::get_private_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k)
{
    return m_scheme->get_private_key(ctx, k);
}

size_t pkc::get_msg_len(std::unique_ptr<user_ctx>& ctx) const
{
    return m_scheme->get_msg_len(ctx);
}

bool pkc::sig_sign(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& m,
    phantom_vector<uint8_t>& s)
{
#if defined(ENABLE_SIGNATURE_DILITHIUM) || \
    defined(ENABLE_SIGNATURE_ECDSA)     || \
    defined(ENABLE_SIGNATURE_EDDSA)     || \
    defined(ENABLE_SIGNATURE_FALCON)    || \
    defined(ENABLE_SIGNATURE_RSASSA_PSS)
    signature* sig = reinterpret_cast<signature*>(m_scheme.get());
    if (sig) {
        return sig->sign(ctx, m, s);
    }
#endif
    return false;
}

bool pkc::sig_sign(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& m,
    phantom_vector<uint8_t>& s, const phantom_vector<uint8_t>& c)
{
#if defined(ENABLE_SIGNATURE_DILITHIUM) || \
    defined(ENABLE_SIGNATURE_ECDSA)     || \
    defined(ENABLE_SIGNATURE_EDDSA)     || \
    defined(ENABLE_SIGNATURE_FALCON)    || \
    defined(ENABLE_SIGNATURE_RSASSA_PSS)
    signature* sig = reinterpret_cast<signature*>(m_scheme.get());
    if (sig) {
        return sig->sign(ctx, m, s, c);
    }
#endif
    return false;
}

bool pkc::sig_verify(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& m,
    const phantom_vector<uint8_t>& s)
{
#if defined(ENABLE_SIGNATURE_DILITHIUM) || \
    defined(ENABLE_SIGNATURE_ECDSA)     || \
    defined(ENABLE_SIGNATURE_EDDSA)     || \
    defined(ENABLE_SIGNATURE_FALCON)    || \
    defined(ENABLE_SIGNATURE_RSASSA_PSS)
    signature* sig = reinterpret_cast<signature*>(m_scheme.get());
    if (sig) {
        return sig->verify(ctx, m, s);
    }
#endif
    return false;
}

bool pkc::sig_verify(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& m,
    const phantom_vector<uint8_t>& s, const phantom_vector<uint8_t>& c)
{
#if defined(ENABLE_SIGNATURE_DILITHIUM) || \
    defined(ENABLE_SIGNATURE_ECDSA)     || \
    defined(ENABLE_SIGNATURE_EDDSA)     || \
    defined(ENABLE_SIGNATURE_FALCON)    || \
    defined(ENABLE_SIGNATURE_RSASSA_PSS)
    signature* sig = reinterpret_cast<signature*>(m_scheme.get());
    if (sig) {
        return sig->verify(ctx, m, s, c);
    }
#endif
    return false;
}

bool pkc::pke_encrypt(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t> pt,
    phantom_vector<uint8_t>& ct)
{
#if defined(ENABLE_PKE_KYBER) || defined(ENABLE_PKE_SABER) || defined(ENABLE_PKE_RSAES_OAEP)
    pke* enc = reinterpret_cast<pke*>(m_scheme.get());
    if (enc) {
        return enc->encrypt(ctx, pt, ct);
    }
#endif
    return false;
}

bool pkc::pke_decrypt(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t> ct,
    phantom_vector<uint8_t>& pt)
{
#if defined(ENABLE_PKE_KYBER) || defined(ENABLE_PKE_SABER) || defined(ENABLE_PKE_RSAES_OAEP)
    pke* enc = reinterpret_cast<pke*>(m_scheme.get());
    if (enc) {
        return enc->decrypt(ctx, ct, pt);
    }
#endif
    return false;
}

bool pkc::kem_encapsulate(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& pk,
    phantom_vector<uint8_t>& c, phantom_vector<uint8_t>& key)
{
#if defined(ENABLE_KEM_KYBER) || defined(ENABLE_KEM_SABER)
    kem* key_exchange = reinterpret_cast<kem*>(m_scheme.get());
    if (key_exchange) {
        return key_exchange->encapsulate(ctx, pk, c, key);
    }
#endif
    return false;
}

bool pkc::kem_decapsulate(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& c,
    phantom_vector<uint8_t>& key)
{
#if defined(ENABLE_KEM_KYBER) || defined(ENABLE_KEM_SABER)
    kem* key_exchange = reinterpret_cast<kem*>(m_scheme.get());
    if (key_exchange) {
        return key_exchange->decapsulate(ctx, c, key);
    }
#endif
    return false;
}

bool pkc::key_exchange_setup(std::unique_ptr<user_ctx>& ctx)
{
#if defined(ENABLE_KEY_EXCHANGE_ECDH)
    key_exchange* exchange = reinterpret_cast<key_exchange*>(m_scheme.get());
    if (exchange) {
        return exchange->key_exchange_setup(ctx);
    }
#endif
    return false;
}

bool pkc::key_exchange_init(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& m)
{
#if defined(ENABLE_KEY_EXCHANGE_ECDH)
    key_exchange* exchange = reinterpret_cast<key_exchange*>(m_scheme.get());
    if (exchange) {
        return exchange->key_exchange_init(ctx, m);
    }
#endif
    return false;
}

bool pkc::key_exchange_final(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& m,
    phantom_vector<uint8_t>& shared_key)
{
#if defined(ENABLE_KEY_EXCHANGE_ECDH)
    key_exchange* exchange = reinterpret_cast<key_exchange*>(m_scheme.get());
    if (exchange) {
        return exchange->key_exchange_final(ctx, m, shared_key);
    }
#endif
    return false;
}

bool pkc::ibe_load_user_key(std::unique_ptr<user_ctx>& ctx,
    const phantom_vector<uint8_t>& id, const phantom_vector<uint8_t>& key)
{
#ifdef ENABLE_IBE_DLP
    ibe* id_based_enc = reinterpret_cast<ibe*>(m_scheme.get());
    if (id_based_enc) {
        return id_based_enc->load_user_key(ctx, id, key);
    }
#endif
    return false;
}

bool pkc::ibe_extract(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& id,
    phantom_vector<uint8_t>& key)
{
#ifdef ENABLE_IBE_DLP
    ibe* id_based_enc = reinterpret_cast<ibe*>(m_scheme.get());
    if (id_based_enc) {
        return id_based_enc->extract(ctx, id, key);
    }
#endif
    return false;
}

bool pkc::ibe_encrypt(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& id,
    const phantom_vector<uint8_t>& m, phantom_vector<uint8_t>& c)
{
#ifdef ENABLE_IBE_DLP
    ibe* id_based_enc = reinterpret_cast<ibe*>(m_scheme.get());
    if (id_based_enc) {
        return id_based_enc->encrypt(ctx, id, m, c);
    }
#endif
    return false;
}

bool pkc::ibe_decrypt(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t> c,
    phantom_vector<uint8_t>& m)
{
#ifdef ENABLE_IBE_DLP
    ibe* id_based_enc = reinterpret_cast<ibe*>(m_scheme.get());
    if (id_based_enc) {
        return id_based_enc->decrypt(ctx, c, m);
    }
#endif
    return false;
}



std::unique_ptr<fpe_ctx> format_preserving_encryption::create_ctx(const phantom_vector<uint8_t>& user_key,
    fpe_type_e type, fpe_format_e format, const phantom_vector<uint8_t>& tweak)
{
    return fpe::create_ctx(user_key, type, format, tweak);
}

void format_preserving_encryption::encrypt_str(std::unique_ptr<fpe_ctx>& ctx, std::string& inout)
{
    switch (ctx->format)
    {
        case FPE_ISO8601: fpe::encrypt_iso8601(ctx, inout); break;
        default:          fpe::encrypt_str(ctx, inout);     break;
    }
}

void format_preserving_encryption::encrypt_number(std::unique_ptr<fpe_ctx>& ctx, int& inout, int range)
{
    fpe::encrypt_number(ctx, inout, range);
}

void format_preserving_encryption::encrypt_float(std::unique_ptr<fpe_ctx>& ctx, double& inout, int range, int precision)
{
    fpe::encrypt_float(ctx, inout, range, precision);
}

void format_preserving_encryption::encrypt_str(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<std::string>& inout)
{
    fpe::encrypt_str(ctx, inout);
}

void format_preserving_encryption::encrypt_number(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<int>& inout, int range)
{
    fpe::encrypt_number(ctx, inout, range);
}

void format_preserving_encryption::encrypt_float(std::unique_ptr<fpe_ctx>& ctx,
    phantom_vector<double>& inout, int range, int precision)
{
    fpe::encrypt_float(ctx, inout, range, precision);
}

void format_preserving_encryption::decrypt_str(std::unique_ptr<fpe_ctx>& ctx, std::string& inout)
{
    switch (ctx->format)
    {
        case FPE_ISO8601: fpe::decrypt_iso8601(ctx, inout); break;
        default:          fpe::decrypt_str(ctx, inout);     break;
    }
}

void format_preserving_encryption::decrypt_number(std::unique_ptr<fpe_ctx>& ctx, int& inout, int range)
{
    fpe::decrypt_number(ctx, inout, range);
}

void format_preserving_encryption::decrypt_float(std::unique_ptr<fpe_ctx>& ctx, double& inout, int range, int precision)
{
    fpe::decrypt_float(ctx, inout, range, precision);
}

void format_preserving_encryption::decrypt_str(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<std::string>& inout)
{
    switch (ctx->format)
    {
        case FPE_ISO8601: fpe::decrypt_iso8601(ctx, inout); break;
        default:          fpe::decrypt_str(ctx, inout);     break;
    }
}

void format_preserving_encryption::decrypt_number(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<int>& inout, int range)
{
    fpe::decrypt_number(ctx, inout, range);
}

void format_preserving_encryption::decrypt_float(std::unique_ptr<fpe_ctx>& ctx,
    phantom_vector<double>& inout, int range, int precision)
{
    fpe::decrypt_float(ctx, inout, range, precision);
}


symmetric_key_ctx* symmetric_key_cipher::make(symmetric_key_type_e key_len)
{
    symmetric_key_ctx* obj = nullptr;

    switch (key_len)
    {
        case SYMKEY_AES_128_ENC: obj = aes_encrypt::make(aes_keylen_e::AES_128); break;
        case SYMKEY_AES_192_ENC: obj = aes_encrypt::make(aes_keylen_e::AES_192); break;
        case SYMKEY_AES_256_ENC: obj = aes_encrypt::make(aes_keylen_e::AES_256); break;
        case SYMKEY_AES_128_DEC: obj = aes_decrypt::make(aes_keylen_e::AES_128); break;
        case SYMKEY_AES_192_DEC: obj = aes_decrypt::make(aes_keylen_e::AES_192); break;
        case SYMKEY_AES_256_DEC: obj = aes_decrypt::make(aes_keylen_e::AES_256); break;
#if defined(ENABLE_AES_CTR)
        case SYMKEY_AES_128_CTR: obj = crypto::aes_ctr::make(aes_keylen_e::AES_128); break;
        case SYMKEY_AES_192_CTR: obj = crypto::aes_ctr::make(aes_keylen_e::AES_192); break;
        case SYMKEY_AES_256_CTR: obj = crypto::aes_ctr::make(aes_keylen_e::AES_256); break;
#endif
#if defined(ENABLE_AES_GCM)
        case SYMKEY_AES_128_GCM: obj = crypto::aes_gcm::make(aes_keylen_e::AES_128); break;
        case SYMKEY_AES_192_GCM: obj = crypto::aes_gcm::make(aes_keylen_e::AES_192); break;
        case SYMKEY_AES_256_GCM: obj = crypto::aes_gcm::make(aes_keylen_e::AES_256); break;
#endif
        default: return nullptr;
    }

    obj->set_keylen(key_len);
    return obj;
}

int32_t symmetric_key_cipher::set_key(symmetric_key_ctx* ctx, const uint8_t *key, size_t key_len_bytes)
{
    switch (ctx->get_keylen())
    {
        case SYMKEY_AES_128_ENC: {
            if (key_len_bytes == 16) {
                return reinterpret_cast<aes_encrypt*>(ctx)->set_key(key, AES_128);
            }
        } break;
        case SYMKEY_AES_192_ENC: {
            if (key_len_bytes == 16 || key_len_bytes == 24) {
                return reinterpret_cast<aes_encrypt*>(ctx)->set_key(key, AES_192);
            }
        } break;
        case SYMKEY_AES_256_ENC: {
            if (key_len_bytes == 16 || key_len_bytes == 24 || key_len_bytes == 32) {
                return reinterpret_cast<aes_encrypt*>(ctx)->set_key(key, AES_256);
            }
        } break;
        case SYMKEY_AES_128_DEC: {
            if (key_len_bytes == 16) {
                return reinterpret_cast<aes_decrypt*>(ctx)->set_key(key, AES_128);
            }
        } break;
        case SYMKEY_AES_192_DEC: {
            if (key_len_bytes == 16 || key_len_bytes == 24) {
                return reinterpret_cast<aes_decrypt*>(ctx)->set_key(key, AES_192);
            }
        } break;
        case SYMKEY_AES_256_DEC: {
            if (key_len_bytes == 16 || key_len_bytes == 24 || key_len_bytes == 32) {
                return reinterpret_cast<aes_decrypt*>(ctx)->set_key(key, AES_256);
            }
        } break;
#if defined(ENABLE_AES_CTR)
        case SYMKEY_AES_128_CTR: {
            if (key_len_bytes == 16) {
                return reinterpret_cast<crypto::aes_ctr*>(ctx)->set_key(key, 16);
            }
        } break;
        case SYMKEY_AES_192_CTR: {
            if (key_len_bytes == 24) {
                return reinterpret_cast<crypto::aes_ctr*>(ctx)->set_key(key, 24);
            }
        } break;
        case SYMKEY_AES_256_CTR: {
            if (key_len_bytes == 32) {
                return reinterpret_cast<crypto::aes_ctr*>(ctx)->set_key(key, 32);
            }
        } break;
#endif
#if defined(ENABLE_AES_GCM)
        case SYMKEY_AES_128_GCM: {
            if (key_len_bytes == 16) {
                return reinterpret_cast<crypto::aes_gcm*>(ctx)->set_key(key, 16);
            }
        } break;
        case SYMKEY_AES_192_GCM: {
            if (key_len_bytes == 24) {
                return reinterpret_cast<crypto::aes_gcm*>(ctx)->set_key(key, 24);
            }
        } break;
        case SYMKEY_AES_256_GCM: {
            if (key_len_bytes == 32) {
                return reinterpret_cast<crypto::aes_gcm*>(ctx)->set_key(key, 32);
            }
        } break;
#endif
        default: {}
    }
    return EXIT_FAILURE;
}

int32_t symmetric_key_cipher::encrypt_start(symmetric_key_ctx* ctx, const uint8_t *iv, size_t iv_len,
    const uint8_t *authdata, size_t authdata_len)
{
    switch (ctx->get_keylen())
    {
#if defined(ENABLE_AES_CTR)
        case SYMKEY_AES_128_CTR:
        case SYMKEY_AES_192_CTR:
        case SYMKEY_AES_256_CTR: {
            reinterpret_cast<crypto::aes_ctr*>(ctx)->encrypt_start(iv, iv_len);
        } break;
#endif
#if defined(ENABLE_AES_GCM)
        case SYMKEY_AES_128_GCM:
        case SYMKEY_AES_192_GCM:
        case SYMKEY_AES_256_GCM: {
            reinterpret_cast<crypto::aes_gcm*>(ctx)->encrypt_start(iv, iv_len, authdata, authdata_len);
         } break;
#endif
        default: return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int32_t symmetric_key_cipher::encrypt(symmetric_key_ctx* ctx, uint8_t *out, const uint8_t *in, size_t len)
{
    switch (ctx->get_keylen())
    {
        case SYMKEY_AES_128_ENC:
        case SYMKEY_AES_192_ENC:
        case SYMKEY_AES_256_ENC:
        {
            // We expect the user to perform all padding operations for ECB mode
            if (0 != (len & 0xf)) {
                return EXIT_FAILURE;
            }
            while (len > 0) {
                reinterpret_cast<aes_encrypt*>(ctx)->encrypt(out, in);
                len -= 16;
                in  += 16;
                out += 16;
            }
        } break;
#if defined(ENABLE_AES_CTR)
        case SYMKEY_AES_128_CTR:
        case SYMKEY_AES_192_CTR:
        case SYMKEY_AES_256_CTR:
        {
            reinterpret_cast<crypto::aes_ctr*>(ctx)->encrypt_update(out, in, len);
        } break;
#endif
#if defined(ENABLE_AES_GCM)
        case SYMKEY_AES_128_GCM:
        case SYMKEY_AES_192_GCM:
        case SYMKEY_AES_256_GCM:
        {
            reinterpret_cast<crypto::aes_gcm*>(ctx)->encrypt_update(out, in, len);
        } break;
#endif
        default: return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int32_t symmetric_key_cipher::encrypt_finish(symmetric_key_ctx* ctx, uint8_t *tag, size_t tag_len)
{
    switch (ctx->get_keylen())
    {
#if defined(ENABLE_AES_GCM)
        case SYMKEY_AES_128_GCM:
        case SYMKEY_AES_192_GCM:
        case SYMKEY_AES_256_GCM:
        {
            return reinterpret_cast<crypto::aes_gcm*>(ctx)->encrypt_finish(tag, tag_len);
        } break;
#endif
        default: return EXIT_FAILURE;
    }
}

int32_t symmetric_key_cipher::decrypt_start(symmetric_key_ctx* ctx, const uint8_t *iv, size_t iv_len,
    const uint8_t *authdata, size_t authdata_len)
{
    switch (ctx->get_keylen())
    {
#if defined(ENABLE_AES_CTR)
        case SYMKEY_AES_128_CTR:
        case SYMKEY_AES_192_CTR:
        case SYMKEY_AES_256_CTR: {
            reinterpret_cast<crypto::aes_ctr*>(ctx)->decrypt_start(iv, iv_len);
        } break;
#endif
#if defined(ENABLE_AES_GCM)
        case SYMKEY_AES_128_GCM:
        case SYMKEY_AES_192_GCM:
        case SYMKEY_AES_256_GCM: {
            reinterpret_cast<crypto::aes_gcm*>(ctx)->decrypt_start(iv, iv_len, authdata, authdata_len);
        } break;
#endif
        default:                 return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int32_t symmetric_key_cipher::decrypt(symmetric_key_ctx* ctx, uint8_t *out, const uint8_t *in, size_t len)
{
    switch (ctx->get_keylen())
    {
        case SYMKEY_AES_128_DEC:
        case SYMKEY_AES_192_DEC:
        case SYMKEY_AES_256_DEC:
        {
            if (0 != (len & 0xf)) {
                return EXIT_FAILURE;
            }
            while (len > 0) {
                reinterpret_cast<aes_decrypt*>(ctx)->decrypt(out, in);
                len -= 16;
                in  += 16;
                out += 16;
            }
        } break;
#if defined(ENABLE_AES_CTR)
        case SYMKEY_AES_128_CTR:
        case SYMKEY_AES_192_CTR:
        case SYMKEY_AES_256_CTR:
        {
            reinterpret_cast<crypto::aes_ctr*>(ctx)->decrypt_update(out, in, len);
        } break;
#endif
#if defined(ENABLE_AES_GCM)
        case SYMKEY_AES_128_GCM:
        case SYMKEY_AES_192_GCM:
        case SYMKEY_AES_256_GCM:
        {
            reinterpret_cast<crypto::aes_gcm*>(ctx)->decrypt_update(out, in, len);
        } break;
#endif
        default: return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int32_t symmetric_key_cipher::decrypt_finish(symmetric_key_ctx* ctx, uint8_t *tag, size_t tag_len)
{
    switch (ctx->get_keylen())
    {
#if defined(ENABLE_AES_GCM)
        case SYMKEY_AES_128_GCM:
        case SYMKEY_AES_192_GCM:
        case SYMKEY_AES_256_GCM:
        {
            return reinterpret_cast<crypto::aes_gcm*>(ctx)->decrypt_finish(tag, tag_len);
        } break;
#endif
        default: return EXIT_FAILURE;
    }
}

key_sharing* key_sharing::make(key_sharing_type_e type, size_t key_len, std::shared_ptr<csprng>& prng)
{
    key_sharing* ctx = nullptr;

    switch (type)
    {
#if defined(ENABLE_SHAMIRS_SECRET_SHARING)
        case KEY_SHARING_SHAMIRS: ctx = new shamirs_secret_sharing(prng); break;
#endif
        default: {};
    }

    return ctx;
}


}  // namespace phantom
