/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "schemes/kem/saber/saber_kem.hpp"
#include "sampling/uniform_sampler.hpp"
#include "logging/logger.hpp"
#include "core/poly.hpp"
#include "packing/packer.hpp"
#include "packing/unpacker.hpp"
#include "packing/stream.hpp"
#include "crypto/hash_sha3.hpp"


namespace phantom {
namespace schemes {

saber_kem::saber_kem()
{
}

saber_kem::~saber_kem()
{
}

std::unique_ptr<user_ctx> saber_kem::create_ctx(security_strength_e bits,
                                                cpu_word_size_e size_hint,
                                                bool masking) const
{
    return create_ctx(saber_indcpa::bits_2_set(bits), size_hint, masking);
}

std::unique_ptr<user_ctx> saber_kem::create_ctx(size_t set,
                                                cpu_word_size_e size_hint,
                                                bool masking) const
{
    ctx_saber* ctx = new ctx_saber(set);
    std::stringstream ss;

    if (ctx->get_set() > 2) {
        ss << "Parameter set " << ctx->get_set() << " is out of range";
        LOG_ERROR(ss.str(), g_pkc_log_level);
        throw std::invalid_argument(ss.str());
    }

    ss << "SABER KEM context created [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);
    return std::unique_ptr<user_ctx>(ctx);
}

bool saber_kem::keygen(std::unique_ptr<user_ctx>& ctx)
{
    std::stringstream ss;
    ss << "SABER KEM KeyGen [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_saber& myctx = dynamic_cast<ctx_saber&>(*ctx.get());

    // Generate a key pair for the underlying Saber IND-CPA PKE
    myctx.pke()->keygen(myctx.pk(), myctx.sk());

    // Generate a random 256-bit number
    myctx.pke()->get_prng()->get_mem(myctx.z(), 32);

    // SHA3-256 hash of the public key
    myctx.pkh() = phantom_vector<uint8_t>(32);
    myctx.get_hash()->init(256);
    myctx.get_hash()->update(myctx.pk().data(), myctx.pk().size());
    myctx.get_hash()->final(myctx.pkh().data());

    return true;
}

bool saber_kem::set_public_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k)
{
    std::stringstream ss;
    ss << "SABER KEM set public key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_saber& myctx = dynamic_cast<ctx_saber&>(*ctx.get());

    size_t   l        = saber_indcpa::m_params[myctx.get_set()].l;
    size_t   ep       = saber_indcpa::m_params[myctx.get_set()].ep;

    myctx.pk() = phantom_vector<uint8_t>(l * ep * (SABER_N/8) + 32);

    packing::unpacker up(k);
    for (size_t i = 0; i < l * ep * (SABER_N/8) + 32; i++) {
        myctx.pk()[i] = up.read_unsigned(8, packing::RAW);
    }

    return true;
}

bool saber_kem::get_public_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k)
{
    std::stringstream ss;
    ss << "SABER KEM get public key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_saber& myctx = dynamic_cast<ctx_saber&>(*ctx.get());

    size_t   l        = saber_indcpa::m_params[myctx.get_set()].l;
    size_t   ep       = saber_indcpa::m_params[myctx.get_set()].ep;

    k.clear();

    packing::packer pack((l * ep * (SABER_N/8) + 32) * 8);
    for (size_t i = 0; i < l * ep * (SABER_N/8) + 32; i++) {
        pack.write_unsigned(myctx.pk()[i], 8, packing::RAW);
    }

    pack.flush();
    k = pack.get();

    return true;
}

bool saber_kem::set_private_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k)
{
    std::stringstream ss;
    ss << "SABER KEM set set_private_key key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_saber& myctx = dynamic_cast<ctx_saber&>(*ctx.get());

    size_t   l        = saber_indcpa::m_params[myctx.get_set()].l;
    size_t   eq       = saber_indcpa::m_params[myctx.get_set()].eq;

    myctx.sk()  = phantom_vector<uint8_t>(l * eq * (SABER_N/8));
    myctx.pkh() = phantom_vector<uint8_t>(32);

    packing::unpacker up(k);
    for (size_t i = 0; i < l * eq * (SABER_N/8); i++) {
        myctx.sk()[i] = up.read_unsigned(8, packing::RAW);
    }
    for (size_t i = 0; i < 32; i++) {
        myctx.z()[i] = up.read_unsigned(8, packing::RAW);
    }
    for (size_t i = 0; i < 32; i++) {
        myctx.pkh()[i] = up.read_unsigned(8, packing::RAW);
    }

    return true;
}

bool saber_kem::get_private_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k)
{
    std::stringstream ss;
    ss << "SABER KEM get set_private_key key [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_saber& myctx = dynamic_cast<ctx_saber&>(*ctx.get());

    size_t   l        = saber_indcpa::m_params[myctx.get_set()].l;
    size_t   eq       = saber_indcpa::m_params[myctx.get_set()].eq;

    k.clear();

    packing::packer pack((l * eq * (SABER_N/8) + 32 + 32) * 8);
    for (size_t i = 0; i < l * eq * (SABER_N/8); i++) {
        pack.write_unsigned(myctx.sk()[i], 8, packing::RAW);
    }
    for (size_t i = 0; i < 32; i++) {
        pack.write_unsigned(myctx.z()[i], 8, packing::RAW);
    }
    for (size_t i = 0; i < 32; i++) {
        pack.write_unsigned(myctx.pkh()[i], 8, packing::RAW);
    }

    pack.flush();
    k = pack.get();

    return true;
}

bool saber_kem::encapsulate(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& pk,
    phantom_vector<uint8_t>& c, phantom_vector<uint8_t>& key)
{
    std::stringstream ss;
    ss << "SABER KEM Encapsulation [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_saber& myctx = dynamic_cast<ctx_saber&>(*ctx.get());

    phantom_vector<uint8_t> kr(64);
    phantom_vector<uint8_t> buf(64);

    // Generate 256 random bits to form the key basis
    myctx.pke()->get_prng()->get_mem(buf.data(), 32);

    // Hash the random key using SHA3-256
    myctx.get_hash()->init(256);
    myctx.get_hash()->update(buf.data(), 32);
    myctx.get_hash()->final(buf.data());

    // Hash the public key using SHA3-256
    myctx.get_hash()->init(256);
    myctx.get_hash()->update(pk.data(), pk.size());
    myctx.get_hash()->final(buf.data() + 32);

    // Hash the concatenated hashes of the random key and the public key using SHA3-512
    myctx.get_hash()->init(512);
    myctx.get_hash()->update(buf.data(), 64);
    myctx.get_hash()->final(kr.data());

    // Encrypt the random key using the most significant 256 bits of the SHA3-512 hash
    phantom_vector<uint8_t> pk_vec(pk.begin(), pk.end());
    phantom_vector<uint8_t> ct;
    myctx.pke()->enc(pk_vec, buf, kr.data() + 32, ct);
    c = phantom_vector<uint8_t>(ct.begin(), ct.end());

    // Hash of the ciphertext using SHA3-256
    myctx.get_hash()->init(256);
    myctx.get_hash()->update(ct.data(), ct.size());
    myctx.get_hash()->final(kr.data() + 32);

    // Hash of the concatenated components using SHA3-256 to form the key
    key = phantom_vector<uint8_t>(32);
    myctx.get_hash()->init(256);
    myctx.get_hash()->update(kr.data(), 64);
    myctx.get_hash()->final(key.data());

    return true;
}

bool saber_kem::decapsulate(std::unique_ptr<user_ctx>& ctx,
                            const phantom_vector<uint8_t>& c,
                            phantom_vector<uint8_t>& key)
{
    std::stringstream ss;
    ss << "SABER KEM Decapsulation [" << ctx->get_uuid() << "]";
    LOG_DEBUG(ss.str(), g_pkc_log_level);

    ctx_saber& myctx = dynamic_cast<ctx_saber&>(*ctx.get());

    phantom_vector<uint8_t> buf(64);
    phantom_vector<uint8_t> kr(64);
    phantom_vector<uint8_t> ct(c.begin(), c.end());

    // Use the private key to decrypt the ciphertext and obtain the key basis
    myctx.pke()->dec(myctx.sk(), ct, buf.data());

    // Hash the concatenated key and public key hash using SHA3-512
    for (size_t i = 0; i < 32; i++) {
        buf[32 + i] = myctx.pkh()[i];
    }
    myctx.get_hash()->init(512);
    myctx.get_hash()->update(buf.data(), 64);
    myctx.get_hash()->final(kr.data());

    // Encrypt the hash using the seed from the SHA3-512 hash
    phantom_vector<uint8_t> cmp;
    myctx.pke()->enc(myctx.pk(), buf, kr.data() + 32, cmp);

    // Verify that the input and generated ciphertext are identical - check if they are not
    // equal and return 1 if so. Replace the hash output with the random key if they do not match.
    uint8_t fail = const_time<uint8_t>::cmp_array_not_equal(c.data(), cmp.data(), cmp.size());
    fail = -fail;
    for (size_t i = 0; i < 32; i++) {
        kr[i] ^= fail & (myctx.z()[i] ^ kr[i]);
    }

    // Hash the ciphertext using SHA3-256
    myctx.get_hash()->init(256);
    myctx.get_hash()->update(ct.data(), ct.size());
    myctx.get_hash()->final(kr.data() + 32);

    // Hash of the concatenated components using SHA3-256 to form the key
    key = phantom_vector<uint8_t>(32);
    myctx.get_hash()->init(256);
    myctx.get_hash()->update(kr.data(), 64);
    myctx.get_hash()->final(key.data());

    return true;
}

size_t saber_kem::get_msg_len(const std::unique_ptr<user_ctx>& ctx) const
{
    return SABRE_MSG_LEN;
}

}  // namespace schemes
}  // namespace phantom
