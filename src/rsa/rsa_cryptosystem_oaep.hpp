/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include "rsa/rsa_cryptosystem.hpp"
#include "rsa/ctx_rsa.hpp"


namespace phantom {
namespace rsa {


/// A class providing an RSA PKE implementation
template<typename T>
class rsa_cryptosystem_oaep : public rsa_cryptosystem<T>
{
public:
    /// Class constructor
    rsa_cryptosystem_oaep()
    {
    }

    /// Class destructor
    virtual ~rsa_cryptosystem_oaep() {}

    bool rsaes_oaep_encrypt(ctx_rsa_tmpl<T>& ctx, const phantom_vector<uint8_t> pt,
        phantom_vector<uint8_t>& ct)
    {
        const size_t k = (ctx.n().sizeinbase(2) + 7) >> 3;
        const size_t hlen = ctx.get_hlen();
        const phantom_vector<uint8_t>& l = ctx.get_label();

        // Length checking (we impose a 2^16 byte length limitation for L)
        if (l.size() > 0x10000) {
            std::cout << "label too long" << std::endl;
            return false;
        }
        if (k < (2*hlen + 2)) {
            std::cout << "hash length is too large" << std::endl;
            return false;
        }
        if (pt.size() > (k - 2*hlen - 2)) {
            std::cout << "message too long" << std::endl;
            return false;
        }

        // EME-OAEP encoding
        phantom_vector<uint8_t> lhash;
        lhash.resize(hlen);
        ctx.get_hash()->init(ctx.get_hblocklen());
        ctx.get_hash()->update(l.data(), l.size());
        ctx.get_hash()->final(lhash.data());

        // Create a padding string and generate the datablock lHash || PS || 0x01 || M
        size_t pslen = k - pt.size() - 2*hlen - 2;
        size_t dblen = k - hlen - 1;
        phantom_vector<uint8_t> ps, db;
        ps.resize(pslen);
        db.insert(db.end(), lhash.begin(), lhash.end());
        db.insert(db.end(), ps.begin(), ps.end());
        db.push_back(0x01);
        db.insert(db.end(), pt.begin(), pt.end());

        // Generate a random octet string seed of length hLen
        phantom_vector<uint8_t> seed, dbmask, maskeddb, seedmask, maskedseed, em;
        seed.resize(hlen);
        this->m_prng->get_mem(seed.data(), hlen);

        // dbMask = MGF(seed, k - hLen - 1)
        if (!this->mgf1(ctx.get_hash(), dbmask, ctx.get_hblocklen(), hlen, seed, k - hlen - 1)) {
            std::cout << "MGF(seed, k - hLen - 1) failed" << std::endl;
            return false;
        }

        // maskedDB = DB XOR dbMask
        maskeddb.resize(k - hlen - 1);
        for (size_t i=0; i < k - hlen - 1; i++) {
            maskeddb[i] = db[i] ^ dbmask[i];
        }

        // seedMask = MGF(maskedDB, hLen)
        if (!this->mgf1(ctx.get_hash(), seedmask, ctx.get_hblocklen(), hlen, maskeddb, k - hlen - 1)) {
            std::cout << "MGF(maskedDB, hLen) failed" << std::endl;
            return false;
        }

        // maskedSeed = seed XOR seedMask
        maskedseed.resize(hlen);
        for (size_t i=0; i < hlen; i++) {
            maskedseed[i] = seed[i] ^ seedmask[i];
        }

        // EM = 0x00 || maskedSeed || maskedDB
        em.push_back(0x00);
        em.insert(em.end(), maskedseed.begin(), maskedseed.end());
        em.insert(em.end(), maskeddb.begin(), maskeddb.end());

        // m = OS2IP(EM)
        core::mpz<T> m;
        this->os2ip(m, em);
        if (m >= ctx.n()) {
            std::cout << "Ciphertext is too large" << std::endl;
            return false;
        }

        // c = RSAEP((n, e), m)
        core::mpz<T> c;
        if (!this->rsa_public_exponentiation(ctx, m, c)) {
            return false;
        }

        // C = I2OSP(c, k)
        this->i2osp(ct, c, k);

        return true;
    }

    bool rsaes_oaep_decrypt(ctx_rsa_tmpl<T>& ctx, const phantom_vector<uint8_t> ct,
        phantom_vector<uint8_t>& pt)
    {
        const size_t k = (ctx.n().sizeinbase(2) + 7) >> 3;
        const size_t hlen = ctx.get_hlen();
        const phantom_vector<uint8_t>& l = ctx.get_label();

        // Length checking (we impose a 2^60 byte length limitation for L)
        if (l.size() > 0x1000000000000000ULL) {
            std::cout << "Label is too long" << std::endl;
            return false;
        }
        if (ct.size() != k) {
            std::cout << "ciphertext length != k" << std::endl;
            return false;
        }
        if (k < (2*hlen + 2)) {
            std::cout << "k < (2*hlen+2)" << std::endl;
            return false;
        }

        // c = OS2IP(C)
        core::mpz<T> c;
        this->os2ip(c, ct);
        if (c >= ctx.n()) {
            std::cout << "c >= n" << std::endl;
            return false;
        }

        // m = RSADP(K, c)
        core::mpz<T> m;
        if (!this->rsa_private_exponentiation(ctx, c, m)) {
            std::cout << "Exponentiation failed" << std::endl;
            return false;
        }

        // EM = I2OSP(m, k)
        phantom_vector<uint8_t> em;
        this->i2osp(em, m, k);

        // EME-OAEP encoding
        phantom_vector<uint8_t> lhash;
        lhash.resize(hlen);
        ctx.get_hash()->init(ctx.get_hblocklen());
        ctx.get_hash()->update(l.data(), l.size());
        ctx.get_hash()->final(lhash.data());

        // Separate EM such that EM = Y || maskedSeed || maskedDB
        const uint8_t Y = em[0];

        phantom_vector<uint8_t> seed, dbmask, maskeddb, seedmask, maskedseed, db;
        maskedseed.insert(maskedseed.end(), em.begin() + 1, em.begin() + 1 + hlen);
        maskeddb.insert(maskeddb.end(), em.begin() + 1 + hlen, em.end());

        // seedMask = MGF(maskedDB, hLen)
        if (!this->mgf1(ctx.get_hash(), seedmask, ctx.get_hblocklen(), hlen, maskeddb, k - hlen - 1)) {
            std::cout << "MGF(maskedSeed, hLen) failed" << std::endl;
            return false;
        }

        // seed = maskedSeed XOR seedMask
        seed.resize(hlen);
        for (size_t i=0; i < hlen; i++) {
            seed[i] = maskedseed[i] ^ seedmask[i];
        }

        // dbMask = MGF(seed, k - hLen - 1)
        if (!this->mgf1(ctx.get_hash(), dbmask, ctx.get_hblocklen(), hlen, seed, k - hlen - 1)) {
            std::cout << "MGF(seed, k - hLen - 1) failed" << std::endl;
            return false;
        }

        // maskedDB = DB XOR dbMask
        db.resize(k - hlen - 1);
        for (size_t i=0; i < k - hlen - 1; i++) {
            db[i] = maskeddb[i] ^ dbmask[i];
        }

        // Separate DB
        phantom_vector<uint8_t> lhash2;
        lhash2.insert(lhash2.begin(), db.begin(), db.begin() + hlen);
        size_t offset = hlen;
        while (0 == db[offset]) {
            offset++;
        }
        const uint8_t marker_one = db[offset++];
        pt.resize(0);
        pt.insert(pt.begin(), db.begin() + offset, db.end());

        uint8_t failure = 0;
        if (0 != Y) {
            failure = 0xff;
        }
        if (1 != marker_one) {
            failure = 0xff;
        }
        for (size_t i=0; i < hlen; i++) {
            failure |= lhash[i] ^ lhash2[i];
        }

        return 0 == failure;
    }
};

}  // namespace rsa
}  // namespace phantom
