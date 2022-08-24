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
class rsa_cryptosystem_rsassa_pss : public rsa_cryptosystem<T>
{
public:
    /// Class constructor
    rsa_cryptosystem_rsassa_pss()
    {
    }

    /// Class destructor
    virtual ~rsa_cryptosystem_rsassa_pss() {}

    bool rsassa_pss_sign(ctx_rsa_tmpl<T>& ctx, const phantom_vector<uint8_t>& M, phantom_vector<uint8_t>& S)
    {
        const size_t k = (ctx.n().sizeinbase(2) + 7) >> 3;

        // EM = EMSA-PSS-ENCODE(M, modBits - 1)
        phantom_vector<uint8_t> EM;
        if (!emsa_pss_encode(ctx.get_hash(), ctx.get_hblocklen(), ctx.get_hlen(), ctx.get_saltlen(),
            EM, M, ctx.n().sizeinbase(2) - 1)) {
            std::cout << "emsa_pss_encode() failed" << std::endl;
            return false;
        }

        // m = OS2IP(EM)
        core::mpz<T> m;
        this->os2ip(m, EM);
        if (m >= ctx.n()) {
            std::cout << "m is not mod n" << std::endl;
            return false;
        }

        // s = RSASP1(K, m)
        core::mpz<T> s;
        if (!this->rsa_private_exponentiation(ctx, m, s)) {
            std::cout << "RSASP1 failed" << std::endl;
            return false;
        }

        // S = I2OSP(s, k)
        this->i2osp(S, s, k);

        return true;
    }

    bool rsassa_pss_verify(ctx_rsa_tmpl<T>& ctx, const phantom_vector<uint8_t>& M, const phantom_vector<uint8_t>& S)
    {
        size_t k = (ctx.n().sizeinbase(2) + 7) >> 3;

        // s = OS2IP (S)
        core::mpz<T> s;
        this->os2ip(s, S);
        if (s >= ctx.n()) {
            return false;
        }

        // m = RSAVP1 ((n, e), s)
        core::mpz<T> m;
        if (!this->rsa_public_exponentiation(ctx, s, m)) {
            return false;
        }

        // EM = I2OSP (m, emLen)
        phantom_vector<uint8_t> EM;
        this->i2osp(EM, m, k);

        // EM = EMSA-PSS-ENCODE(M, modBits - 1)
        return emsa_pss_verify(ctx.get_hash(), ctx.get_hblocklen(), ctx.get_hlen(), ctx.get_saltlen(),
            EM, M, ctx.n().sizeinbase(2) - 1);
    }

private:

    bool emsa_pss_encode(crypto::hash* h, size_t hblocklen, size_t hlen, size_t slen, phantom_vector<uint8_t>& EM,
        const phantom_vector<uint8_t>& M, size_t bits)
    {
        size_t emlen = (bits + 7) >> 3;

        // Length checking (we impose a 2^60 byte length limitation for M)
        if (M.size() > 0x1000000000000000ULL) {
            std::cout << "label too long" << std::endl;
            return false;
        }

        // Let mHash = Hash(M), an octet string of length hLen
        phantom_vector<uint8_t> mhash;
        mhash.resize(hlen);
        h->init(hblocklen);
        h->update(M.data(), M.size());
        h->final(mhash.data());

        // If emLen < hLen + sLen + 2, output "encoding error" and stop
        if (emlen < (hlen + slen + 2)) {
            std::cout << "encoding error" << std::endl;
            return false;
        }

        // Generate a random octet string salt of length sLen
        phantom_vector<uint8_t> salt;
        salt.resize(slen);
        this->m_prng->get_mem(salt.data(), slen);

        // M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
        phantom_vector<uint8_t> M2;
        M2.resize(8);
        M2.insert(M2.end(), mhash.begin(), mhash.end());
        M2.insert(M2.end(), salt.begin(), salt.end());

        // H = Hash(M')
        phantom_vector<uint8_t> H;
        H.resize(hlen);
        h->init(hblocklen);
        h->update(M2.data(), M2.size());
        h->final(H.data());

        // Generate an octet string PS consisting of emLen - sLen - hLen - 2 octets
        // Let DB = PS || 0x01 || salt; DB is an octet string of length emLen - hLen - 1
        phantom_vector<uint8_t> DB;
        DB.resize(emlen - slen - hlen - 2);  // PS
        DB.push_back(0x01);
        DB.insert(DB.end(), salt.begin(), salt.end());

        // dbMask = MGF(H, emLen - hLen - 1)
        phantom_vector<uint8_t> dbmask;
        if (!this->mgf1(h, dbmask, hblocklen, hlen, H, emlen - hlen - 1)) {
            std::cout << "MGF(seed, k - hLen - 1) failed" << std::endl;
            return false;
        }

        // maskedDB = DB XOR dbMask
        phantom_vector<uint8_t> maskeddb;
        maskeddb.resize(emlen - hlen - 1);
        for (size_t i=0; i < emlen - hlen - 1; i++) {
            maskeddb[i] = DB[i] ^ dbmask[i];
        }

        // Set the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB to zero
        maskeddb[0] &= (1UL << (8*emlen - bits)) - 1;

        // Let EM = maskedDB || H || 0xbc
        EM.resize(0);
        EM.insert(EM.end(), maskeddb.begin(), maskeddb.end());
        EM.insert(EM.end(), H.begin(), H.end());
        EM.push_back(0xbc);

        return true;
    }

    bool emsa_pss_verify(crypto::hash* h, size_t hblocklen, size_t hlen, size_t slen, phantom_vector<uint8_t>& EM,
        const phantom_vector<uint8_t>& M, size_t bits)
    {
        size_t emlen = (bits + 7) >> 3;

        // Length checking (we impose a 2^60 byte length limitation for M)
        if (M.size() > 0x1000000000000000ULL) {
            std::cout << "label too long" << std::endl;
            return false;
        }

        // Let mHash = Hash(M), an octet string of length hLen
        phantom_vector<uint8_t> mhash;
        mhash.resize(hlen);
        h->init(hblocklen);
        h->update(M.data(), M.size());
        h->final(mhash.data());

        // If emLen < hLen + sLen + 2, output "encoding error" and stop
        if (emlen < (hlen + slen + 2)) {
            std::cout << "encoding error" << std::endl;
            return false;
        }

        // If the rightmost octet of EM does not have hexadecimal value
        // 0xbc, output "inconsistent" and stop
        if (0xbc != EM[EM.size() - 1]) {
            std::cout << "inconsistent" << std::endl;
            return false;
        }

        // Let maskedDB be the leftmost emLen - hLen - 1 octets of EM,
        // and let H be the next hLen octets
        phantom_vector<uint8_t> maskeddb, H;
        maskeddb.insert(maskeddb.end(), EM.begin(), EM.begin() + emlen - hlen - 1);
        H.insert(H.end(), EM.begin() + emlen - hlen - 1, EM.begin() + emlen - 1);

        // If the leftmost 8emLen - emBits bits of the leftmost octet in
        // maskedDB are not all equal to zero, output "inconsistent" and stop
        if (0 != (maskeddb[0] & ~((1UL << (8*emlen - bits)) - 1))) {
            std::cout << "inconsistent 2" << std::endl;
            return false;
        }

        // dbMask = MGF(H, emLen - hLen - 1)
        phantom_vector<uint8_t> dbmask;
        if (!this->mgf1(h, dbmask, hblocklen, hlen, H, emlen - hlen - 1)) {
            std::cout << "MGF(H, emLen - hLen - 1) failed" << std::endl;
            return false;
        }

        // DB = maskedDB XOR dbMask
        phantom_vector<uint8_t> DB;
        DB.resize(emlen - hlen - 1);
        for (size_t i=0; i < emlen - hlen - 1; i++) {
            DB[i] = maskeddb[i] ^ dbmask[i];
        }

        // Set the leftmost 8emLen - emBits bits of the leftmost octet in DB to zero
        size_t zero_bits = 8*emlen - bits;
        DB[0] &= (1UL << (8*emlen - bits)) - 1;

        // If the emLen - hLen - sLen - 2 leftmost octets of DB are not
        // zero or if the octet at position emLen - hLen - sLen - 1 (the
        // leftmost position is "position 1") does not have hexadecimal
        // value 0x01, output "inconsistent" and stop
        uint8_t failure = 0;
        if (0x01 != DB[emlen - hlen - slen - 2]) {
            failure = 0xff;
        }
        if (failure) {
            std::cout << "inconsistent 3" << std::endl;
            return false;
        }
        for (size_t i=0; i < emlen - hlen - slen - 2; i++) {
            failure |= DB[i];
        }
        if (failure) {
            std::cout << "inconsistent 4" << std::endl;
            return false;
        }

        // Let salt be the last sLen octets of DB
        // M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
        phantom_vector<uint8_t> M2;
        M2.resize(8);
        M2.insert(M2.end(), mhash.begin(), mhash.end());
        M2.insert(M2.end(), DB.end() - slen, DB.end());

        // Let H' = Hash(M'), an octet string of length hLen
        phantom_vector<uint8_t> H2;
        H2.resize(hlen);
        h->init(hblocklen);
        h->update(M2.data(), M2.size());
        h->final(H2.data());

        // Check if H = H'
        failure = 0;
        for (size_t i=0; i < hlen; i++) {
            failure |= H[i] ^ H2[i];
        }

        return 0 == failure;
    }
};

}  // namespace rsa
}  // namespace phantom
