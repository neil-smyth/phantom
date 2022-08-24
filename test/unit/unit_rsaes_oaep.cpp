/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include <iostream>
#include <memory>
#include "./lest.hpp"
#include "schemes/pke/rsaes_oaep/rsaes_oaep_pke.hpp"
#include "core/mpz.hpp"
#include <nlohmann/json.hpp>

namespace phantom {
using namespace core;           // NOLINT
using namespace schemes;        // NOLINT
using json = nlohmann::json;


const lest::test specification[] =
{
    CASE("RSA public key get and set - 32-bit")
    {
        rsaes_oaep_pke uut;
        std::unique_ptr<user_ctx> ctx = uut.create_ctx(0, CPU_WORD_SIZE_32);

        mpz<uint32_t> n("123456789abcdef", 16);
        mpz<uint32_t> e("fedcba9876543210", 16);

        json pubkey = {
            {"n", n.get_str(16)},
            {"e", e.get_str(16)}
        };
        std::string jstr = pubkey.dump();
        const char* key = jstr.c_str();
        phantom_vector<uint8_t> k(key, key + jstr.length());

        bool result;
        result = uut.set_public_key(ctx, k);
        EXPECT(true == result);

        phantom_vector<uint8_t> k2;
        result = uut.get_public_key(ctx, k2);

        std::string jstr2 = std::string(k2.begin(), k2.end());
        auto json2 = json::parse(jstr2);

        EXPECT(json2["n"].get<std::string>() == n.get_str(16));
        EXPECT(json2["e"].get<std::string>() == e.get_str(16));
    },
    CASE("RSA private key get and set - 32-bit")
    {
        rsaes_oaep_pke uut;
        std::unique_ptr<user_ctx> ctx = uut.create_ctx(0, CPU_WORD_SIZE_32);

        mpz<uint32_t> n("123456789abcdef", 16);
        mpz<uint32_t> e("fedcba9876543210", 16);
        mpz<uint32_t> d("fedcba9876543210", 16);
        mpz<uint32_t> p("fedcba9876543210", 16);
        mpz<uint32_t> q("fedcba9876543210", 16);
        mpz<uint32_t> exp1("fedcba9876543210", 16);
        mpz<uint32_t> exp2("fedcba9876543210", 16);
        mpz<uint32_t> inv("fedcba9876543210", 16);

        json privkey = {
            {"n", n.get_str(16)},
            {"e", e.get_str(16)},
            {"d", d.get_str(16)},
            {"p", p.get_str(16)},
            {"q", q.get_str(16)},
            {"exp1", exp1.get_str(16)},
            {"exp2", exp2.get_str(16)},
            {"inv", inv.get_str(16)}
        };

        std::string jstr = privkey.dump();
        const char* key = jstr.c_str();
        phantom_vector<uint8_t> k(key, key + jstr.length());

        bool result;
        result = uut.set_private_key(ctx, k);
        EXPECT(true == result);

        phantom_vector<uint8_t> k2;
        result = uut.get_private_key(ctx, k2);
        EXPECT(true == result);

        std::string jstr2 = std::string(k2.begin(), k2.end());
        auto json2 = json::parse(jstr2);

        EXPECT(json2["n"].get<std::string>() == n.get_str(16));
        EXPECT(json2["e"].get<std::string>() == e.get_str(16));
        EXPECT(json2["d"].get<std::string>() == d.get_str(16));
        EXPECT(json2["p"].get<std::string>() == p.get_str(16));
        EXPECT(json2["q"].get<std::string>() == q.get_str(16));
        EXPECT(json2["exp1"].get<std::string>() == exp1.get_str(16));
        EXPECT(json2["exp2"].get<std::string>() == exp2.get_str(16));
        EXPECT(json2["inv"].get<std::string>() == inv.get_str(16));
    },
    CASE("RSA keygen - 32-bit")
    {
        rsaes_oaep_pke uut;
        std::unique_ptr<user_ctx> ctx = uut.create_ctx(0, CPU_WORD_SIZE_32);

        bool success = uut.keygen(ctx);
        EXPECT(success == true);

        phantom_vector<uint8_t> k;
        success = uut.get_private_key(ctx, k);
        EXPECT(success == true);

        std::string jstr = std::string(k.begin(), k.end());
        auto json = json::parse(jstr);

        mpz<uint32_t> e(json["e"].get<std::string>().c_str(), 16);
        mpz<uint32_t> d(json["d"].get<std::string>().c_str(), 16);
        mpz<uint32_t> p(json["p"].get<std::string>().c_str(), 16);
        mpz<uint32_t> q(json["q"].get<std::string>().c_str(), 16);
        mpz<uint32_t> theta, g, inv, dummy;
        theta = (p-uint32_t(1))*(q-uint32_t(1));
        g = theta.gcd(d * e);
        EXPECT(g.get_str(16) == "1");
    },
#if defined(IS_64BIT)
    CASE("RSA encryption & decryption (512-bit) - 64-bit")
    {
        rsaes_oaep_pke uut;
        std::unique_ptr<user_ctx> ctx = uut.create_ctx(0, CPU_WORD_SIZE_64);
        bool success = uut.keygen(ctx);
        EXPECT(success == true);

        phantom_vector<uint8_t> pt(6), ct, rt;
        for (size_t i=0; i < 6; i++) {
            pt[i] = 5 - i;
        }
        bool code = uut.encrypt(ctx, pt, ct);
        EXPECT(code == true);

        std::cout << "ct = ";
        for (size_t i=0; i < ct.size(); i++) {
            std::cout << std::hex <<std::setw(2) << std::setfill('0') << static_cast<int>(ct[i]);
        }
        std::cout << std::dec << std::endl;

        code = uut.decrypt(ctx, ct, rt);
        EXPECT(code == true);

        std::cout << "rt = ";
        EXPECT(rt.size() == pt.size());
        for (size_t i=0; i < pt.size(); i++) {
            EXPECT(rt[i] == pt[i]);
            std::cout << std::hex <<std::setw(2) << std::setfill('0') << static_cast<int>(rt[i]);
        }
        std::cout << std::dec << std::endl;
    },
    CASE("RSA encryption & decryption (1024-bit) - 64-bit")
    {
        rsaes_oaep_pke uut;
        std::unique_ptr<user_ctx> ctx = uut.create_ctx(1, CPU_WORD_SIZE_64);
        bool success = uut.keygen(ctx);
        EXPECT(success == true);

        phantom_vector<uint8_t> pt(70), ct, rt;
        for (size_t i=0; i < 70; i++) {
            pt[i] = (69 - i) & 0xff;
        }
        bool code = uut.encrypt(ctx, pt, ct);
        EXPECT(code == true);

        std::cout << "ct = ";
        for (size_t i=0; i < ct.size(); i++) {
            std::cout << std::hex <<std::setw(2) << std::setfill('0') << static_cast<int>(ct[i]);
        }
        std::cout << std::dec << std::endl;

        code = uut.decrypt(ctx, ct, rt);
        EXPECT(code == true);

        std::cout << "rt = ";
        EXPECT(rt.size() == pt.size());
        for (size_t i=0; i < pt.size(); i++) {
            EXPECT(rt[i] == pt[i]);
            std::cout << std::hex <<std::setw(2) << std::setfill('0') << static_cast<int>(rt[i]);
        }
        std::cout << std::dec << std::endl;
    },
    CASE("RSA encryption & decryption (1536-bit) - 64-bit")
    {
        rsaes_oaep_pke uut;
        std::unique_ptr<user_ctx> ctx = uut.create_ctx(2, CPU_WORD_SIZE_64);
        bool success = uut.keygen(ctx);
        EXPECT(success == true);

        phantom_vector<uint8_t> pt(134), ct, rt;
        for (size_t i=0; i < 134; i++) {
            pt[i] = (133 - i) & 0xff;
        }
        bool code = uut.encrypt(ctx, pt, ct);
        EXPECT(code == true);

        std::cout << "ct = ";
        for (size_t i=0; i < ct.size(); i++) {
            std::cout << std::hex <<std::setw(2) << std::setfill('0') << static_cast<int>(ct[i]);
        }
        std::cout << std::dec << std::endl;

        code = uut.decrypt(ctx, ct, rt);
        EXPECT(code == true);

        std::cout << "rt = ";
        EXPECT(rt.size() == pt.size());
        for (size_t i=0; i < pt.size(); i++) {
            EXPECT(rt[i] == pt[i]);
            std::cout << std::hex <<std::setw(2) << std::setfill('0') << static_cast<int>(rt[i]);
        }
        std::cout << std::dec << std::endl;
    },
    CASE("RSA encryption & decryption (2048-bit) - 64-bit")
    {
        rsaes_oaep_pke uut;
        std::unique_ptr<user_ctx> ctx = uut.create_ctx(3, CPU_WORD_SIZE_64);
        bool success = uut.keygen(ctx);
        EXPECT(success == true);

        phantom_vector<uint8_t> pt(198), ct, rt;
        for (size_t i=0; i < 198; i++) {
            pt[i] = (197 - i) & 0xff;
        }
        bool code = uut.encrypt(ctx, pt, ct);
        EXPECT(code == true);

        std::cout << "ct = ";
        for (size_t i=0; i < ct.size(); i++) {
            std::cout << std::hex <<std::setw(2) << std::setfill('0') << static_cast<int>(ct[i]);
        }
        std::cout << std::dec << std::endl;

        code = uut.decrypt(ctx, ct, rt);
        EXPECT(code == true);

        std::cout << "rt = ";
        EXPECT(rt.size() == pt.size());
        for (size_t i=0; i < pt.size(); i++) {
            EXPECT(rt[i] == pt[i]);
            std::cout << std::hex <<std::setw(2) << std::setfill('0') << static_cast<int>(rt[i]);
        }
        std::cout << std::dec << std::endl;
    }
#endif
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

