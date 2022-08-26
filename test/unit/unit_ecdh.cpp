/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include <iostream>
#include <memory>
#include "./lest.hpp"
#include "schemes/key_exchange/ecdh/ecdh_key_exchange.hpp"

namespace phantom {
using namespace core;      // NOLINT
using namespace schemes;   // NOLINT

const lest::test specification[] =
{
#if defined(IS_64BIT)
    CASE("secp192r1 affine ECDH get non-existant private key - 64-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(0, CPU_WORD_SIZE_64);

        bool retflag;
        phantom_vector<uint8_t> privkey;
        retflag = ecdh.get_private_key(ctx, privkey);
        EXPECT(false == retflag);
    },
    CASE("secp192r1 affine ECDH key generation - 64-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(0, CPU_WORD_SIZE_64);

        bool retflag;
        retflag = ecdh.keygen(ctx);
        EXPECT(false == retflag);
    },
    CASE("secp192r1 affine ECDH init - 64-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(0, CPU_WORD_SIZE_64);

        bool retflag;

        phantom_vector<uint8_t> m;
        retflag = ecdh.key_exchange_init(ctx, m);
        EXPECT(true == retflag);
        EXPECT(48U == m.size());
    },
    CASE("secp192r1 affine ECDH final bad message length - 64-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(0, CPU_WORD_SIZE_64);

        bool retflag;

        phantom_vector<uint8_t> m(47);
        phantom_vector<uint8_t> shared_key;
        retflag = ecdh.key_exchange_final(ctx, m, shared_key);
        EXPECT(false == retflag);
        phantom_vector<uint8_t> m2(49);
        retflag = ecdh.key_exchange_final(ctx, m2, shared_key);
        EXPECT(false == retflag);
        phantom_vector<uint8_t> m3(48);
        retflag = ecdh.key_exchange_final(ctx, m3, shared_key);
        EXPECT(true == retflag);
    },
    CASE("secp192r1 affine ECDH incomplete - 64-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(0, CPU_WORD_SIZE_64);

        bool retflag;

        phantom_vector<uint8_t> m;
        retflag = ecdh.key_exchange_init(ctx, m);
        EXPECT(true == retflag);
        EXPECT(48U == m.size());

        m.resize(47);

        phantom_vector<uint8_t> shared_key;
        retflag = ecdh.key_exchange_final(ctx, m, shared_key);
        EXPECT(false == retflag);
    },
    CASE("secp192r1 affine ECDH complete - 64-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(0, CPU_WORD_SIZE_64);

        bool retflag;

        phantom_vector<uint8_t> m;
        retflag = ecdh.key_exchange_init(ctx, m);
        EXPECT(true == retflag);
        EXPECT(48U == m.size());

        phantom_vector<uint8_t> shared_key;
        retflag = ecdh.key_exchange_final(ctx, m, shared_key);
        EXPECT(true == retflag);
        EXPECT(24U == shared_key.size());
    },
    CASE("secp224r1 affine ECDH get non-existant private key - 64-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(1, CPU_WORD_SIZE_64);

        bool retflag;
        phantom_vector<uint8_t> privkey;
        retflag = ecdh.get_private_key(ctx, privkey);
        EXPECT(false == retflag);
    },
    CASE("secp224r1 affine ECDH key generation - 64-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(1, CPU_WORD_SIZE_64);

        bool retflag;
        retflag = ecdh.keygen(ctx);
        EXPECT(false == retflag);
    },
    CASE("secp224r1 affine ECDH init - 64-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(1, CPU_WORD_SIZE_64);

        bool retflag;

        phantom_vector<uint8_t> m;
        retflag = ecdh.key_exchange_init(ctx, m);
        EXPECT(true == retflag);
        EXPECT(56U == m.size());
    },
    CASE("secp224r1 affine ECDH final bad message length - 64-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(1, CPU_WORD_SIZE_64);

        bool retflag;

        phantom_vector<uint8_t> m(55);
        phantom_vector<uint8_t> shared_key;
        retflag = ecdh.key_exchange_final(ctx, m, shared_key);
        EXPECT(false == retflag);
        phantom_vector<uint8_t> m2(57);
        retflag = ecdh.key_exchange_final(ctx, m2, shared_key);
        EXPECT(false == retflag);
        phantom_vector<uint8_t> m3(56);
        retflag = ecdh.key_exchange_final(ctx, m3, shared_key);
        EXPECT(true == retflag);
    },
    CASE("secp224r1 affine ECDH incomplete - 64-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(1, CPU_WORD_SIZE_64);

        bool retflag;

        phantom_vector<uint8_t> m;
        retflag = ecdh.key_exchange_init(ctx, m);
        EXPECT(true == retflag);
        EXPECT(56U == m.size());

        m.resize(55);

        phantom_vector<uint8_t> shared_key;
        retflag = ecdh.key_exchange_final(ctx, m, shared_key);
        EXPECT(false == retflag);
    },
    CASE("secp224r1 affine ECDH complete - 64-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(1, CPU_WORD_SIZE_64);

        bool retflag;

        phantom_vector<uint8_t> m;
        retflag = ecdh.key_exchange_init(ctx, m);
        EXPECT(true == retflag);
        EXPECT(56U == m.size());

        phantom_vector<uint8_t> shared_key;
        retflag = ecdh.key_exchange_final(ctx, m, shared_key);
        EXPECT(true == retflag);
        EXPECT(28U == shared_key.size());
    },
#endif
    CASE("secp192r1 affine ECDH get non-existant private key - 32-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(0, CPU_WORD_SIZE_32);

        bool retflag;
        phantom_vector<uint8_t> privkey;
        retflag = ecdh.get_private_key(ctx, privkey);
        EXPECT(false == retflag);
    },
    CASE("secp192r1 affine ECDH key generation - 32-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(0, CPU_WORD_SIZE_32);

        bool retflag;
        retflag = ecdh.keygen(ctx);
        EXPECT(false == retflag);
    },
    CASE("secp192r1 affine ECDH init - 32-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(0, CPU_WORD_SIZE_32);

        bool retflag;

        phantom_vector<uint8_t> m;
        retflag = ecdh.key_exchange_init(ctx, m);
        EXPECT(true == retflag);
        EXPECT(48U == m.size());
    },
    CASE("secp192r1 affine ECDH final bad message length - 32-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(0, CPU_WORD_SIZE_32);

        bool retflag;

        phantom_vector<uint8_t> m(47);
        phantom_vector<uint8_t> shared_key;
        retflag = ecdh.key_exchange_final(ctx, m, shared_key);
        EXPECT(false == retflag);
        phantom_vector<uint8_t> m2(49);
        retflag = ecdh.key_exchange_final(ctx, m2, shared_key);
        EXPECT(false == retflag);
        phantom_vector<uint8_t> m3(48);
        retflag = ecdh.key_exchange_final(ctx, m3, shared_key);
        EXPECT(true == retflag);
    },
    CASE("secp192r1 affine ECDH incomplete - 32-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(0, CPU_WORD_SIZE_32);

        bool retflag;

        phantom_vector<uint8_t> m;
        retflag = ecdh.key_exchange_init(ctx, m);
        EXPECT(true == retflag);
        EXPECT(48U == m.size());

        m.resize(47);

        phantom_vector<uint8_t> shared_key;
        retflag = ecdh.key_exchange_final(ctx, m, shared_key);
        EXPECT(false == retflag);
    },
    CASE("secp192r1 affine ECDH complete - 32-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(0, CPU_WORD_SIZE_32);

        bool retflag;

        phantom_vector<uint8_t> m;
        retflag = ecdh.key_exchange_init(ctx, m);
        EXPECT(true == retflag);
        EXPECT(48U == m.size());

        phantom_vector<uint8_t> shared_key;
        retflag = ecdh.key_exchange_final(ctx, m, shared_key);
        EXPECT(true == retflag);
        EXPECT(24U == shared_key.size());
    },
    CASE("secp224r1 affine ECDH get non-existant private key - 32-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(1, CPU_WORD_SIZE_32);

        bool retflag;
        phantom_vector<uint8_t> privkey;
        retflag = ecdh.get_private_key(ctx, privkey);
        EXPECT(false == retflag);
    },
    CASE("secp224r1 affine ECDH key generation - 32-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(1, CPU_WORD_SIZE_32);

        bool retflag;
        retflag = ecdh.keygen(ctx);
        EXPECT(false == retflag);
    },
    CASE("secp224r1 affine ECDH init - 32-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(1, CPU_WORD_SIZE_32);

        bool retflag;

        phantom_vector<uint8_t> m;
        retflag = ecdh.key_exchange_init(ctx, m);
        EXPECT(true == retflag);
        EXPECT(56U == m.size());
    },
    CASE("secp224r1 affine ECDH final bad message length - 32-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(1, CPU_WORD_SIZE_32);

        bool retflag;

        phantom_vector<uint8_t> m(55);
        phantom_vector<uint8_t> shared_key;
        retflag = ecdh.key_exchange_final(ctx, m, shared_key);
        EXPECT(false == retflag);
        phantom_vector<uint8_t> m2(57);
        retflag = ecdh.key_exchange_final(ctx, m2, shared_key);
        EXPECT(false == retflag);
        phantom_vector<uint8_t> m3(56);
        retflag = ecdh.key_exchange_final(ctx, m3, shared_key);
        EXPECT(true == retflag);
    },
    CASE("secp224r1 affine ECDH incomplete - 32-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(1, CPU_WORD_SIZE_32);

        bool retflag;

        phantom_vector<uint8_t> m;
        retflag = ecdh.key_exchange_init(ctx, m);
        EXPECT(true == retflag);
        EXPECT(56U == m.size());

        m.resize(55);

        phantom_vector<uint8_t> shared_key;
        retflag = ecdh.key_exchange_final(ctx, m, shared_key);
        EXPECT(false == retflag);
    },
    CASE("secp224r1 affine ECDH complete - 32-bit")
    {
        ecdh_key_exchange ecdh;
        std::unique_ptr<user_ctx> ctx = ecdh.create_ctx(1, CPU_WORD_SIZE_32);

        bool retflag;

        phantom_vector<uint8_t> m;
        retflag = ecdh.key_exchange_init(ctx, m);
        EXPECT(true == retflag);
        EXPECT(56U == m.size());

        phantom_vector<uint8_t> shared_key;
        retflag = ecdh.key_exchange_final(ctx, m, shared_key);
        EXPECT(true == retflag);
        EXPECT(28U == shared_key.size());
    }
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

