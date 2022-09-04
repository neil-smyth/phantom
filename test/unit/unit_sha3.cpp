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
#include "crypto/hash_sha3.hpp"
#include "./phantom.hpp"

namespace phantom {
namespace crypto {

const lest::test specification[] =
{
    CASE("Hash Construct")
    {
        std::unique_ptr<hash_sha3> hash = std::unique_ptr<hash_sha3>(new hash_sha3());
        EXPECT(nullptr != hash);
    },
    CASE("Hash Init")
    {
        std::unique_ptr<hash_sha3> hash = std::unique_ptr<hash_sha3>(new hash_sha3());
        EXPECT(nullptr != hash);
        bool retval = hash->init(0);
        EXPECT(false == retval);
        retval = hash->init(1);
        EXPECT(false == retval);
        retval = hash->init(28);
        EXPECT(true == retval);
        retval = hash->init(32);
        EXPECT(true == retval);
        retval = hash->init(48);
        EXPECT(true == retval);
        retval = hash->init(64);
        EXPECT(true == retval);
        retval = hash->init(224);
        EXPECT(true == retval);
        retval = hash->init(256);
        EXPECT(true == retval);
        retval = hash->init(384);
        EXPECT(true == retval);
        retval = hash->init(512);
        EXPECT(true == retval);
        retval = hash->init(33);
        EXPECT(false == retval);
        retval = hash->init(511);
        EXPECT(false == retval);
    },
    CASE("Hash Length 224")
    {
        std::unique_ptr<hash_sha3> hash = std::unique_ptr<hash_sha3>(new hash_sha3());
        EXPECT(nullptr != hash);
        bool retval = hash->init(28);
        EXPECT(true == retval);
        size_t len = hash->get_length();
        EXPECT(28U == len);

        retval = hash->init(224);
        EXPECT(true == retval);
        len = hash->get_length();
        EXPECT(28U == len);
    },
    CASE("Hash Length 256")
    {
        std::unique_ptr<hash_sha3> hash = std::unique_ptr<hash_sha3>(new hash_sha3());
        EXPECT(nullptr != hash);
        bool retval = hash->init(32);
        EXPECT(true == retval);
        size_t len = hash->get_length();
        EXPECT(32U == len);

        retval = hash->init(256);
        EXPECT(true == retval);
        len = hash->get_length();
        EXPECT(32U == len);
    },
    CASE("Hash Length 384")
    {
        std::unique_ptr<hash_sha3> hash = std::unique_ptr<hash_sha3>(new hash_sha3());
        EXPECT(nullptr != hash);
        bool retval = hash->init(48);
        EXPECT(true == retval);
        size_t len = hash->get_length();
        EXPECT(48U == len);

        retval = hash->init(384);
        EXPECT(true == retval);
        len = hash->get_length();
        EXPECT(48U == len);
    },
    CASE("Hash Length 512")
    {
        std::unique_ptr<hash_sha3> hash = std::unique_ptr<hash_sha3>(new hash_sha3());
        EXPECT(nullptr != hash);
        bool retval = hash->init(64);
        EXPECT(true == retval);
        size_t len = hash->get_length();
        EXPECT(64U == len);

        retval = hash->init(512);
        EXPECT(true == retval);
        len = hash->get_length();
        EXPECT(64U == len);
    },
    CASE("Hash copy")
    {
        std::unique_ptr<hash_sha3> hash = std::unique_ptr<hash_sha3>(new hash_sha3());
        EXPECT(nullptr != hash);
        bool retval = hash->init(32);
        EXPECT(true == retval);

        std::unique_ptr<hash_sha3> hash2 = std::unique_ptr<hash_sha3>(reinterpret_cast<hash_sha3*>(hash->get_copy()));

        hash->init(64);
        size_t len = hash->get_length();
        EXPECT(64U == len);
        len = hash2->get_length();
        EXPECT(32U == len);
    },
    CASE("Phantom Hash Construct")
    {
        std::unique_ptr<hashing_function> hash;
        hash = std::unique_ptr<hashing_function>(hashing_function::make(static_cast<hash_alg_e>(999999)));
        EXPECT(nullptr == hash);
        hash = std::unique_ptr<hashing_function>(hashing_function::make(HASH_SHA3_256));
        EXPECT(nullptr != hash);
    },
    CASE("Phantom Hash 224")
    {
        const uint8_t data[4] = { 0, 1, 2, 3 };
        uint8_t hash_bytes[28] = { 0 };
        std::unique_ptr<hashing_function> hash;
        bool result, hash_check = false;
        hash   = std::unique_ptr<hashing_function>(hashing_function::make(HASH_SHA3_224));
        result = hash->init();
        EXPECT(true == result);
        EXPECT(28U == hash->get_length());
        hash->update(nullptr, 0);
        hash->update(data, 4);
        hash->final(hash_bytes);
        for (size_t i=0; i < hash->get_length(); i++) {
            hash_check |= hash_bytes[i] != 0;
        };
        EXPECT(true == hash_check);
    },
    CASE("Phantom Hash 256")
    {
        const uint8_t data[4] = { 0, 1, 2, 3 };
        uint8_t hash_bytes[32] = { 0 };
        std::unique_ptr<hashing_function> hash;
        bool result, hash_check = false;
        hash   = std::unique_ptr<hashing_function>(hashing_function::make(HASH_SHA3_256));
        result = hash->init();
        EXPECT(true == result);
        EXPECT(32U == hash->get_length());
        hash->update(nullptr, 0);
        hash->update(data, 4);
        hash->final(hash_bytes);
        for (size_t i=0; i < hash->get_length(); i++) {
            hash_check |= hash_bytes[i] != 0;
        };
        EXPECT(true == hash_check);
    },
    CASE("Phantom Hash 384")
    {
        const uint8_t data[4] = { 0, 1, 2, 3 };
        uint8_t hash_bytes[48] = { 0 };
        std::unique_ptr<hashing_function> hash;
        bool result, hash_check = false;
        hash   = std::unique_ptr<hashing_function>(hashing_function::make(HASH_SHA3_384));
        result = hash->init();
        EXPECT(true == result);
        EXPECT(48U == hash->get_length());
        hash->update(nullptr, 0);
        hash->update(data, 4);
        hash->final(hash_bytes);
        for (size_t i=0; i < hash->get_length(); i++) {
            hash_check |= hash_bytes[i] != 0;
        };
        EXPECT(true == hash_check);
    },
    CASE("Phantom Hash 512")
    {
        const uint8_t data[4] = { 0, 1, 2, 3 };
        uint8_t hash_bytes[64] = { 0 };
        std::unique_ptr<hashing_function> hash;
        bool result, hash_check = false;
        hash   = std::unique_ptr<hashing_function>(hashing_function::make(HASH_SHA3_512));
        result = hash->init();
        EXPECT(true == result);
        EXPECT(64U == hash->get_length());
        hash->update(nullptr, 0);
        hash->update(data, 4);
        hash->final(hash_bytes);
        for (size_t i=0; i < hash->get_length(); i++) {
            hash_check |= hash_bytes[i] != 0;
        };
        EXPECT(true == hash_check);
    },
    CASE("Phantom Hash 256 update multiple")
    {
        const uint8_t data[4] = { 0, 1, 2, 3 };
        uint8_t hash_bytes[32] = { 0 };
        bool result;
        std::unique_ptr<hashing_function> hash;
        hash   = std::unique_ptr<hashing_function>(hashing_function::make(HASH_SHA3_256));
        result = hash->init();
        EXPECT(true == result);
        hash->update(data, 4);
        hash->final(hash_bytes);

        uint8_t hash_bytes_multiple[32] = { 0 };
        result = hash->init();
        EXPECT(true == result);
        hash->update(data, 1);
        hash->update(data + 1, 2);
        hash->update(data + 3, 1);
        hash->final(hash_bytes_multiple);

        for (size_t i=0; i < hash->get_length(); i++) {
            EXPECT(hash_bytes_multiple[i] == hash_bytes[i]);
        };
    },
};

}  // namespace crypto
}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::crypto::specification, argc, argv);
}

