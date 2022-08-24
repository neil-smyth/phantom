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
        EXPECT(28 == len);

        retval = hash->init(224);
        EXPECT(true == retval);
        len = hash->get_length();
        EXPECT(28 == len);
    },
    CASE("Hash Length 256")
    {
        std::unique_ptr<hash_sha3> hash = std::unique_ptr<hash_sha3>(new hash_sha3());
        EXPECT(nullptr != hash);
        bool retval = hash->init(32);
        EXPECT(true == retval);
        size_t len = hash->get_length();
        EXPECT(32 == len);

        retval = hash->init(256);
        EXPECT(true == retval);
        len = hash->get_length();
        EXPECT(32 == len);
    },
    CASE("Hash Length 384")
    {
        std::unique_ptr<hash_sha3> hash = std::unique_ptr<hash_sha3>(new hash_sha3());
        EXPECT(nullptr != hash);
        bool retval = hash->init(48);
        EXPECT(true == retval);
        size_t len = hash->get_length();
        EXPECT(48 == len);

        retval = hash->init(384);
        EXPECT(true == retval);
        len = hash->get_length();
        EXPECT(48 == len);
    },
    CASE("Hash Length 512")
    {
        std::unique_ptr<hash_sha3> hash = std::unique_ptr<hash_sha3>(new hash_sha3());
        EXPECT(nullptr != hash);
        bool retval = hash->init(64);
        EXPECT(true == retval);
        size_t len = hash->get_length();
        EXPECT(64 == len);

        retval = hash->init(512);
        EXPECT(true == retval);
        len = hash->get_length();
        EXPECT(64 == len);
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
        EXPECT(64 == len);
        len = hash2->get_length();
        EXPECT(32 == len);
    },
};

}  // namespace crypto
}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::crypto::specification, argc, argv);
}

