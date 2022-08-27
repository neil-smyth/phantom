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
#include "crypto/shamirs_secret_sharing.hpp"
#include "./phantom.hpp"

namespace phantom {

static void test_cb(size_t len, uint8_t* data)
{
    for (size_t i=0; i < len; i++) {
        data[i] = i + 1;
    }
}

const lest::test specification[] =
{
    CASE("SSS create instance")
    {
        auto prng = csprng::make(0, nullptr);
        EXPECT(nullptr == prng);
        EXPECT_THROWS_AS(shamirs_secret_sharing(std::shared_ptr<csprng>(prng)), std::runtime_error);
        prng = csprng::make(0, &test_cb);
        EXPECT(nullptr != prng);
        EXPECT_NO_THROW(shamirs_secret_sharing(std::shared_ptr<csprng>(prng)));
    },
    CASE("SSS get_keylen")
    {
        auto prng = csprng::make(0, &test_cb);
        EXPECT(nullptr != prng);
        auto sss = shamirs_secret_sharing(std::shared_ptr<csprng>(prng));
        key_sharing_type_e type = sss.get_keylen();
        EXPECT(KEY_SHARING_SHAMIRS == type);
    },
    CASE("SSS create")
    {
        auto prng = csprng::make(0, &test_cb);
        EXPECT(nullptr != prng);
        auto sss = shamirs_secret_sharing(std::shared_ptr<csprng>(prng));
        phantom_vector<phantom_vector<uint8_t>> shares(3);
        uint8_t key[shamirs_secret_sharing::key_bytes] = {0};
        phantom_vector<phantom_vector<uint8_t>> shares_empty;
        int32_t retval = sss.create(shares_empty, key, 3, 2);
        EXPECT(EXIT_FAILURE == retval);

        retval = sss.create(shares, nullptr, 3, 2);
        EXPECT(EXIT_FAILURE == retval);

        retval = sss.create(shares, key, 3, 2);
        EXPECT(EXIT_SUCCESS == retval);
    },
    CASE("SSS combine")
    {
        auto prng = csprng::make(0, &test_cb);
        EXPECT(nullptr != prng);
        auto sss = shamirs_secret_sharing(std::shared_ptr<csprng>(prng));
        phantom_vector<phantom_vector<uint8_t>> shares(3);
        uint8_t key[shamirs_secret_sharing::key_bytes] = {0};
        uint8_t keyout[shamirs_secret_sharing::key_bytes] = {0};
        int32_t retval = sss.create(shares, key, 3, 2);

        EXPECT(EXIT_SUCCESS == retval);
        retval = sss.combine(keyout, shares, 0);

        EXPECT(EXIT_FAILURE == retval);
        retval = sss.combine(keyout, shares, 1);

        EXPECT(EXIT_SUCCESS == retval);
        bool mismatch = false;
        for (size_t i = 0; i < shamirs_secret_sharing::key_bytes; i++)
        {
            mismatch |= key[i] != keyout[i];
        }
        EXPECT(mismatch);

        retval = sss.combine(keyout, shares, 2);
        EXPECT(EXIT_SUCCESS == retval);
        mismatch = false;
        for (size_t i = 0; i < shamirs_secret_sharing::key_bytes; i++)
        {
            mismatch |= key[i] != keyout[i];
        }
        EXPECT(!mismatch);
    },
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

