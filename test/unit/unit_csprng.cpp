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
#include <cstdint>
#include "./lest.hpp"
#include "crypto/csprng.hpp"

namespace phantom {

static void test_cb(size_t len, uint8_t* data)
{
    for (size_t i=0; i < len; i++) {
        data[i] = i + 1;
    }
}

const lest::test specification[] =
{
    CASE("CSPRNG Construct with null callback")
    {
        std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0, nullptr));
        EXPECT(nullptr == rng.get());
    },
    CASE("CSPRNG Construct with callback")
    {
        std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0, &test_cb));
        EXPECT(nullptr != rng.get());
    },
    CASE("CSPRNG bits")
    {
        std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0, &test_cb));

        uint32_t bits = rng.get()->get_bits(0);
        EXPECT(bits == 0);

        for (size_t i = 1; i < 32; i++) {
            uint32_t bits = rng.get()->get_bits(i);
            EXPECT((bits & (0xffffffff << i)) == 0);
        }
    },
    CASE("CSPRNG memory")
    {
        std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0, &test_cb));

        for (size_t i = 1; i <= 16; i++) {
            uint8_t mem[16] = { 0 };
            rng.get()->get_mem(&mem[0], i);
            for (size_t j = i; j < 16; j++) {
                EXPECT(mem[j] == 0);
            }
        }
    },
    CASE("CSPRNG Boolean")
    {
        std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0, &test_cb));

        int num_true = 0;
        for (size_t i = 0; i < 1000; i++) {
            num_true += rng.get()->get<bool>() ? 1 : 0;
        }

        EXPECT(num_true != 0);
        EXPECT(num_true != 1000);
    },
    CASE("CSPRNG 8-bit")
    {
        std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0, &test_cb));

        size_t sum = 0;
        for (size_t i = 0; i < 1000; i++) {
            sum += rng.get()->get<uint8_t>();
        }

        EXPECT(sum != 0);
        EXPECT(sum != 255000);
    },
    CASE("CSPRNG 16-bit")
    {
        std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0, &test_cb));

        size_t sum = 0;
        for (size_t i = 0; i < 256; i++) {
            sum += rng.get()->get<uint16_t>();
        }

        EXPECT(sum != 0);
        EXPECT(sum != 0xFFFF00);
    },
    CASE("CSPRNG 32-bit")
    {
        std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0, &test_cb));

        size_t sum = 0;
        for (size_t i = 0; i < 256; i++) {
            sum += rng.get()->get<uint32_t>();
        }

        EXPECT(sum != 0);
        EXPECT(sum != 0xFFFFFFFF00);
    },
    CASE("CSPRNG 64-bit")
    {
        std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0, &test_cb));

        uint64_t v = rng.get()->get<uint64_t>();

        EXPECT(v != 0);
        EXPECT(v != 0xFFFFFFFFFFFFFFFFULL);
    },
    CASE("CSPRNG float")
    {
        std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0, &test_cb));

        float v = rng.get()->get<float>();

        EXPECT(v != 0);
    },
    CASE("CSPRNG double")
    {
        std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0, &test_cb));

        double v = rng.get()->get<double>();

        EXPECT(v != 0);
    }
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

