/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include <utils/third_party/cpp-base64/base64.h>

#include <cassert>
#include <cstdlib>
#include <iostream>

#include "crypto/shamirs_secret_sharing.hpp"
#include "crypto/random_seed.hpp"
#include "logging/logger.hpp"
#include "utils/stopwatch.hpp"
#include "./phantom_types.hpp"

using namespace phantom;    // NOLINT
using namespace utilities;  // NOLINT


int main(int argc, char *argv[])
{
    std::cout << "Shamir's Secret Sharing" << std::endl;

    auto prng = std::shared_ptr<csprng>(csprng::make(0x10000000, random_seed::seed_cb));
    auto shamirs = new shamirs_secret_sharing(prng);

    for (size_t n=2; n < 128; n++) {
        phantom_vector<uint8_t> key(shamirs_secret_sharing::key_bytes), keyout(shamirs_secret_sharing::key_bytes);
        prng->get_mem(key.data(), shamirs_secret_sharing::key_bytes);

        phantom_vector<phantom_vector<uint8_t>> shares(n);

        for (size_t k=1; k <= n; k++) {
            std::cout << "n = " << n << ", k = " << k << std::endl;
            shamirs->create(shares, key, n, k);
            shamirs->combine(keyout, shares, k);

            for (size_t i=0; i < n; i++) {
                auto shard_base64 = base64_encode(&shares[i][0], shamirs_secret_sharing::shard_length);
                std::cout << "shard " << i << ": " << shard_base64 << std::endl;
            }

            for (size_t i=0; i < shamirs_secret_sharing::key_bytes; i++) {
                assert(keyout[i] == key[i]);
            }
        }
    }

    delete shamirs;
}
