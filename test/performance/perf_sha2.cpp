/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "test/performance/perf_sha2.hpp"
#include <algorithm>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include "./phantom.hpp"
#include "crypto/csprng.hpp"
#include "crypto/random_seed.hpp"
#include "logging/logger.hpp"
#include "utils/stopwatch.hpp"
#include "core/poly.hpp"
#include "core/mpz.hpp"
#include <nlohmann/json.hpp>


using namespace phantom;    // NOLINT
using namespace utilities;  // NOLINT
using namespace core;       // NOLINT

using json = nlohmann::json;


json perf_sha2::run(size_t duration_us)
{
    std::cout << "  CRYPTOGRAPHIC HASH :: SHA2" << std::endl;

    stopwatch sw_total, sw_keygen, sw_sign, sw_verify;
    std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0, &random_seed::seed_cb));
    json hash_performance = json::array();

    std::unique_ptr<user_ctx> ctx;

    size_t hash_type = 0;
    do {

        uint32_t total_us = 0;
        size_t num_iter = 0;

        hash_alg_e type;
        std::string hash_name;
        switch (hash_type)
        {
            case 0: type = HASH_SHA2_224; hash_name = "SHA-224"; break;
            case 1: type = HASH_SHA2_256; hash_name = "SHA-256"; break;
            case 2: type = HASH_SHA2_384; hash_name = "SHA-384"; break;
            case 3: type = HASH_SHA2_512; hash_name = "SHA-512"; break;
        }

        utilities::stopwatch sw_hash;

        auto hash = std::unique_ptr<hashing_function>(hashing_function::make(type));

        uint8_t hash_bytes[64];
        phantom_vector<uint8_t> msg(16384);
        rng->get_mem(msg.data(), 16384);

        num_iter = 0;
        total_us = 0;
        do {
            sw_total.start();
            for (size_t i = 0; i < 2048; i++) {
                hash->init();
                hash->update(msg.data(), 16);
                hash->final(hash_bytes);
                num_iter++;
            }
            sw_total.stop();
            total_us += sw_total.elapsed_us();
        } while (total_us < duration_us);

        json hash_metrics_16 = {
            {"algorithm", hash_name},
            {"message_length", 16},
            {"hash_length", hash->get_length()},
            {"hash_us", static_cast<float>(total_us) / static_cast<float>(num_iter)},
            {"hash_per_sec", static_cast<uint32_t>((num_iter*1000000.0f)/static_cast<float>(total_us))}
            ,
            {"bytes_per_sec", static_cast<uint32_t>((16*num_iter*1000000.0f)/static_cast<float>(total_us))}
        };

        hash_performance.push_back(hash_metrics_16);

        num_iter = 0;
        total_us = 0;
        do {
            sw_total.start();
            for (size_t i = 0; i < 2048; i++) {
                hash->init();
                hash->update(msg.data(), 512);
                hash->final(hash_bytes);
                num_iter++;
            }
            sw_total.stop();
            total_us += sw_total.elapsed_us();
        } while (total_us < duration_us);

        json hash_metrics_512 = {
            {"algorithm", hash_name},
            {"message_length", 512},
            {"hash_length", hash->get_length()},
            {"hash_us", static_cast<float>(total_us) / static_cast<float>(num_iter)},
            {"hash_per_sec", static_cast<uint32_t>((num_iter*1000000.0f)/static_cast<float>(total_us))},
            {"bytes_per_sec", static_cast<uint32_t>((512*num_iter*1000000.0f)/static_cast<float>(total_us))}
        };

        hash_performance.push_back(hash_metrics_512);

        num_iter = 0;
        total_us = 0;
        do {
            sw_total.start();
            for (size_t i = 0; i < 2048; i++) {
                hash->init();
                hash->update(msg.data(), 16384);
                hash->final(hash_bytes);
                num_iter++;
            }
            sw_total.stop();
            total_us += sw_total.elapsed_us();
        } while (total_us < duration_us);

        json hash_metrics_16384 = {
            {"algorithm", hash_name},
            {"message_length", 16384},
            {"hash_length", hash->get_length()},
            {"hash_us", static_cast<float>(total_us) / static_cast<float>(num_iter)},
            {"hash_per_sec", static_cast<uint32_t>((num_iter*1000000.0f)/static_cast<float>(total_us))},
            {"bytes_per_sec", static_cast<uint32_t>((16384*num_iter*1000000.0f)/static_cast<float>(total_us))}
        };

        hash_performance.push_back(hash_metrics_16384);

        hash_type++;
    } while (hash_type < 4);

    json hash_header = {
        {"type", "Hash"},
        {"scheme", "SHA2"},
        {"metrics", json::array()}
    };
    hash_header["metrics"] = hash_performance;

    return hash_header;
}
