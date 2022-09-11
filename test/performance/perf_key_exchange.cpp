/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "test/performance/perf_key_exchange.hpp"
#include <algorithm>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include "./phantom.hpp"
#include "crypto/random_seed.hpp"
#include "utils/stopwatch.hpp"
#include <nlohmann/json.hpp>

using namespace phantom;    // NOLINT
using namespace utilities;  // NOLINT
using namespace core;       // NOLINT

using json = nlohmann::json;

json perf_key_exchange::run(phantom::pkc_e pkc_type, size_t duration_us)
{
    std::cout << "  PKC :: KEY :: ";
    switch (pkc_type)
    {
        case PKC_KEY_ECDH: std::cout << "ECDH" << std::endl; break;
        default:           throw new std::runtime_error("Error! Invalid key exchange scheme");
    }

    stopwatch sw_total, sw_init, sw_final;
    std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0, &random_seed::seed_cb));
    json key_exchange_performance = json::array();

    pkc key_a(pkc_type);
    pkc key_b(pkc_type);
    std::unique_ptr<user_ctx> ctx_a;
    std::unique_ptr<user_ctx> ctx_b;

    size_t param_set = 0;
    do {

        uint32_t total_us = 0, init_us = 0, final_us = 0;
        uint32_t public_key_len = 0;

        size_t num_iter = 0;

        ctx_a = key_a.create_ctx(param_set);
        ctx_b = key_b.create_ctx(param_set);

        key_a.key_exchange_setup(ctx_a);
        key_b.key_exchange_setup(ctx_b);

        num_iter = 0;
        do {
            sw_total.start();

            phantom_vector<uint8_t> ma, mb;
            phantom_vector<uint8_t> sa, sb;

            sw_init.start();
            if (!key_a.key_exchange_init(ctx_a, ma)) {
                std::cerr << "A Key Exchange Initialization failed" << std::endl;
                return EXIT_FAILURE;
            }
            if (!key_b.key_exchange_init(ctx_b, mb)) {
                std::cerr << "B Key Exchange Initialization failed" << std::endl;
                return EXIT_FAILURE;
            }
            sw_init.stop();

            sw_final.start();
            if (!key_a.key_exchange_final(ctx_a, mb, sa)) {
                std::cerr << "A Key Exchange Finalization failed" << std::endl;
                return EXIT_FAILURE;
            }
            if (!key_b.key_exchange_final(ctx_b, ma, sb)) {
                std::cerr << "B Key Exchange Finalization failed" << std::endl;
                return EXIT_FAILURE;
            }
            sw_final.stop();

            public_key_len += ma.size() + mb.size();

            init_us  += sw_init.elapsed_us();
            final_us += sw_final.elapsed_us();
            num_iter++;

            sw_total.stop();
            total_us += sw_total.elapsed_us();

        } while (total_us < duration_us);

        num_iter *= 2;
        public_key_len /= 2 * num_iter;

        json key_exchange_metrics = {
            {"parameter_set", ctx_a->get_set_name()},
            {"public_key_length", public_key_len},
            {"init_us", static_cast<float>(init_us)/num_iter},
            {"init_per_sec", static_cast<uint32_t>((num_iter*1000000.0f)/static_cast<float>(init_us))},
            {"final_us", static_cast<float>(final_us)/num_iter},
            {"final_per_sec", static_cast<uint32_t>((num_iter*1000000.0f)/static_cast<float>(final_us))}
        };

        key_exchange_performance.push_back(key_exchange_metrics);

        param_set++;
    } while (param_set < ctx_a->get_set_names().size());

    json key_exchange_header = {
        {"type", "Key Exchange"},
        {"scheme", "ECDH"},
        {"metrics", json::array()}
    };
    key_exchange_header["metrics"] = key_exchange_performance;

    return key_exchange_header;
}
