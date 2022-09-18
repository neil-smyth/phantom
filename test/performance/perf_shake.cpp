/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "test/performance/perf_shake.hpp"
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


json perf_shake::run(size_t duration_us)
{
    std::cout << "  XOF :: SHAKE" << std::endl;

    stopwatch sw_total, sw_keygen, sw_sign, sw_verify;
    std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0, &random_seed::seed_cb));
    json xof_performance = json::array();

    std::unique_ptr<user_ctx> ctx;

    size_t xof_type = 0;
    do {

        uint32_t total_us = 0;
        size_t num_iter = 0;

        xof_alg_e type;
        std::string xof_name;
        switch (xof_type)
        {
            case 0: type = XOF_SHAKE_128; xof_name = "SHAKE-128"; break;
            case 1: type = XOF_SHAKE_256; xof_name = "SHAKE-256"; break;
        }

        utilities::stopwatch sw_xof;

        auto xof = std::unique_ptr<hashing_function>(hashing_function::make(type));

        phantom_vector<uint8_t> msg(16384), out(16384);
        rng->get_mem(msg.data(), 16384);

        num_iter = 0;
        total_us = 0;
        do {
            sw_total.start();
            for (size_t i = 0; i < 2048; i++) {
                xof->init();
                xof->absorb(msg.data(), 16);
                xof->final();
                xof->squeeze(out.data(), 16);
                num_iter++;
            }
            sw_total.stop();
            total_us += sw_total.elapsed_us();
        } while (total_us < duration_us);

        json xof_metrics_16 = {
            {"algorithm", xof_name},
            {"message_length", 16},
            {"xof_length", xof->get_length()},
            {"xof_us", static_cast<float>(total_us) / static_cast<float>(num_iter)},
            {"xof_per_sec", static_cast<uint32_t>((num_iter*1000000.0f)/static_cast<float>(total_us))}
            ,
            {"bytes_per_sec", static_cast<uint32_t>((16*num_iter*1000000.0f)/static_cast<float>(total_us))}
        };

        xof_performance.push_back(xof_metrics_16);

        num_iter = 0;
        total_us = 0;
        do {
            sw_total.start();
            for (size_t i = 0; i < 2048; i++) {
                xof->init();
                xof->absorb(msg.data(), 512);
                xof->final();
                xof->squeeze(out.data(), 512);
                num_iter++;
            }
            sw_total.stop();
            total_us += sw_total.elapsed_us();
        } while (total_us < duration_us);

        json xof_metrics_512 = {
            {"algorithm", xof_name},
            {"message_length", 512},
            {"xof_length", xof->get_length()},
            {"xof_us", static_cast<float>(total_us) / static_cast<float>(num_iter)},
            {"xof_per_sec", static_cast<uint32_t>((num_iter*1000000.0f)/static_cast<float>(total_us))},
            {"bytes_per_sec", static_cast<uint32_t>((512*num_iter*1000000.0f)/static_cast<float>(total_us))}
        };

        xof_performance.push_back(xof_metrics_512);

        num_iter = 0;
        total_us = 0;
        do {
            sw_total.start();
            for (size_t i = 0; i < 2048; i++) {
                xof->init();
                xof->absorb(msg.data(), 16384);
                xof->final();
                xof->squeeze(out.data(), 16384);
                num_iter++;
            }
            sw_total.stop();
            total_us += sw_total.elapsed_us();
        } while (total_us < duration_us);

        json xof_metrics_16384 = {
            {"algorithm", xof_name},
            {"message_length", 16384},
            {"xof_length", xof->get_length()},
            {"xof_us", static_cast<float>(total_us) / static_cast<float>(num_iter)},
            {"xof_per_sec", static_cast<uint32_t>((num_iter*1000000.0f)/static_cast<float>(total_us))},
            {"bytes_per_sec", static_cast<uint32_t>((16384*num_iter*1000000.0f)/static_cast<float>(total_us))}
        };

        xof_performance.push_back(xof_metrics_16384);

        xof_type++;
    } while (xof_type < 2);

    json xof_header = {
        {"scheme", "SHAKE"},
        {"metrics", json::array()}
    };
    xof_header["metrics"] = xof_performance;

    return xof_header;
}
