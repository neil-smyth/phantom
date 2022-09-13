/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "test/performance/perf_kem.hpp"
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

json perf_kem::run(phantom::pkc_e pkc_type, size_t duration_us, cpu_word_size_e size_hint, bool masking)
{
    std::cout << "  PKC :: KEM :: ";
    switch (pkc_type)
    {
        case PKC_KEM_SABER: std::cout << "SABRE"; break;
        case PKC_KEM_KYBER: std::cout << "Kyber"; break;
        default:            throw new std::runtime_error("Error! Invalid KEM scheme");
    }
    std::cout << ":: " << static_cast<int>(size_hint) << "-bit :: " <<
        (masking ? "masked" : "unmasked") << std::endl;

    stopwatch sw_total, sw_keygen, sw_encap, sw_decap;
    std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0, &random_seed::seed_cb));
    json kem_performance = json::array();

    pkc kem_a(pkc_type);
    pkc kem_b(pkc_type);
    std::unique_ptr<user_ctx> ctx_a;
    std::unique_ptr<user_ctx> ctx_b;

    size_t param_set = 0;
    do {

        uint32_t total_us = 0, keygen_us = 0, encap_us = 0, decap_us = 0;
        uint32_t ct_len = 0;
        uint32_t private_key_len = 0;
        uint32_t public_key_len = 0;

        size_t num_iter = 0;

        ctx_a = kem_a.create_ctx(param_set, size_hint, masking);
        ctx_b = kem_b.create_ctx(param_set, size_hint, masking);

        size_t n = kem_a.get_msg_len(ctx_a);

        num_iter = 0;
        do {
            sw_total.start();

            sw_keygen.start();
            if (!kem_a.keygen(ctx_a)) {
                std::cerr << "KeyGen failed" << std::endl;
                return EXIT_FAILURE;
            }
            if (!kem_b.keygen(ctx_b)) {
                std::cerr << "KeyGen failed" << std::endl;
                return EXIT_FAILURE;
            }
            sw_keygen.stop();
            keygen_us  += sw_keygen.elapsed_us() / 2;

            // Generate the plaintext
            phantom_vector<uint8_t> pt(n);
            rng->get_mem(pt.data(), n);

            phantom_vector<uint8_t> ct_a;
            phantom_vector<uint8_t> key_a;
            phantom_vector<uint8_t> ct_b;
            phantom_vector<uint8_t> key_b;

            phantom_vector<uint8_t> private_key_a;
            phantom_vector<uint8_t> pkb;
            kem_a.get_private_key(ctx_a, private_key_a);
            kem_b.get_public_key(ctx_b, pkb);

            sw_encap.start();
            kem_a.kem_encapsulate(ctx_a, pkb, ct_a, key_a);
            sw_encap.stop();

            sw_decap.start();
            bool ready = kem_b.kem_decapsulate(ctx_b, ct_a, key_b);
            if (!ready) {
                std::cerr << "Decapsulation failed" << std::endl;
                return EXIT_FAILURE;
            }
            sw_decap.stop();

            keygen_us += sw_keygen.elapsed_us();
            encap_us  += sw_encap.elapsed_us();
            decap_us  += sw_decap.elapsed_us();

            private_key_len += private_key_a.size();
            public_key_len += pkb.size();
            ct_len += ct_a.size();
            num_iter++;

            sw_total.stop();
            total_us += sw_total.elapsed_us();

        } while (total_us < duration_us);

        private_key_len /= num_iter;
        public_key_len /= num_iter;
        ct_len /= num_iter;

        json kem_metrics = {
            {"parameter_set", ctx_a->get_set_name()},
            {"private_key_length", private_key_len},
            {"public_key_length", public_key_len},
            {"plaintext_length", n},
            {"ciphertext_length", ct_len},
            {"keygen_us", static_cast<float>(keygen_us)/num_iter},
            {"keygen_per_sec", static_cast<uint32_t>((num_iter*1000000.0f)/static_cast<float>(keygen_us))},
            {"encap_us", static_cast<float>(encap_us)/num_iter},
            {"encap_sec", static_cast<uint32_t>((num_iter*1000000.0f)/static_cast<float>(encap_us))},
            {"decap_us", static_cast<float>(decap_us)/num_iter},
            {"decap_per_sec", static_cast<uint32_t>((num_iter*1000000.0f)/static_cast<float>(decap_us))}
        };

        kem_performance.push_back(kem_metrics);

        param_set++;
    } while (param_set < ctx_a->get_set_names().size());

    json kem_header = {
        {"type", "KEM"},
        {"scheme", pkc_type == PKC_KEM_SABER ? "SABRE" : "Kyber"},
        {"metrics", json::array()}
    };
    kem_header["metrics"] = kem_performance;

    return kem_header;
}
