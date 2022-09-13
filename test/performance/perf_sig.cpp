/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "test/performance/perf_sig.hpp"
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


json perf_sig::run(phantom::pkc_e pkc_type, size_t duration_us, cpu_word_size_e size_hint, bool masking)
{
    std::string name;
    switch (pkc_type)
    {
        case PKC_SIG_DILITHIUM:  name = "Dilithium"; break;
        case PKC_SIG_FALCON:     name = "Falcon"; break;
        case PKC_SIG_ECDSA:      name = "ECDSA"; break;
        case PKC_SIG_EDDSA:      name = "EDDSA"; break;
        case PKC_SIG_RSASSA_PSS: name = "RSASSA-PSS"; break;
        default:                 throw new std::runtime_error("Error! Invalid digital signature scheme");
    }

    std::cout << "  PKC :: SIG :: " << name << ":: " << static_cast<int>(size_hint) << "-bit :: " <<
        (masking ? "masked" : "unmasked") << std::endl;

    stopwatch sw_total, sw_keygen, sw_sign, sw_verify;
    std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0, &random_seed::seed_cb));
    json sig_performance = json::array();

    pkc signature(pkc_type);

    std::unique_ptr<user_ctx> ctx;

    size_t param_set = 0;
    do {

        uint32_t total_us = 0, keygen_us = 0, sign_us = 0, verify_us = 0;
        uint32_t s_len = 0;
        uint32_t public_key_len = 0;
        uint32_t private_key_len = 0;

        // Create an instance of a PKE
        ctx = signature.create_ctx(param_set, size_hint, masking);

        size_t n = signature.get_msg_len(ctx);

        size_t num_iter = 0;

        num_iter = 0;
        do {
            sw_total.start();

            // Generate the plaintext
            phantom_vector<uint8_t> s;
            phantom_vector<uint8_t> m(128);
            rng->get_mem(m.data(), 128);

            sw_keygen.start();
            if (!signature.keygen(ctx)) {
                std::cerr << "KeyGen failed" << std::endl;
                return EXIT_FAILURE;
            }
            sw_keygen.stop();

            // Obtain the public key
            phantom_vector<uint8_t> public_key;
            signature.get_public_key(ctx, public_key);
            public_key_len += public_key.size();

            // Obtain the private key
            phantom_vector<uint8_t> private_key;
            signature.get_private_key(ctx, private_key);
            private_key_len += private_key.size();

            sw_sign.start();
            signature.sig_sign(ctx, m, s);
            sw_sign.stop();

            sw_verify.start();
            signature.sig_verify(ctx, m, s);
            sw_verify.stop();

            sign_us   += sw_sign.elapsed_us();
            verify_us += sw_verify.elapsed_us();

            s_len += s.size();
            num_iter++;

            sw_total.stop();
            total_us += sw_total.elapsed_us();

        } while (total_us < duration_us);

        s_len /= num_iter;
        public_key_len /= num_iter;
        private_key_len /= num_iter;

        json sig_metrics = {
            {"parameter_set", ctx->get_set_name()},
            {"private_key_length", public_key_len},
            {"public_key_length", private_key_len},
            {"message_length", n},
            {"signature_length", s_len},
            {"keygen_us", keygen_us},
            {"keygen_per_sec", (1000000.0f)/static_cast<float>(keygen_us)},
            {"sign_us", static_cast<float>(sign_us)/num_iter},
            {"sign_per_sec", static_cast<uint32_t>((num_iter*1000000.0f)/static_cast<float>(sign_us))},
            {"verify_us", static_cast<float>(verify_us)/num_iter},
            {"verify_per_sec", static_cast<uint32_t>((num_iter*1000000.0f)/static_cast<float>(verify_us))}
        };

        sig_performance.push_back(sig_metrics);

        param_set++;
    } while (param_set < ctx->get_set_names().size());

    json sig_header = {
        {"type", "Signature"},
        {"scheme", name},
        {"metrics", json::array()}
    };
    sig_header["metrics"] = sig_performance;

    return sig_header;
}
