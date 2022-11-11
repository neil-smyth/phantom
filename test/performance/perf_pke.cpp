/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "test/performance/perf_pke.hpp"
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


json perf_pke::run(phantom::pkc_e pkc_type, size_t duration_us, cpu_word_size_e size_hint, bool masking)
{
    std::string name;
    switch (pkc_type)
    {
        case PKC_PKE_KYBER:      name = "SABRE"; break;
        case PKC_PKE_SABER:      name = "Kyber"; break;
        case PKC_PKE_RSAES_OAEP: name = "RSAES-OAEP"; break;
        default:                 throw new std::runtime_error("Error! Invalid public key encryption scheme");
    }

    std::cout << "  PKC :: PKE :: " << name << ":: " << static_cast<int>(size_hint) << "-bit :: " <<
        (masking ? "masked" : "unmasked") << std::endl;

    stopwatch sw_total, sw_keygen, sw_encrypt, sw_decrypt;
    std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0, &random_seed::seed_cb));
    json pke_performance = json::array();

    pkc pke_a(pkc_type);
    pkc pke_b(pkc_type);

    std::unique_ptr<user_ctx> ctx_a;
    std::unique_ptr<user_ctx> ctx_b;

    size_t param_set = 0;
    do {

        uint32_t total_us = 0, keygen_us = 0, encrypt_us = 0, decrypt_us = 0;
        uint32_t ct_len = 0;

        // Create an instance of a PKE
        ctx_a = pke_a.create_ctx(param_set, size_hint, masking);
        ctx_b = pke_b.create_ctx(param_set, size_hint, masking);

        size_t n = pke_a.get_msg_len(ctx_a) / 2;

        size_t num_iter = 0;
        do {
            sw_keygen.start();
            if (!pke_a.keygen(ctx_a)) {
                std::cerr << "KeyGen failed" << std::endl;
                return EXIT_FAILURE;
            }
            if (!pke_b.keygen(ctx_b)) {
                std::cerr << "KeyGen failed" << std::endl;
                return EXIT_FAILURE;
            }
            sw_keygen.stop();
            keygen_us  += sw_keygen.elapsed_us();
            num_iter += 2;
        } while (keygen_us < duration_us);
        keygen_us /= num_iter;

        // Obtain the public key
        phantom_vector<uint8_t> public_key;
        pke_a.get_public_key(ctx_a, public_key);

        // Obtain the private key
        phantom_vector<uint8_t> private_key;
        pke_a.get_private_key(ctx_a, private_key);

        num_iter = 0;
        do {
            sw_total.start();

            // Generate the plaintext
            phantom_vector<uint8_t> ct;
            phantom_vector<uint8_t> pt2;
            phantom_vector<uint8_t> pt(n);
            rng->get_mem(pt.data(), n);

            // Extract the User Key from the PKG
            sw_encrypt.start();
            pke_a.pke_encrypt(ctx_a, pt, ct);
            sw_encrypt.stop();

            // Load the public key into the client and encrypt the message
            sw_decrypt.start();
            bool ready = pke_a.pke_decrypt(ctx_a, ct, pt2);
            if (!ready) {
                std::cerr << "Decryption failed" << std::endl;
                return EXIT_FAILURE;
            }
            sw_decrypt.stop();

            encrypt_us += sw_encrypt.elapsed_us();
            decrypt_us += sw_decrypt.elapsed_us();

            ct_len += ct.size();
            num_iter++;

            sw_total.stop();
            total_us += sw_total.elapsed_us();

        } while (total_us < duration_us);

        ct_len /= num_iter;

        json pke_metrics = {
            {"parameter_set", ctx_a->get_set_name()},
            {"private_key_length", private_key.size()},
            {"public_key_length", public_key.size()},
            {"plaintext_length", n},
            {"ciphertext_length", ct_len},
            {"keygen_us", keygen_us},
            {"keygen_per_sec", (1000000.0f)/static_cast<float>(keygen_us)},
            {"encrypt_us", static_cast<float>(encrypt_us)/num_iter},
            {"encrypt_per_sec", static_cast<uint32_t>((num_iter*1000000.0f)/static_cast<float>(encrypt_us))},
            {"decrypt_us", static_cast<float>(decrypt_us)/num_iter},
            {"decrypt_per_sec", static_cast<uint32_t>((num_iter*1000000.0f)/static_cast<float>(decrypt_us))}
        };

        pke_performance.push_back(pke_metrics);

        std::cout << "param_set = " << param_set << std::endl;
        param_set++;
    } while (param_set < ctx_a->get_set_names().size());

    json pke_header = {
        {"scheme", name},
        {"metrics", json::array()}
    };
    pke_header["metrics"] = pke_performance;

    return pke_header;
}
