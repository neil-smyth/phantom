/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "test/performance/perf_ibe.hpp"
#include <algorithm>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include "schemes/ibe/dlp/ibe_dlp.hpp"
#include "crypto/csprng.hpp"
#include "logging/logger.hpp"
#include "utils/stopwatch.hpp"
#include "core/poly.hpp"
#include "core/mpz.hpp"
#include <nlohmann/json.hpp>


using namespace phantom;    // NOLINT
using namespace utilities;  // NOLINT
using namespace core;       // NOLINT

using json = nlohmann::json;


json perf_ibe::run(phantom::pkc_e pkc_type, size_t duration_us)
{
    std::cout << "  PKC :: IBE :: DLP" << std::endl;

    stopwatch sw_total, sw_keygen, sw_extract, sw_encrypt, sw_decrypt;
    std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0, &random_seed::seed_cb));
    json ibe_performance = json::array();

    pkc ibe_dlp_a(pkc_type);
    pkc ibe_dlp_b(pkc_type);

    std::unique_ptr<user_ctx> ctx_pkg;

    size_t param_set = 0;
    do {

        uint32_t total_us = 0, keygen_us = 0, extract_us = 0, encrypt_us = 0, decrypt_us = 0;
        uint32_t ct_len = 0;

        // Create an instance of a DLP-IBE Private Key Generator
        ctx_pkg = ibe_dlp_a.create_ctx(param_set);

        size_t n = ibe_dlp_a.get_msg_len(ctx_pkg);

        size_t num_iter = 0;
        do {
            sw_keygen.start();
            ibe_dlp_a.keygen(ctx_pkg);
            sw_keygen.stop();
            keygen_us  += sw_keygen.elapsed_us();
            num_iter++;
        } while (keygen_us < duration_us);
        keygen_us /= num_iter;

        // Obtain the IBE public key
        phantom_vector<uint8_t> public_key;
        ibe_dlp_a.get_public_key(ctx_pkg, public_key);

        // Obtain the IBE master key
        phantom_vector<uint8_t> master_key;
        ibe_dlp_a.get_private_key(ctx_pkg, master_key);

        std::unique_ptr<user_ctx> ctx_client = ibe_dlp_a.create_ctx(param_set);
        std::unique_ptr<user_ctx> ctx_server = ibe_dlp_b.create_ctx(param_set);

        num_iter = 0;
        do {
            sw_total.start();

            // Generate the plaintext
            phantom_vector<uint8_t> pt(n);
            rng->get_mem(pt.data(), n);

            // Generate a User ID
            std::stringstream ss;
            ss << std::hex << std::setfill('0') << std::setw(5) << num_iter  << "@foobar.com";
            char id[32];
            strncpy(id, ss.str().c_str(), 32);

            phantom_vector<uint8_t> vec_id(id, id + 16);
            phantom_vector<uint8_t> vec_user_key;

            // Extract the User Key from the PKG
            sw_extract.start();
            ibe_dlp_a.ibe_extract(ctx_pkg, vec_id, vec_user_key);
            sw_extract.stop();

            // Load the public key into the client and encrypt the message
            phantom_vector<uint8_t> to, rec;
            ibe_dlp_a.set_public_key(ctx_client, public_key);
            sw_encrypt.start();
            ibe_dlp_a.ibe_encrypt(ctx_client, vec_id, pt, to);
            sw_encrypt.stop();

            // The server obtains the User Key and decrypts the message
            ibe_dlp_b.ibe_load_user_key(ctx_server, vec_id, vec_user_key);
            sw_decrypt.start();
            ibe_dlp_b.ibe_decrypt(ctx_server, to, rec);
            sw_decrypt.stop();

            extract_us += sw_extract.elapsed_us();
            encrypt_us += sw_encrypt.elapsed_us();
            decrypt_us += sw_decrypt.elapsed_us();

            ct_len += to.size();
            num_iter++;

            sw_total.stop();
            total_us += sw_total.elapsed_us();

        } while (total_us < duration_us);

        ct_len /= num_iter;

        json ibe_metrics = {
            {"parameter_set", ctx_client->get_set_name()},
            {"master_key_length", master_key.size()},
            {"public_key_length", public_key.size()},
            {"id_length", 16},
            {"plaintext_length", n},
            {"ciphertext_length", ct_len},
            {"keygen_us", keygen_us},
            {"keygen_per_sec", (1000000.0f)/static_cast<float>(keygen_us)},
            {"extract_us", static_cast<float>(extract_us)/num_iter},
            {"extract_per_sec", static_cast<uint32_t>((num_iter*1000000.0f)/static_cast<float>(extract_us))},
            {"encrypt_us", static_cast<float>(encrypt_us)/num_iter},
            {"encrypt_per_sec", static_cast<uint32_t>((num_iter*1000000.0f)/static_cast<float>(encrypt_us))},
            {"decrypt_us", static_cast<float>(decrypt_us)/num_iter},
            {"decrypt_per_sec", static_cast<uint32_t>((num_iter*1000000.0f)/static_cast<float>(decrypt_us))}
        };

        ibe_performance.push_back(ibe_metrics);

        param_set++;
    } while (param_set < ctx_pkg->get_set_names().size());

    json ibe_header = {
        {"type", "IBE"},
        {"scheme", "DLP"},
        {"metrics", json::array()}
    };
    ibe_header["metrics"] = ibe_performance;

    return ibe_header;
}
