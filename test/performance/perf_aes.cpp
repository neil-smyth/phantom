/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "test/performance/perf_aes.hpp"
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


json perf_aes::run(symmetric_key_type_e key_type, size_t duration_us)
{
    std::cout << "  SYMMETRIC KEY :: AES" << std::endl;

    stopwatch sw_total, sw_keygen, sw_encrypt, sw_decrypt;
    std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0, &random_seed::seed_cb));
    json aes_performance = json::array();

    std::unique_ptr<user_ctx> ctx;

    if (SYMKEY_AES_128_ENC == key_type || SYMKEY_AES_192_ENC == key_type || SYMKEY_AES_256_ENC == key_type) {

        symmetric_key_type_e enc_key_type = key_type;
        symmetric_key_type_e dec_key_type = (SYMKEY_AES_128_ENC == key_type) ? SYMKEY_AES_128_DEC :
                                            (SYMKEY_AES_192_ENC == key_type) ? SYMKEY_AES_192_DEC
                                                                             : SYMKEY_AES_256_DEC;

        size_t num_key_bytes = (SYMKEY_AES_128_ENC == key_type) ? 16 :
                               (SYMKEY_AES_192_ENC == key_type) ? 24 :
                                                                  32;
        uint32_t total_us = 0;
        size_t num_iter;

        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(enc_key_type));
        auto aesdec = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(dec_key_type));

        size_t num_bytes = 16;
        do {
            uint32_t keygen_per_sec = 0, encrypt_bytes_per_sec = 0, decrypt_bytes_per_sec = 0;

            phantom_vector<uint8_t> key(num_key_bytes), pt(num_bytes), ct(num_bytes);
            rng->get_mem(key.data(), num_key_bytes);
            rng->get_mem(pt.data(), num_bytes);

            num_iter = 0;
            total_us = 0;
            do {
                sw_total.start();
                for (size_t i = 0; i < 2048; i++) {
                    symmetric_key_cipher::set_key(aesenc.get(), key.data(), key.size());
                }
                sw_total.stop();
                num_iter += 2048;
                total_us += sw_total.elapsed_us();
            } while (total_us < duration_us);

            keygen_per_sec = static_cast<uint32_t>((static_cast<float>(num_iter)*1000000.0f)/static_cast<float>(total_us));

            num_iter = 0;
            total_us = 0;
            do {
                sw_total.start();
                for (size_t i = 0; i < 2048; i++) {
                    symmetric_key_cipher::encrypt(aesenc.get(), ct.data(), pt.data(), num_bytes);
                }
                sw_total.stop();
                num_iter += 2048;
                total_us += sw_total.elapsed_us();
            } while (total_us < duration_us);

            encrypt_bytes_per_sec = (static_cast<float>(num_bytes)*static_cast<float>(num_iter)*1000000.0f)/static_cast<float>(total_us);

            symmetric_key_cipher::set_key(aesdec.get(), key.data(), key.size());
            num_iter = 0;
            total_us = 0;
            do {
                sw_total.start();
                for (size_t i = 0; i < 2048; i++) {
                    symmetric_key_cipher::decrypt(aesdec.get(), pt.data(), ct.data(), num_bytes);
                }
                sw_total.stop();
                num_iter += 2048;
                total_us += sw_total.elapsed_us();
            } while (total_us < duration_us);

            decrypt_bytes_per_sec = (static_cast<float>(num_bytes)*static_cast<float>(num_iter)*1000000.0f)/static_cast<float>(total_us);

            json hash_metrics_16 = {
                {"message_length", num_bytes},
                {"keygen_per_sec", keygen_per_sec},
                {"encrypt_bytes_per_sec", encrypt_bytes_per_sec},
                {"decrypt_bytes_per_sec", decrypt_bytes_per_sec}
            };

            aes_performance.push_back(hash_metrics_16);

            num_bytes += num_bytes;
        } while (num_bytes <= 16384);

        json ecb_header = {
            {"scheme", "AES-ECB"},
            {"key_length", num_key_bytes},
            {"metrics", json::array()}
        };
        ecb_header["metrics"] = aes_performance;

        return ecb_header;
    }

    json empty = {};
    return empty;
}
