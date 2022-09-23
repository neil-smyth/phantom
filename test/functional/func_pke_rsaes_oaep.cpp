/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include <cstdlib>
#include <iostream>

#include "schemes/pke/rsaes_oaep/rsaes_oaep_pke.hpp"
#include "logging/logger.hpp"
#include "utils/stopwatch.hpp"

using namespace phantom;    // NOLINT
using namespace utilities;  // NOLINT


int main(int argc, char *argv[])
{
    std::cout << "RSA RSAES-OAEP Test" << std::endl;

    for (size_t i=0; i < 5; i++) {

        stopwatch sw_test, sw_keygen, sw_enc, sw_dec;
        uint32_t test_us = 0, keygen_us = 0, enc_us = 0, dec_us = 0;

        pkc dut_a(PKC_PKE_RSAES_OAEP);
        pkc dut_b(PKC_PKE_RSAES_OAEP);
        std::unique_ptr<user_ctx> ctx_a = dut_a.create_ctx(i, NATIVE_CPU_WORD_SIZE, false);
        std::unique_ptr<user_ctx> ctx_b = dut_b.create_ctx(i, NATIVE_CPU_WORD_SIZE, true);

        std::cout << ctx_a->get_set_name() << " bits" << std::endl;

        sw_keygen.start();
        if (!dut_a.keygen(ctx_a)) {
            std::cerr << "KeyGen failed" << std::endl;
            return EXIT_FAILURE;
        }
        if (!dut_b.keygen(ctx_b)) {
            std::cerr << "KeyGen failed" << std::endl;
            return EXIT_FAILURE;
        }
        sw_keygen.stop();

        keygen_us += sw_keygen.elapsed_us();

        std::cout << "keygen time     = " << static_cast<float>(keygen_us)/(2)
            << " us, " << (2*1000000.0f)/static_cast<float>(keygen_us) << " per sec" << std::endl;

        phantom_vector<uint8_t> pk;
        dut_b.get_public_key(ctx_b, pk);
        dut_a.set_public_key(ctx_a, pk);

        sw_test.start();

        size_t num_iter = 0;
        for (;;) {
            phantom_vector<uint8_t> pt(32);
            for (size_t i=0; i < 32; i++) { pt[i] = i; }
            phantom_vector<uint8_t> ct;
            phantom_vector<uint8_t> pt2;

            sw_enc.start();
            dut_a.pke_encrypt(ctx_a, pt, ct);
            sw_enc.stop();

            sw_dec.start();
            bool ready = dut_b.pke_decrypt(ctx_b, ct, pt2);
            if (!ready) {
                std::cerr << "Decryption failed" << std::endl;
                return EXIT_FAILURE;
            }
            sw_dec.stop();

            for (size_t k=0; k < 32; k++) {
                if (pt2[k] != pt[k]) {
                    std::cerr << "Decryption failed - mismatch " << k << std::endl;
                    return EXIT_FAILURE;
                }
            }

            sw_test.stop();

            test_us   += sw_test.elapsed_us();
            enc_us    += sw_enc.elapsed_us();
            dec_us    += sw_dec.elapsed_us();

            num_iter++;
            if (test_us >= 10000000) {
                break;
            }

            sw_test.start();
        }

        std::cout << "encryption time = " << static_cast<float>(enc_us)/(num_iter)
            << " us, " << (num_iter*1000000.0f)/static_cast<float>(enc_us)  << " per sec" << std::endl;
        std::cout << "decryption time = " << static_cast<float>(dec_us)/(num_iter)
            << " us, " << (num_iter*1000000.0f)/static_cast<float>(dec_us)  << " per sec" << std::endl;
    }

    return EXIT_SUCCESS;
}
