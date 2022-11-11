/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include <cstdlib>
#include <iostream>

#include "schemes/pke/kyber/kyber_pke.hpp"
#include "logging/logger.hpp"
#include "utils/stopwatch.hpp"

using namespace phantom;    // NOLINT
using namespace utilities;  // NOLINT

#define NUM_ITER   4096


int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;
    
    std::cout << "Kyber PKE Test" << std::endl;

    phantom_vector<uint8_t> m(128);

    for (size_t i=0; i < 3; i++) {

        stopwatch sw_keygen, sw_enc, sw_dec;
        uint32_t keygen_us = 0, enc_us = 0, dec_us = 0;

        pkc dut_a(PKC_PKE_KYBER);
        pkc dut_b(PKC_PKE_KYBER);
        std::unique_ptr<user_ctx> ctx_a = dut_a.create_ctx(i);
        std::unique_ptr<user_ctx> ctx_b = dut_b.create_ctx(i);

        for (size_t j=0; j < NUM_ITER; j++) {
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

            phantom_vector<uint8_t> pt(32);
            for (size_t i=0; i < 32; i++) { pt[i] = i; }
            phantom_vector<uint8_t> ct;
            phantom_vector<uint8_t> pt2;

            phantom_vector<uint8_t> pkb;
            dut_b.get_public_key(ctx_b, pkb);
            dut_a.set_public_key(ctx_a, pkb);

            sw_enc.start();
            dut_a.pke_encrypt(ctx_a, pt, ct);
            sw_enc.stop();

            bool ready;
            sw_dec.start();
            ready = dut_b.pke_decrypt(ctx_b, ct, pt2);
            if (!ready) {
                std::cerr << "Decryption failed" << std::endl;
                return EXIT_FAILURE;
            }
            sw_dec.stop();

            for (size_t k=0; k < 32; k++) {
                if (pt2[k] != pt[k]) {
                    std::cerr << "Decryption failed - mismatch" << std::endl;
                    return EXIT_FAILURE;
                }
            }

            keygen_us += sw_keygen.elapsed_us();
            enc_us    += sw_enc.elapsed_us();
            dec_us    += sw_dec.elapsed_us();
        }

        std::cout << "KYBER " << ctx_a->get_set_name() << std::endl;
        std::cout << "keygen time     = " << static_cast<float>(keygen_us)/(2*NUM_ITER)
            << " us, " << (2*NUM_ITER*1000000.0f)/static_cast<float>(keygen_us) << " per sec" << std::endl;
        std::cout << "encryption time = " << static_cast<float>(enc_us)/(NUM_ITER)
            << " us, " << (NUM_ITER*1000000.0f)/static_cast<float>(enc_us)  << " per sec" << std::endl;
        std::cout << "decryption time = " << static_cast<float>(dec_us)/(NUM_ITER)
            << " us, " << (NUM_ITER*1000000.0f)/static_cast<float>(dec_us)  << " per sec" << std::endl;
    }

    return EXIT_SUCCESS;
}
