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

#include "schemes/kem/kyber/kyber_kem.hpp"
#include "logging/logger.hpp"
#include "utils/stopwatch.hpp"

using namespace phantom;  // NOLINT

#define NUM_ITER   4096


int main(int argc, char *argv[])
{
    std::cout << "Kyber KEM Test" << std::endl;

    phantom_vector<uint8_t> m(128);

    for (size_t i=0; i < 3; i++) {

        utilities::stopwatch sw_keygen, sw_encap, sw_decap;
        uint32_t keygen_us = 0, encap_us = 0, decap_us = 0;

        pkc dut_a(PKC_KEM_KYBER);
        pkc dut_b(PKC_KEM_KYBER);
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

            phantom_vector<uint8_t> ct_a;
            phantom_vector<uint8_t> key_a;
            phantom_vector<uint8_t> ct_b;
            phantom_vector<uint8_t> key_b;

            phantom_vector<uint8_t> pkb;
            dut_b.get_public_key(ctx_b, pkb);

            sw_encap.start();
            dut_a.kem_encapsulate(ctx_a, pkb, ct_a, key_a);
            sw_encap.stop();

            sw_decap.start();
            bool ready = dut_b.kem_decapsulate(ctx_b, ct_a, key_b);
            if (!ready) {
                std::cerr << "Decapsulation failed" << std::endl;
                return EXIT_FAILURE;
            }
            sw_decap.stop();

            for (size_t k=0; k < 32; k++) {
                if (key_a[k] != key_b[k]) {
                    std::cerr << "Decapsulation mismatch" << std::endl;
                    return EXIT_FAILURE;
                }
            }

            keygen_us += sw_keygen.elapsed_us();
            encap_us  += sw_encap.elapsed_us();
            decap_us  += sw_decap.elapsed_us();
        }

        std::cout << "KYBER " << ctx_a->get_set_name() << std::endl;
        std::cout << "keygen time        = " << static_cast<float>(keygen_us)/(2*NUM_ITER)
            << " us, " << (2*NUM_ITER*1000000.0f)/static_cast<float>(keygen_us) << " per sec" << std::endl;
        std::cout << "encapsualtion time = " << static_cast<float>(encap_us)/(NUM_ITER)
            << " us, "  << (NUM_ITER*1000000.0f)/static_cast<float>(encap_us)  << " per sec" << std::endl;
        std::cout << "decapsulation time = " << static_cast<float>(decap_us)/(NUM_ITER)
            << " us, "  << (NUM_ITER*1000000.0f)/static_cast<float>(decap_us)  << " per sec" << std::endl;
    }

    return EXIT_SUCCESS;
}
