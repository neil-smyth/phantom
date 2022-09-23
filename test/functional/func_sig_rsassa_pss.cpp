/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include <cstdlib>
#include <iostream>

#include "./phantom.hpp"
#include "logging/logger.hpp"
#include "utils/stopwatch.hpp"

using namespace phantom;    // NOLINT
using namespace utilities;  // NOLINT

#define NUM_ITER   64


int main(int argc, char *argv[])
{
    std::cout << "RSASSA-PSS Test" << std::endl;

    phantom_vector<uint8_t> m(128);
    for (size_t i=0; i < 128; i++) { m[i] = i; }

    for (size_t i=0; i < 3; i++) {

        stopwatch sw_keygen, sw_sign, sw_verify;
        uint32_t keygen_us = 0, sign_us = 0, verify_us = 0;

        pkc rsa(PKC_SIG_RSASSA_PSS);
        std::unique_ptr<user_ctx> ctx_sign   = rsa.create_ctx(i, NATIVE_CPU_WORD_SIZE, true);
        std::unique_ptr<user_ctx> ctx_verify = rsa.create_ctx(i, NATIVE_CPU_WORD_SIZE, false);

        for (size_t j=0; j < NUM_ITER; j++) {
            sw_keygen.start();
            if (!rsa.keygen(ctx_sign)) {
                std::cerr << "KeyGen failed" << std::endl;
                return EXIT_FAILURE;
            }
            sw_keygen.stop();

            phantom_vector<uint8_t> s;
            sw_sign.start();
            if (!rsa.sig_sign(ctx_sign, m, s)) {
                std::cerr << "Signing failed" << std::endl;
                return EXIT_FAILURE;
            }
            sw_sign.stop();

            phantom_vector<uint8_t> pk;
            rsa.get_public_key(ctx_sign, pk);
            rsa.set_public_key(ctx_verify, pk);

            sw_verify.start();
            bool verified = rsa.sig_verify(ctx_verify, m, s);
            sw_verify.stop();

            keygen_us += sw_keygen.elapsed_us();
            sign_us   += sw_sign.elapsed_us();
            verify_us += sw_verify.elapsed_us();

            if (!verified) {
                std::cerr << "Could not verify signature" << std::endl;
                return EXIT_FAILURE;
            }
        }

        std::cout << "RSASSA-PSS-" << ctx_sign->get_set_name() << std::endl;
        std::cerr << "keygen time = " << static_cast<float>(keygen_us)/(NUM_ITER)
            << " us, "  << (NUM_ITER*1000000.0f)/static_cast<float>(keygen_us)
                << " per sec" << std::endl;
        std::cerr << "sign time   = " << static_cast<float>(sign_us)/(NUM_ITER)
            << " us, "    << (NUM_ITER*1000000.0f)/static_cast<float>(sign_us)  << " per sec" << std::endl;
        std::cerr << "verify time = " << static_cast<float>(verify_us)/(NUM_ITER)
            << " us, "  << (NUM_ITER*1000000.0f)/static_cast<float>(verify_us)  << " per sec" << std::endl;
    }

    return EXIT_SUCCESS;
}
