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

#include "schemes/signature/falcon/falcon_signature.hpp"
#include "logging/logger.hpp"
#include "utils/stopwatch.hpp"

using namespace phantom;    // NOLINT
using namespace utilities;  // NOLINT

#define NUM_ITER   128


int main(int argc, char *argv[])
{
    std::cout << "Falcon Test" << std::endl;

    phantom_vector<uint8_t> m(128);

    for (size_t i=0; i < 2; i++) {

        stopwatch sw_keygen, sw_sign, sw_verify;
        uint32_t keygen_us = 0, sign_us = 0, verify_us = 0;

        pkc falcon(PKC_SIG_FALCON);
        std::unique_ptr<user_ctx> ctx = falcon.create_ctx(i);

        for (size_t j=0; j < NUM_ITER; j++) {
            sw_keygen.start();
            if (!falcon.keygen(ctx)) {
                std::cerr << "KeyGen failed" << std::endl;
                return EXIT_FAILURE;
            }
            sw_keygen.stop();

            phantom_vector<uint8_t> s;
            sw_sign.start();
            falcon.sig_sign(ctx, m, s);
            sw_sign.stop();

            sw_verify.start();
            bool verified = falcon.sig_verify(ctx, m, s);
            sw_verify.stop();

            keygen_us += sw_keygen.elapsed_us();
            sign_us   += sw_sign.elapsed_us();
            verify_us += sw_verify.elapsed_us();

            if (!verified) {
                std::cerr << "Could not verify signature" << std::endl;
                return EXIT_FAILURE;
            }
        }

        std::cout << "FALCON-" << ((0 == i)? "512" : "1024") << std::endl;
        std::cerr << "keygen time = " << static_cast<float>(keygen_us)/(NUM_ITER)
            << " us, "  << (NUM_ITER*1000000.0f)/static_cast<float>(keygen_us) << " per sec" << std::endl;
        std::cerr << "sign time   = " << static_cast<float>(sign_us)/(NUM_ITER)
            << " us, "    << (NUM_ITER*1000000.0f)/static_cast<float>(sign_us)  << " per sec" << std::endl;
        std::cerr << "verify time = " << static_cast<float>(verify_us)/(NUM_ITER)
            << " us, "  << (NUM_ITER*1000000.0f)/static_cast<float>(verify_us)  << " per sec" << std::endl;
    }

    return EXIT_SUCCESS;
}
