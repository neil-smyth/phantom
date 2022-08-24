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

#include "schemes/signature/ecdsa/ecdsa_signature.hpp"
#include "logging/logger.hpp"
#include "utils/stopwatch.hpp"

using namespace phantom;    // NOLINT
using namespace utilities;  // NOLINT
using namespace core;     // NOLINT

#define NUM_ITER   1


int main(int argc, char *argv[])
{
    std::cout << "ECDSA Test" << std::endl;

    phantom_vector<uint8_t> m(128);
    for (size_t i=0; i < 128; i++) { m[i] = i; }

    for (size_t i=0; i < 5; i++) {

        stopwatch sw_keygen, sw_sign, sw_verify;
        uint32_t keygen_us = 0, sign_us = 0, verify_us = 0;

        pkc ecdsa(PKC_SIG_ECDSA);
        std::unique_ptr<user_ctx> ctx = ecdsa.create_ctx(i);

        for (size_t j=0; j < NUM_ITER; j++) {
            sw_keygen.start();
            if (!ecdsa.keygen(ctx)) {
                std::cerr << "KeyGen failed" << std::endl;
                return EXIT_FAILURE;
            }
            sw_keygen.stop();

            phantom_vector<uint8_t> privkey;
            if (!ecdsa.get_private_key(ctx, privkey)) {
                std::cerr << "get_private_key() failed" << std::endl;
                return EXIT_FAILURE;
            }
            std::cerr << "!!! privkey = " << mpz<uint8_t>(privkey.data(), privkey.size()).get_str(16) << std::endl;

            phantom_vector<uint8_t> pubkey;
            if (!ecdsa.get_public_key(ctx, pubkey)) {
                std::cerr << "get_private_key() failed" << std::endl;
                return EXIT_FAILURE;
            }
            std::cerr << "!!! pubkey = " << mpz<uint8_t>(pubkey.data(), pubkey.size()).get_str(16) << std::endl;

            std::cerr << "!!! j = " << j << std::endl;

            phantom_vector<uint8_t> s;
            sw_sign.start();
            ecdsa.sig_sign(ctx, m, s);
            sw_sign.stop();

            std::cerr << "!!! s = " << mpz<uint8_t>(s.data(), s.size()).get_str(16) << std::endl;

            std::cerr << "!!! Verify" << std::endl;

            sw_verify.start();
            bool verified = ecdsa.sig_verify(ctx, m, s);
            sw_verify.stop();

            keygen_us += sw_keygen.elapsed_us();
            sign_us   += sw_sign.elapsed_us();
            verify_us += sw_verify.elapsed_us();

            if (!verified) {
                std::cerr << "Could not verify signature" << std::endl;
                return EXIT_FAILURE;
            }
        }

        std::cout << "ECDSA-" << ((0 == i)? "P192" : (1 == i)? "P224" : (2 == i)? "P256" :
                                  (3 == i)? "P384" : (4 == i)? "P521" : (5 == i)? "B163" :
                                  (6 == i)? "B233" : (7 == i)? "B283" : (8 == i)? "B409" :
                                  (9 == i)? "B571" : (10 == i)? "K163" : (11 == i)? "K233" :
                                  (12 == i)? "K283" : (13 == i)? "K409" : "K571") << std::endl;
        std::cerr << "keygen time = " << static_cast<float>(keygen_us)/(NUM_ITER)
            << " us, "  << (NUM_ITER*1000000.0f)/static_cast<float>(keygen_us) << " per sec" << std::endl;
        std::cerr << "sign time   = " << static_cast<float>(sign_us)/(NUM_ITER)
            << " us, "    << (NUM_ITER*1000000.0f)/static_cast<float>(sign_us)  << " per sec" << std::endl;
        std::cerr << "verify time = " << static_cast<float>(verify_us)/(NUM_ITER)
            << " us, "  << (NUM_ITER*1000000.0f)/static_cast<float>(verify_us)  << " per sec" << std::endl;
    }

    return EXIT_SUCCESS;
}
