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
#include <iterator>

#include "schemes/kem/kyber/kyber_kem.hpp"
#include "logging/logger.hpp"
#include "utils/stopwatch.hpp"


using namespace phantom;    // NOLINT
using namespace utilities;  // NOLINT

#define NUM_ITER   128


int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;
    
    std::cout << "ECDH Key Exchange Test" << std::endl;

    phantom_vector<uint8_t> m(128);

    for (size_t i=0; i < 17; i++) {

        stopwatch sw_init, sw_final;
        uint32_t init_us = 0, final_us = 0;

        pkc dut_a(PKC_KEY_ECDH);
        pkc dut_b(PKC_KEY_ECDH);
        std::unique_ptr<user_ctx> ctx_a = dut_a.create_ctx(i);
        std::unique_ptr<user_ctx> ctx_b = dut_b.create_ctx(i);


        dut_a.key_exchange_setup(ctx_a);
        dut_b.key_exchange_setup(ctx_b);

        for (size_t j=0; j < NUM_ITER; j++) {
            phantom_vector<uint8_t> ct_a;
            phantom_vector<uint8_t> ma, mb;
            phantom_vector<uint8_t> ct_b;
            phantom_vector<uint8_t> sa, sb;

            bool retval;

            sw_init.start();
            retval = dut_a.key_exchange_init(ctx_a, ma);
            if (!retval) {
                std::cerr << "A Key Exchange Initialization failed" << std::endl;
                return EXIT_FAILURE;
            }
            retval = dut_b.key_exchange_init(ctx_b, mb);
            if (!retval) {
                std::cerr << "B Key Exchange Initialization failed" << std::endl;
                return EXIT_FAILURE;
            }
            sw_init.stop();

            sw_final.start();
            retval = dut_a.key_exchange_final(ctx_a, mb, sa);
            if (!retval) {
                std::cerr << "A Key Exchange Finalization failed" << std::endl;
                return EXIT_FAILURE;
            }
            retval = dut_b.key_exchange_final(ctx_b, ma, sb);
            if (!retval) {
                std::cerr << "B Key Exchange Finalization failed" << std::endl;
                return EXIT_FAILURE;
            }
            sw_final.stop();

            for (size_t k=0; k < dut_a.get_msg_len(ctx_a); k++) {
                if (sa[k] != sb[k]) {
                    std::cerr << "Key Exchange mismatch " << i << " " << j << std::endl;

                    std::cout << "sa = ";
                    std::copy(sa.begin(), sa.end(), std::ostream_iterator<int>(std::cout, " "));
                    std::cout << std::endl;

                    std::cout << "sb = ";
                    std::copy(sb.begin(), sb.end(), std::ostream_iterator<int>(std::cout, " "));
                    std::cout << std::endl;

                    return EXIT_FAILURE;
                }
            }

            init_us  += sw_init.elapsed_us();
            final_us  += sw_final.elapsed_us();
        }

        std::cout << "ECDH " << ((0 == i)? "secp192r1" : (1 == i)? "secp224r1" : (2 == i)? "secp256r1" :
                                 (3 == i)? "secp384r1" : (4 == i)? "secp521r1" : (5 == i)? "sect163r2" :
                                 (6 == i)? "sect233r1" : (7 == i)? "sect283r1" : (8 == i)? "sect409r1" :
                                 (9 == i)? "sect571r1" : (10 == i)? "sect163k1" : (11 == i)? "sect233k1" :
                                 (12 == i)? "sect283k1" : (13 == i)? "sect409rk1" : (14 == i)? "sect571k1" :
                                 (15 == i)? "curve25519" : "curve448") << std::endl;
        std::cout << "initialization time = " << static_cast<float>(init_us)/(2*NUM_ITER)
            << " us, "  << (2*NUM_ITER*1000000.0f)/static_cast<float>(init_us)  << " per sec" << std::endl;
        std::cout << "finalization time   = " << static_cast<float>(final_us)/(2*NUM_ITER)
            << " us, "  << (2*NUM_ITER*1000000.0f)/static_cast<float>(final_us)  << " per sec" << std::endl;
    }

    return EXIT_SUCCESS;
}
