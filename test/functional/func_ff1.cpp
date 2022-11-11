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

#include "crypto/aes_fpe_ff1.hpp"
#include "utils/stopwatch.hpp"


using namespace phantom;  // NOLINT
using namespace crypto;   // NOLINT

#define NUM_ITER   65536

static void test_cb(size_t len, uint8_t* data)
{
    for (size_t i=0; i < len; i++) {
        data[i] = i + 1;
    }
}

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;
    
    std::cout << "FPE FF1 Test" << std::endl;

    std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0, &test_cb));

    for (size_t i=0; i < 3; i++) {

        utilities::stopwatch sw_encrypt, sw_decrypt;
        uint32_t encrypt_us = 0, decrypt_us = 0;

        phantom_vector<uint8_t> tweak;
        phantom_vector<uint8_t> user_key(16);
        rng->get_mem(user_key.data(), 16);

        fpe_format_e format = (i == 0)? FPE_STR_NUMERIC : FPE_STR_ALPHANUMERIC;
        size_t num_char = (i == 0)? 8 : (i == 1)? 12 : 16;
        size_t radix = (i < 1)? 10 : 62;

        std::unique_ptr<fpe_ctx> ctx = format_preserving_encryption::create_ctx(user_key, AES_FF1_128, format, tweak);

        for (size_t j=0; j < NUM_ITER; j++) {

            phantom_vector<uint8_t> pt(num_char), ct, rt;

            for (size_t k=0; k < num_char; k++) { pt[k] = rng->get_u8() % radix; }

            sw_encrypt.start();
            aes_fpe_ff1<uint8_t>::encrypt(ctx, radix, pt, ct);
            sw_encrypt.stop();

            sw_decrypt.start();
            aes_fpe_ff1<uint8_t>::decrypt(ctx, radix, ct, rt);
            sw_decrypt.stop();

            encrypt_us += sw_encrypt.elapsed_us();
            decrypt_us += sw_decrypt.elapsed_us();

            for (size_t k=0; k < rt.size(); k++) {
                if (pt[k] != rt[k]) {
                    std::cerr << "Mismatch found" << std::endl;
                    return EXIT_FAILURE;
                }
            }
        }

        std::cout << "AES-FPE-FF1 radix-" << radix << " length=" << static_cast<int>(num_char) << std::endl;
        std::cerr << "encrypt time = " << static_cast<float>(encrypt_us)/(NUM_ITER)
                  << " us, " << (NUM_ITER*1000000.0f)/static_cast<float>(encrypt_us)  << " per sec" << std::endl;
        std::cerr << "decrypt time = " << static_cast<float>(decrypt_us)/(NUM_ITER)
                  << " us, " << (NUM_ITER*1000000.0f)/static_cast<float>(decrypt_us)  << " per sec" << std::endl;
    }

    for (size_t i=0; i < 1; i++) {

        utilities::stopwatch sw_encrypt, sw_decrypt;
        uint32_t encrypt_us = 0, decrypt_us = 0;

        phantom_vector<uint8_t> tweak;
        phantom_vector<uint8_t> user_key(16);
        rng->get_mem(user_key.data(), 16);

        std::unique_ptr<fpe_ctx> ctx =
            format_preserving_encryption::create_ctx(user_key, AES_FF1_128, FPE_ISO8601, tweak);

        for (size_t j=1; j < 2700; j++) {

            std::string m, rt;
            m = (j&1)? "0000-12-31T23:59:59Z" : "0000-12-31T23:59:57Z";
            std::string yyyy = std::to_string(j);
            yyyy.insert(0, 4 - yyyy.size(), '0');
            m.replace(0, 4, yyyy);

            rt = m;
            sw_encrypt.start();
            format_preserving_encryption::encrypt(ctx, rt);
            sw_encrypt.stop();

            sw_decrypt.start();
            format_preserving_encryption::decrypt(ctx, rt);
            sw_decrypt.stop();

            encrypt_us += sw_encrypt.elapsed_us();
            decrypt_us += sw_decrypt.elapsed_us();

            for (size_t k=0; k < rt.size(); k++) {
                if (m[k] != rt[k]) {
                    std::cerr << "Mismatch found: " << m << ", " << rt << std::endl;
                    return EXIT_FAILURE;
                }
            }
        }

        std::cout << "AES-FPE-FF1 ISO8601" << std::endl;
        std::cerr << "encrypt time = " << static_cast<float>(encrypt_us)/(2699)
                  << " us, " << (2699*1000000.0f)/static_cast<float>(encrypt_us)  << " per sec" << std::endl;
        std::cerr << "decrypt time = " << static_cast<float>(decrypt_us)/(2699)
                  << " us, " << (2699*1000000.0f)/static_cast<float>(decrypt_us)  << " per sec" << std::endl;
    }

    return EXIT_SUCCESS;
}
