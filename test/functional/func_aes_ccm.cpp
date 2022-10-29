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
#include "crypto/random_seed.hpp"
#include "utils/stopwatch.hpp"


using namespace phantom;  // NOLINT

#define NUM_ITER   65536


int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;
    
    std::cout << "AES-CCM Test" << std::endl;

    std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0x10000000, &random_seed::seed_cb));

    for (size_t i=0; i < 3; i++) {

        utilities::stopwatch sw_encrypt, sw_decrypt;
        uint32_t encrypt_us = 0, decrypt_us = 0;

        symmetric_key_type_e key_type = (0 == i) ? SYMKEY_AES_128_CCM :
                                        (1 == i) ? SYMKEY_AES_192_CCM
                                                 : SYMKEY_AES_256_CCM;

        size_t key_len = (0 == i) ? 16 : (1 == i) ? 24 : 32;
        phantom_vector<uint8_t> key(key_len);

        size_t num_bytes = (0 == i) ? 16 : (1 == i) ? 520 : 8192;
        size_t num_aad_bytes = rng->get_u8();

        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(key_type));
        auto aesdec = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(key_type));

        for (size_t j=0; j < NUM_ITER/64; j++) {

            phantom_vector<uint8_t> pt(num_bytes), ct(num_bytes), rt(num_bytes), aad(num_aad_bytes), nonce(12);
            phantom_vector<uint8_t> auth_tag(4), recovered_tag(4);
            rng->get_mem(key.data(), key_len);
            rng->get_mem(pt.data(), num_bytes);
            rng->get_mem(aad.data(), num_aad_bytes);
            rng->get_mem(nonce.data(), 6);

            sw_encrypt.start();
            for (size_t k=0; k < 64; k++) {
                symmetric_key_cipher::set_key(aesenc.get(), key.data(), key.size());
                symmetric_key_cipher::encrypt_start(aesenc.get(), nonce.data(), 6, aad.data(), num_aad_bytes, num_bytes, 4);
                symmetric_key_cipher::encrypt(aesenc.get(), ct.data(), pt.data(), num_bytes);
                symmetric_key_cipher::encrypt_finish(aesenc.get(), auth_tag.data(), 4);
            }
            sw_encrypt.stop();

            sw_decrypt.start();
            for (size_t k=0; k < 64; k++) {
                symmetric_key_cipher::set_key(aesdec.get(), key.data(), key.size());
                symmetric_key_cipher::decrypt_start(aesdec.get(), nonce.data(), 6, aad.data(), num_aad_bytes, num_bytes, 4);
                symmetric_key_cipher::decrypt(aesdec.get(), rt.data(), ct.data(), num_bytes);
                symmetric_key_cipher::decrypt_finish(aesdec.get(), recovered_tag.data(), 4);
            }
            sw_decrypt.stop();

            encrypt_us += sw_encrypt.elapsed_us();
            decrypt_us += sw_decrypt.elapsed_us();

            for (size_t k=0; k < rt.size(); k++) {
                if (pt[k] != rt[k]) {
                    std::cerr << "Recovered data mismatch found" << std::endl;
                    return EXIT_FAILURE;
                }
            }

            for (size_t k=0; k < 4; k++) {
                if (auth_tag[k] != recovered_tag[k]) {
                    std::cerr << "Authentication tag mismatch found" << std::endl;
                    return EXIT_FAILURE;
                }
            }
        }

        std::cout << "AES-CCM length=" << static_cast<int>(num_bytes) << std::endl;
        std::cerr << "encrypt time = " << static_cast<float>(encrypt_us)/(NUM_ITER)
                  << " us, " << (NUM_ITER * 1000000.0f * num_bytes)/(static_cast<float>(encrypt_us) * 1024.0f * 1024.0f)
                  << " MB/sec" << std::endl;
        std::cerr << "decrypt time = " << static_cast<float>(decrypt_us)/(NUM_ITER)
                  << " us, " << (NUM_ITER * 1000000.0f * num_bytes)/(static_cast<float>(decrypt_us) * 1024.0f * 1024.0f)
                  << " MB/sec" << std::endl;
    }

    return EXIT_SUCCESS;
}
