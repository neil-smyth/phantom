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
#include "schemes/ibe/dlp/ibe_dlp.hpp"
#include "crypto/csprng.hpp"
#include "logging/logger.hpp"
#include "utils/stopwatch.hpp"
#include "core/poly.hpp"
#include "core/mpz.hpp"

using namespace phantom;    // NOLINT
using namespace utilities;  // NOLINT
using namespace core;       // NOLINT

#define NUM_ITER   1024


int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;
    
    std::cout << "DLP-IBE Test" << std::endl;

    for (size_t i=0; i < 2; i++) {

        stopwatch sw_keygen, sw_extract, sw_encrypt, sw_decrypt;
        uint32_t keygen_us = 0, extract_us = 0, encrypt_us = 0, decrypt_us = 0;

        // Create an instance of a DLP-IBE Private Key Generator
        pkc ibe_dlp_a(PKC_IBE_DLP);
        pkc ibe_dlp_b(PKC_IBE_DLP);
        std::unique_ptr<user_ctx> ctx_pkg = ibe_dlp_a.create_ctx(i);

        size_t n = ibe_dlp_a.get_msg_len(ctx_pkg);

        sw_keygen.start();
        ibe_dlp_a.keygen(ctx_pkg);
        sw_keygen.stop();
        keygen_us  += sw_keygen.elapsed_us();

        // Obtain the IBE public key
        phantom_vector<uint8_t> public_key;
        ibe_dlp_a.get_public_key(ctx_pkg, public_key);

        std::unique_ptr<user_ctx> ctx_client = ibe_dlp_a.create_ctx(i);
        std::unique_ptr<user_ctx> ctx_server = ibe_dlp_b.create_ctx(i);

        for (size_t j = 0; j < NUM_ITER; j++) {

            // Generate the plaintext
            phantom_vector<uint8_t> pt(n);
            for (size_t i = 0; i < n; i++) {
                pt[i] = (i + j) % 256;
            }

            // Generate a User ID
            uint8_t id[32] = "    @foobar";
            id[0] = ((j/1000) % 10) + 48;
            id[1] = ((j/100) % 10) + 48;
            id[2] = ((j/10) % 10) + 48;
            id[3] = (j % 10) + 48;

            phantom_vector<uint8_t> vec_id(id, id + 11);
            phantom_vector<uint8_t> vec_user_key;

            // Extract the User Key from the PKG
            sw_extract.start();
            ibe_dlp_a.ibe_extract(ctx_pkg, vec_id, vec_user_key);
            sw_extract.stop();

            // Load the public key into the client and encrypt the message
            phantom_vector<uint8_t> to, rec;
            ibe_dlp_a.set_public_key(ctx_client, public_key);
            sw_encrypt.start();
            ibe_dlp_a.ibe_encrypt(ctx_client, vec_id, pt, to);
            sw_encrypt.stop();

            // The server obtains the User Key and decrypts the message
            ibe_dlp_b.ibe_load_user_key(ctx_server, vec_id, vec_user_key);
            sw_decrypt.start();
            ibe_dlp_b.ibe_decrypt(ctx_server, to, rec);
            sw_decrypt.stop();

            // Verify that the decrypted message is correct
            for (size_t i = 0; i < n; i++) {
                if (pt[i] != rec[i]) {
                    fprintf(stderr, "Decryption mismatch:\n");
                    return EXIT_FAILURE;
                }
            }

            extract_us += sw_extract.elapsed_us();
            encrypt_us += sw_encrypt.elapsed_us();
            decrypt_us += sw_decrypt.elapsed_us();
        }

        std::cout << "DLP " << ((0 == i)? "Light" : (1 == i)? "Normal" : "Paranoid") << std::endl;
        std::cout << "keygen time  = " << static_cast<float>(keygen_us) << " us, "
                  << (1000000.0f)/static_cast<float>(keygen_us) << " per sec" << std::endl;
        std::cout << "extract time = " << static_cast<float>(extract_us)/(NUM_ITER) << " us, "
                  << (NUM_ITER*1000000.0f)/static_cast<float>(extract_us) << " per sec" << std::endl;
        std::cout << "encrypt time = " << static_cast<float>(encrypt_us)/(NUM_ITER) << " us, "
                  << (NUM_ITER*1000000.0f)/static_cast<float>(encrypt_us)  << " per sec" << std::endl;
        std::cout << "decrypt time = " << static_cast<float>(decrypt_us)/(NUM_ITER) << " us, "
                  << (NUM_ITER*1000000.0f)/static_cast<float>(decrypt_us)  << " per sec" << std::endl;
    }

    return EXIT_SUCCESS;
}
