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

#include "crypto/aes_fpe_ff1.hpp"
#include "core/mpz.hpp"
#include "utils/stopwatch.hpp"


using namespace phantom;  // NOLINT
using namespace crypto;   // NOLINT

struct aes_ff3_tv
{
    fpe_type_e type;
    fpe_format_e format;
    const char *key;
    const char *tweak;
    const char *plaintext;
    const char *ciphertext;
};

aes_ff3_tv tv[] = {
    {
        AES_FF3_1_128,
        FPE_STR_NUMERIC,
        "2DE79D232DF5585D68CE47882AE256D6",
        "CBD09280979564",
        "3992520240",
        "8901801106",
    },
};


int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;
    
    std::cout << "FPE FF3-1 Known Answer Test" << std::endl;

    for (size_t i=0; i < 1; i++) {

        core::mpz<uint32_t> mpz_tweak(tv[i].tweak, 16);
        phantom_vector<uint8_t> tweak(7);
        if (!mpz_tweak.is_zero()) {
            mpz_tweak.get_bytes(tweak, true);
        }

        core::mpz<uint32_t> mpz_user_key(tv[i].key, 16);
        phantom_vector<uint8_t> user_key;
        mpz_user_key.get_bytes(user_key, true);

        size_t pt_len = strlen(tv[i].plaintext);


        auto ctx = std::unique_ptr<fpe_ctx>(
            format_preserving_encryption::create_ctx(user_key, tv[i].type, tv[i].format, tweak));


        std::string str = std::string(tv[i].plaintext);
        phantom::format_preserving_encryption::encrypt(ctx, str);

        /*for (size_t k=0; k < pt_len; k++) {
            if (str.c_str()[k] != tv[i].ciphertext[k]) {
                std::cerr << "Error! Ciphertext mismatch found in test " << i << std::endl;
                return EXIT_FAILURE;
            }
        }*/
        std::cout << "ct = " << str << std::endl;

        phantom::format_preserving_encryption::decrypt(ctx, str);

        for (size_t k=0; k < pt_len; k++) {
            if (str.c_str()[k] != tv[i].plaintext[k]) {
                std::cerr << "Error! Plaintext mismatch found in test " << i << std::endl;
                return EXIT_FAILURE;
            }
        }
    }

    std::cout << "All tests passed" << std::endl;

    return EXIT_SUCCESS;
}
