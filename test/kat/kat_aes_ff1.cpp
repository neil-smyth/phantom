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

struct aes_ff1_tv
{
    fpe_type_e type;
    fpe_format_e format;
    const char *key;
    const char *tweak;
    const char *plaintext;
    const char *ciphertext;
};

aes_ff1_tv tv[] = {
    {
        AES_FF1_128,
        FPE_STR_NUMERIC,
        "2B7E151628AED2A6ABF7158809CF4F3C",
        "",
        "0123456789",
        "2433477484",
    },
    {
        AES_FF1_128,
        FPE_STR_NUMERIC,
        "2B7E151628AED2A6ABF7158809CF4F3C",
        "39383736353433323130",
        "0123456789",
        "6124200773",
    },
    {
        AES_FF1_128,
        FPE_STR_LOWER_ALPHANUMERIC,
        "2B7E151628AED2A6ABF7158809CF4F3C",
        "3737373770717273373737",
        "0123456789abcdefghi",
        "a9tv40mll9kdu509eum",
    },
    {
        AES_FF1_192,
        FPE_STR_NUMERIC,
        "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F",
        "",
        "0123456789",
        "2830668132",
    },
    {
        AES_FF1_192,
        FPE_STR_NUMERIC,
        "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F",
        "39383736353433323130",
        "0123456789",
        "2496655549",
    },
    {
        AES_FF1_192,
        FPE_STR_LOWER_ALPHANUMERIC,
        "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F",
        "3737373770717273373737",
        "0123456789abcdefghi",
        "xbj3kv35jrawxv32ysr",
    },
    {
        AES_FF1_256,
        FPE_STR_NUMERIC,
        "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94",
        "",
        "0123456789",
        "6657667009",
    },
    {
        AES_FF1_256,
        FPE_STR_NUMERIC,
        "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94",
        "39383736353433323130",
        "0123456789",
        "1001623463",
    },
    {
        AES_FF1_256,
        FPE_STR_LOWER_ALPHANUMERIC,
        "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94",
        "3737373770717273373737",
        "0123456789abcdefghi",
        "xs8a0azh2avyalyzuwd",
    },
};


int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;
    
    std::cout << "FPE FF1 Known Answer Test" << std::endl;

    for (size_t i=0; i < 9; i++) {

        core::mpz<uint32_t> mpz_tweak(tv[i].tweak, 16);
        phantom_vector<uint8_t> tweak;
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

        for (size_t k=0; k < pt_len; k++) {
            if (str.c_str()[k] != tv[i].ciphertext[k]) {
                std::cerr << "Error! Ciphertext mismatch found in test " << i << std::endl;
                return EXIT_FAILURE;
            }
        }

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
