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

#include "crypto/aes.hpp"
#include "core/mpz.hpp"
#include "utils/stopwatch.hpp"


using namespace phantom;  // NOLINT
using namespace crypto;   // NOLINT

struct aes_ecb_tv
{
    aes_keylen_e keylen;
    const char  *key;
    const char  *plaintext;
    const char  *ciphertext;
};

aes_ecb_tv tv[] = {
    {
        AES_128,
        "2b7e151628aed2a6abf7158809cf4f3c",
        "6bc1bee22e409f96e93d7e117393172a",
        "3ad77bb40d7a3660a89ecaf32466ef97",
    },
    {
        AES_128,
        "2b7e151628aed2a6abf7158809cf4f3c",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "f5d3d58503b9699de785895a96fdbaaf",
    },
    {
        AES_128,
        "2b7e151628aed2a6abf7158809cf4f3c",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "43b1cd7f598ece23881b00e3ed030688",
    },
    {
        AES_128,
        "2b7e151628aed2a6abf7158809cf4f3c",
        "f69f2445df4f9b17ad2b417be66c3710",
        "7b0c785e27e8ad3f8223207104725dd4",
    },
    {
        AES_192,
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        "6bc1bee22e409f96e93d7e117393172a",
        "bd334f1d6e45f25ff712a214571fa5cc",
    },
    {
        AES_192,
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "974104846d0ad3ad7734ecb3ecee4eef",
    },
    {
        AES_192,
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "ef7afd2270e2e60adce0ba2face6444e",
    },
    {
        AES_192,
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        "f69f2445df4f9b17ad2b417be66c3710",
        "9a4b41ba738d6c72fb16691603c18e0e",
    },
    {
        AES_256,
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "6bc1bee22e409f96e93d7e117393172a",
        "f3eed1bdb5d2a03c064b5a7e3db181f8",
    },
    {
        AES_256,
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "591ccb10d410ed26dc5ba74a31362870",
    },
    {
        AES_256,
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "b6ed21b99ca6f4f9f153e7b1beafed1d",
    },
    {
        AES_256,
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "f69f2445df4f9b17ad2b417be66c3710",
        "23304b7a39f9f3ff067d8d8f9e24ecc7",
    },
};

int main(int argc, char *argv[])
{
    std::cout << "AES ECB Known Answer Test" << std::endl;

    for (size_t i=0; i < 12; i++) {

        core::mpz<uint32_t> mpz_key(tv[i].key, 16);
        phantom_vector<uint8_t> key;
        mpz_key.get_bytes(key, true);

        core::mpz<uint32_t> mpz_pt(tv[i].plaintext, 16);
        phantom_vector<uint8_t> pt;
        mpz_pt.get_bytes(pt, true);

        core::mpz<uint32_t> mpz_ref_ct(tv[i].ciphertext, 16);
        phantom_vector<uint8_t> ref_ct;
        mpz_ref_ct.get_bytes(ref_ct, true);

        uint8_t ct[16], rt[16];

        auto block_cipher_enc = std::unique_ptr<aes_encrypt>(aes_encrypt::make(tv[i].keylen));
        auto block_cipher_dec = std::unique_ptr<aes_decrypt>(aes_decrypt::make(tv[i].keylen));
        block_cipher_enc->set_key(key.data(), tv[i].keylen);
        block_cipher_enc->encrypt(ct, pt.data());
        block_cipher_dec->set_key(key.data(), tv[i].keylen);
        block_cipher_dec->decrypt(rt, ct);

        for (size_t k=0; k < 16; k++) {
            if (ref_ct[k] != ct[k]) {
                std::cerr << "Error! Ciphertext mismatch found in test " << i << std::endl;
                return EXIT_FAILURE;
            }
        }

        for (size_t k=0; k < 16; k++) {
            if (pt[k] != rt[k]) {
                std::cerr << "Error! Plaintext mismatch found in test " << i << std::endl;
                return EXIT_FAILURE;
            }
        }
    }

    std::cout << "All tests passed" << std::endl;

    return EXIT_SUCCESS;
}
