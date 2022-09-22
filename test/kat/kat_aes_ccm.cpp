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
#include "core/mpz.hpp"
#include "utils/stopwatch.hpp"


using namespace phantom;  // NOLINT
using namespace crypto;   // NOLINT

struct aes_ccm_tv
{
    symmetric_key_type_e keytype;
    const char  *key;
    const char  *nonce;
    const char  *aad;
    const char  *plaintext;
    const char  *authtag;
    const char  *ciphertext;
};

aes_ccm_tv tv[] = {
    {
        SYMKEY_AES_128_CCM,
        "404142434445464748494a4b4c4d4e4f",
        "10111213141516",
        "0001020304050607",
        "20212223",
        "4dac255d",
        "7162015b",
    },
    {
        SYMKEY_AES_128_CCM,
        "404142434445464748494a4b4c4d4e4f",
        "1011121314151617",
        "000102030405060708090a0b0c0d0e0f",
        "202122232425262728292a2b2c2d2e2f",
        "1fc64fbfaccd",
        "d2a1f0e051ea5f62081a7792073d593d",
    },
    {
        SYMKEY_AES_128_CCM,
        "404142434445464748494a4b4c4d4e4f",
        "101112131415161718191a1b",
        "000102030405060708090a0b0c0d0e0f10111213",
        "202122232425262728292a2b2c2d2e2f3031323334353637",
        "484392fbc1b09951",
        "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5",
    },
    {
        SYMKEY_AES_128_CCM,
        "404142434445464748494a4b4c4d4e4f",
        "101112131415161718191a1b1c",
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f"
        "505152535455565758595a5b5c5d5e5f"
        "606162636465666768696a6b6c6d6e6f"
        "707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "b4ac6bec93e8598e7f0dadbcea5b",
        "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72",
    },
};

const uint8_t hex_lut[0x80] =
{   // 0     1     2     3     4     5     6    7      8     9     A     B     C     D     E     F
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 1
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 2
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 3
    0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 4
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 5
    0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 6
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00   // 7
};

phantom_vector<uint8_t> cstring_to_hex(const std::string& input)
{
    size_t len = input.length() /2;
    phantom_vector<uint8_t> output(len);
    const char *str = input.c_str();
    for (size_t i = 0; i < len; i++) {
        output[i]  = hex_lut[static_cast<int>(*str++)] << 4;
        output[i] |= hex_lut[static_cast<int>(*str++)];
    }
    return output;
}

int main(int argc, char *argv[])
{
    std::cout << "AES CCM Known Answer Test" << std::endl;

    for (size_t i=0; i < sizeof(tv)/sizeof(aes_ccm_tv); i++) {

        phantom_vector<uint8_t> key         = cstring_to_hex(tv[i].key);
        phantom_vector<uint8_t> pt          = cstring_to_hex(tv[i].plaintext);
        phantom_vector<uint8_t> nonce       = cstring_to_hex(tv[i].nonce);
        phantom_vector<uint8_t> aad         = cstring_to_hex(tv[i].aad);
        phantom_vector<uint8_t> ref_ct      = cstring_to_hex(tv[i].ciphertext);
        phantom_vector<uint8_t> ref_authtag = cstring_to_hex(tv[i].authtag);

        if (3 == i) {
            while (aad.size() < (524288/8)) {
                auto cur_bytes = aad.size();
                aad.resize(2 * cur_bytes);
                std::copy_n(aad.begin(), cur_bytes, aad.begin() + cur_bytes);
            }

            std::cout << "ptlength is " << aad.size() << std::endl;
        }

        phantom_vector<uint8_t> ct(pt.size());
        phantom_vector<uint8_t> rt(pt.size());
        phantom_vector<uint8_t> authtag(ref_authtag.size());
        phantom_vector<uint8_t> rec_authtag(ref_authtag.size());

        auto cipher_ctx = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(tv[i].keytype));
        symmetric_key_cipher::set_key(cipher_ctx.get(), key.data(), key.size());
        symmetric_key_cipher::encrypt_start(cipher_ctx.get(), nonce.data(), nonce.size(), aad.data(), aad.size(), pt.size(), authtag.size());
        symmetric_key_cipher::encrypt(cipher_ctx.get(), ct.data(), pt.data(), pt.size());
        symmetric_key_cipher::encrypt_finish(cipher_ctx.get(), authtag.data(), authtag.size());
        symmetric_key_cipher::decrypt_start(cipher_ctx.get(), nonce.data(), nonce.size(), aad.data(), aad.size(), pt.size(), authtag.size());
        symmetric_key_cipher::decrypt(cipher_ctx.get(), rt.data(), ct.data(), ct.size());
        symmetric_key_cipher::decrypt_finish(cipher_ctx.get(), rec_authtag.data(), rec_authtag.size());

        for (size_t k=0; k < pt.size(); k++) {
            if (ref_ct[k] != ct[k]) {
                std::cerr << "Error! Ciphertext mismatch found in test " << i << std::endl;
                return EXIT_FAILURE;
            }
        }

        for (size_t k=0; k < authtag.size(); k++) {
            if (authtag[k] != ref_authtag[k]) {
                std::cerr << "Error! Authentication tag mismatch found in test " << i << std::endl;
                return EXIT_FAILURE;
            }
        }

        for (size_t k=0; k < pt.size(); k++) {
            if (pt[k] != rt[k]) {
                std::cerr << "Error! Plaintext mismatch found in test " << i << std::endl;
                return EXIT_FAILURE;
            }
        }

        for (size_t k=0; k < rec_authtag.size(); k++) {
            if (rec_authtag[k] != ref_authtag[k]) {
                std::cerr << "Error! Decoder authentication tag mismatch found in test " << i << std::endl;
                return EXIT_FAILURE;
            }
        }
    }

    std::cout << "All tests passed" << std::endl;

    return EXIT_SUCCESS;
}
