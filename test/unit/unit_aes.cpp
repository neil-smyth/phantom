/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include <iostream>
#include <memory>
#include "./lest.hpp"
#include "./phantom.hpp"

namespace phantom {
using namespace crypto;  // NOLINT

const lest::test specification[] =
{
    CASE("AES-128 Encrypt make")
    {
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_ENC));
        EXPECT(nullptr != aesenc);
    },
    CASE("AES-192 Encrypt make")
    {
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_192_ENC));
        EXPECT(nullptr != aesenc);
    },
    CASE("AES-256 Encrypt make")
    {
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_256_ENC));
        EXPECT(nullptr != aesenc);
    },
    CASE("AES-128 Decrypt make")
    {
        auto aesdec = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_DEC));
        EXPECT(nullptr != aesdec);
    },
    CASE("AES-192 Decrypt make")
    {
        auto aesdec = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_192_DEC));
        EXPECT(nullptr != aesdec);
    },
    CASE("AES-256 Decrypt make")
    {
        auto aesdec = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_192_DEC));
        EXPECT(nullptr != aesdec);
    },
    CASE("AES-256 cannot be used with a 192-bit instance")
    {
        uint8_t key[32];
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_192_ENC));
        int32_t retval = symmetric_key_cipher::set_key(aesenc.get(), key, 32);
        EXPECT(EXIT_FAILURE == retval);
    },
    CASE("Key must be a non-NULL pointer")
    {
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_256_ENC));
        int32_t retval = symmetric_key_cipher::set_key(aesenc.get(), nullptr, 16);
        EXPECT(EXIT_FAILURE == retval);
        retval = symmetric_key_cipher::set_key(aesenc.get(), nullptr, 24);
        EXPECT(EXIT_FAILURE == retval);
        retval = symmetric_key_cipher::set_key(aesenc.get(), nullptr, 32);
        EXPECT(EXIT_FAILURE == retval);

    },
    CASE("AES-256 and AES-192 cannot be used with a 128-bit instance")
    {
        uint8_t key[32] = {0};
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_ENC));
        int32_t retval = symmetric_key_cipher::set_key(aesenc.get(), key, 16);
        EXPECT(EXIT_SUCCESS == retval);
        retval = symmetric_key_cipher::set_key(aesenc.get(), key, 24);
        EXPECT(EXIT_FAILURE == retval);
        retval = symmetric_key_cipher::set_key(aesenc.get(), key, 32);
        EXPECT(EXIT_FAILURE == retval);
    },
    CASE("AES-256 cannot be used with a 192-bit instance")
    {
        uint8_t key[32] = {0};
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_192_ENC));
        int32_t retval = symmetric_key_cipher::set_key(aesenc.get(), key, 16);
        EXPECT(EXIT_SUCCESS == retval);
        retval = symmetric_key_cipher::set_key(aesenc.get(), key, 24);
        EXPECT(EXIT_SUCCESS == retval);
        retval = symmetric_key_cipher::set_key(aesenc.get(), key, 32);
        EXPECT(EXIT_FAILURE == retval);
    },
    CASE("AES-128 encryption and decryption")
    {
        uint8_t key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        };
        uint8_t pt[16]  = {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
        };
        uint8_t ct[16]  = {
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
        };
        uint8_t result_ct[16], result_pt[16];
        int32_t retval;
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_ENC));
        retval = symmetric_key_cipher::set_key(aesenc.get(), key, 16);
        EXPECT(retval == EXIT_SUCCESS);
        retval = symmetric_key_cipher::encrypt(aesenc.get(), result_ct, pt, 16);
        EXPECT(retval == EXIT_SUCCESS);
        for (size_t i=0; i < 16; i++) {
            EXPECT(ct[i] == result_ct[i]);
        }
        auto aesdec = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_DEC));
        retval = symmetric_key_cipher::set_key(aesdec.get(), key, 16);
        EXPECT(retval == EXIT_SUCCESS);
        retval = symmetric_key_cipher::decrypt(aesdec.get(), result_pt, result_ct, 16);
        EXPECT(retval == EXIT_SUCCESS);
        for (size_t i=0; i < 16; i++) {
            EXPECT(pt[i] == result_pt[i]);
        }
    },
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

