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
    CASE("AES-128 CTR make")
    {
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_CTR));
        EXPECT(nullptr != aesenc);
    },
    CASE("AES-192 CTR make")
    {
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_192_CTR));
        EXPECT(nullptr != aesenc);
    },
    CASE("AES-256 CTR make")
    {
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_256_CTR));
        EXPECT(nullptr != aesenc);
    },
    CASE("AES-128 CTR encryption and decryption")
    {
        uint8_t key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        };
        uint8_t ctr[16] = {
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
        };
        uint8_t pt[16]  = {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
        };
        uint8_t ct[16]  = {
            0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce
        };
        uint8_t result_ct[16], result_pt[16];
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_CTR));
        symmetric_key_cipher::set_key(aesenc.get(), key, 16);
        symmetric_key_cipher::encrypt_start(aesenc.get(), ctr, 16);
        symmetric_key_cipher::encrypt(aesenc.get(), result_ct, pt, 16);
        for (size_t i=0; i < 16; i++) {
            EXPECT(ct[i] == result_ct[i]);
        }
        auto aesdec = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_CTR));
        symmetric_key_cipher::set_key(aesdec.get(), key, 16);
        symmetric_key_cipher::decrypt_start(aesdec.get(), ctr, 16);
        symmetric_key_cipher::decrypt(aesdec.get(), result_pt, result_ct, 16);
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

