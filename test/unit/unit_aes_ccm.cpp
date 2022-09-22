/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
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
    CASE("AES-128 CCM make")
    {
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_CCM));
        EXPECT(nullptr != aesenc);
    },
    CASE("AES-192 CCM make")
    {
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_192_CCM));
        EXPECT(nullptr != aesenc);
    },
    CASE("AES-256 CCM make")
    {
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_256_CCM));
        EXPECT(nullptr != aesenc);
    },
    CASE("AES-128 CCM authenticated encryption and decryption 1")
    {
        uint8_t key[16] = {
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
        };
        uint8_t nonce[7] = {
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16
        };
        uint8_t aad[8] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
        };
        uint8_t pt[4] = {
            0x20, 0x21, 0x22, 0x23
        };
        uint8_t ct[4] = {
            0x71, 0x62, 0x01, 0x5b
        };
        uint8_t tag[4] = {
            0x4d, 0xac, 0x25, 0x5d
        };
        uint8_t result_ct[4], result_pt[4], pt_tag[4], ct_tag[4];
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_CCM));
        symmetric_key_cipher::set_key(aesenc.get(), key, 16);
        symmetric_key_cipher::encrypt_start(aesenc.get(), nonce, 7, aad, 8, 4, 4);
        symmetric_key_cipher::encrypt(aesenc.get(), result_ct, pt, 4);
        symmetric_key_cipher::encrypt_finish(aesenc.get(), ct_tag, 4);
        for (size_t i=0; i < 4; i++) {
            EXPECT(ct[i] == result_ct[i]);
        }
        for (size_t i=0; i < 4; i++) {
            EXPECT(tag[i] == ct_tag[i]);
        }
        auto aesdec = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_CCM));
        symmetric_key_cipher::set_key(aesdec.get(), key, 16);
        symmetric_key_cipher::decrypt_start(aesdec.get(), nonce, 7, aad, 8, 4, 4);
        symmetric_key_cipher::decrypt(aesdec.get(), result_pt, result_ct, 4);
        symmetric_key_cipher::decrypt_finish(aesdec.get(), pt_tag, 4);
        for (size_t i=0; i < 4; i++) {
            EXPECT(pt[i] == result_pt[i]);
        }
        for (size_t i=0; i < 4; i++) {
            EXPECT(tag[i] == pt_tag[i]);
        }
    },
    CASE("AES-128 CCM authenticated encryption and decryption 2")
    {
        uint8_t key[16] = {
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
        };
        uint8_t nonce[8] = {
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
        };
        uint8_t aad[16] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };
        uint8_t pt[16] = {
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
        };
        uint8_t ct[16] = {
            0xd2, 0xa1, 0xf0, 0xe0, 0x51, 0xea, 0x5f, 0x62, 0x08, 0x1a, 0x77, 0x92, 0x07, 0x3d, 0x59, 0x3d
        };
        uint8_t tag[6] = {
            0x1f, 0xc6, 0x4f, 0xbf, 0xac, 0xcd
        };
        uint8_t result_ct[16], result_pt[16], pt_tag[6], ct_tag[6];
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_CCM));
        symmetric_key_cipher::set_key(aesenc.get(), key, 16);
        symmetric_key_cipher::encrypt_start(aesenc.get(), nonce, 8, aad, 16, 16, 6);
        symmetric_key_cipher::encrypt(aesenc.get(), result_ct, pt, 16);
        symmetric_key_cipher::encrypt_finish(aesenc.get(), ct_tag, 6);
        for (size_t i=0; i < 16; i++) {
            EXPECT(ct[i] == result_ct[i]);
        }
        for (size_t i=0; i < 6; i++) {
            EXPECT(tag[i] == ct_tag[i]);
        }
        auto aesdec = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_CCM));
        symmetric_key_cipher::set_key(aesdec.get(), key, 16);
        symmetric_key_cipher::decrypt_start(aesdec.get(), nonce, 8, aad, 16, 16, 6);
        symmetric_key_cipher::decrypt(aesdec.get(), result_pt, result_ct, 16);
        symmetric_key_cipher::decrypt_finish(aesdec.get(), pt_tag, 6);
        for (size_t i=0; i < 16; i++) {
            EXPECT(pt[i] == result_pt[i]);
        }
        for (size_t i=0; i < 6; i++) {
            EXPECT(tag[i] == pt_tag[i]);
        }
    },
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

