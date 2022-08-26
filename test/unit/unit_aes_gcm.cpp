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
    CASE("AES-128 GCM make")
    {
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_GCM));
        EXPECT(nullptr != aesenc);
    },
    CASE("AES-192 GCM make")
    {
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_192_GCM));
        EXPECT(nullptr != aesenc);
    },
    CASE("AES-256 GCM make")
    {
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_256_GCM));
        EXPECT(nullptr != aesenc);
    },
    CASE("AES-128 GCM authenticated encryption and decryption 1")
    {
        uint8_t key[16] = {
            0x11, 0x75, 0x4c, 0xd7, 0x2a, 0xec, 0x30, 0x9b, 0xf5, 0x2f, 0x76, 0x87, 0x21, 0x2e, 0x89, 0x57
        };
        uint8_t ctr[12] = {
            0x3c, 0x81, 0x9d, 0x9a, 0x9b, 0xed, 0x08, 0x76, 0x15, 0x03, 0x0b, 0x65
        };
        uint8_t pt[0]  = {};
        uint8_t tag[16] = {
            0x25, 0x03, 0x27, 0xc6, 0x74, 0xaa, 0xf4, 0x77, 0xae, 0xf2, 0x67, 0x57, 0x48, 0xcf, 0x69, 0x71
        };
        uint8_t result_ct[0], result_pt[0], pt_tag[16], ct_tag[16];
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_GCM));
        symmetric_key_cipher::set_key(aesenc.get(), key, 16);
        symmetric_key_cipher::encrypt_start(aesenc.get(), ctr, 12, nullptr, 0);
        symmetric_key_cipher::encrypt_update(aesenc.get(), result_ct, pt, 0);
        symmetric_key_cipher::encrypt_finish(aesenc.get(), ct_tag, 16);
        for (size_t i=0; i < 16; i++) {
            EXPECT(tag[i] == ct_tag[i]);
        }
        auto aesdec = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_GCM));
        symmetric_key_cipher::set_key(aesdec.get(), key, 16);
        symmetric_key_cipher::decrypt_start(aesdec.get(), ctr, 12, nullptr, 0);
        symmetric_key_cipher::decrypt_update(aesenc.get(), result_pt, result_ct, 0);
        symmetric_key_cipher::decrypt_finish(aesdec.get(), pt_tag, 16);
        for (size_t i=0; i < 16; i++) {
            EXPECT(tag[i] == pt_tag[i]);
        }
    },
    CASE("AES-128 GCM authenticated encryption and decryption 2")
    {
        uint8_t key[16] = {
            0x27, 0x2f, 0x16, 0xed, 0xb8, 0x1a, 0x7a, 0xbb, 0xea, 0x88, 0x73, 0x57, 0xa5, 0x8c, 0x19, 0x17
        };
        uint8_t ctr[12] = {
            0x79, 0x4e, 0xc5, 0x88, 0x17, 0x6c, 0x70, 0x3d, 0x3d, 0x2a, 0x7a, 0x07
        };
        uint8_t pt[0]  = {};
        uint8_t tag[16] = {
            0xb6, 0xe6, 0xf1, 0x97, 0x16, 0x8f, 0x50, 0x49, 0xae, 0xda, 0x32, 0xda, 0xfb, 0xda, 0xeb
        };
        uint8_t result_ct[0], result_pt[0], pt_tag[16], ct_tag[16];
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_GCM));
        symmetric_key_cipher::set_key(aesenc.get(), key, 16);
        symmetric_key_cipher::encrypt_start(aesenc.get(), ctr, 12, nullptr, 0);
        symmetric_key_cipher::encrypt_update(aesenc.get(), result_ct, pt, 0);
        symmetric_key_cipher::encrypt_finish(aesenc.get(), ct_tag, 15);
        for (size_t i=0; i < 15; i++) {
            EXPECT(tag[i] == ct_tag[i]);
        }
        auto aesdec = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_GCM));
        symmetric_key_cipher::set_key(aesdec.get(), key, 16);
        symmetric_key_cipher::decrypt_start(aesdec.get(), ctr, 12, nullptr, 0);
        symmetric_key_cipher::decrypt_update(aesenc.get(), result_pt, result_ct, 0);
        symmetric_key_cipher::decrypt_finish(aesdec.get(), pt_tag, 15);
        for (size_t i=0; i < 15; i++) {
            EXPECT(tag[i] == pt_tag[i]);
        }
    },
    CASE("AES-128 GCM authenticated encryption and decryption 3")
    {
        uint8_t key[16] = {
            0x2f, 0xb4, 0x5e, 0x5b, 0x8f, 0x99, 0x3a, 0x2b, 0xfe, 0xbc, 0x4b, 0x15, 0xb5, 0x33, 0xe0, 0xb4
        };
        uint8_t ctr[12] = {
            0x5b, 0x05, 0x75, 0x5f, 0x98, 0x4d, 0x2b, 0x90, 0xf9, 0x4b, 0x80, 0x27
        };
        uint8_t pt[0]  = {};
        uint8_t tag[16] = {
            0xc7, 0x5b, 0x78, 0x32, 0xb2, 0xa2, 0xd9, 0xbd, 0x82, 0x74, 0x12, 0xb6, 0xef, 0x57, 0x69, 0xdb
        };
        uint8_t aad[20] = {
            0xe8, 0x54, 0x91, 0xb2, 0x20, 0x2c, 0xaf, 0x1d, 0x7d, 0xce, 0x03, 0xb9, 0x7e, 0x09, 0x33, 0x1c,
            0x32, 0x47, 0x39, 0x41
        };
        uint8_t result_ct[0], result_pt[0], pt_tag[16], ct_tag[16];
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_GCM));
        symmetric_key_cipher::set_key(aesenc.get(), key, 16);
        symmetric_key_cipher::encrypt_start(aesenc.get(), ctr, 12, aad, 20);
        symmetric_key_cipher::encrypt_update(aesenc.get(), result_ct, pt, 0);
        symmetric_key_cipher::encrypt_finish(aesenc.get(), ct_tag, 16);
        for (size_t i=0; i < 16; i++) {
            EXPECT(tag[i] == ct_tag[i]);
        }
        auto aesdec = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_GCM));
        symmetric_key_cipher::set_key(aesdec.get(), key, 16);
        symmetric_key_cipher::decrypt_start(aesdec.get(), ctr, 12, aad, 20);
        symmetric_key_cipher::decrypt_update(aesenc.get(), result_pt, result_ct, 0);
        symmetric_key_cipher::decrypt_finish(aesdec.get(), pt_tag, 16);
        for (size_t i=0; i < 16; i++) {
            EXPECT(tag[i] == pt_tag[i]);
        }
    },
    CASE("AES-128 GCM authenticated encryption and decryption 4")
    {
        uint8_t key[16] = {
            0xf0, 0x0f, 0xdd, 0x01, 0x8c, 0x02, 0xe0, 0x35, 0x76, 0x00, 0x8b, 0x51, 0x6e, 0xa9, 0x71, 0xad
        };
        uint8_t ctr[12] = {
            0x3b, 0x3e, 0x27, 0x6f, 0x9e, 0x98, 0xb1, 0xec, 0xb7, 0xce, 0x6d, 0x28
        };
        uint8_t pt[16]  = {
            0x28, 0x53, 0xe6, 0x6b, 0x7b, 0x1b, 0x3e, 0x1f, 0xa3, 0xd1, 0xf3, 0x72, 0x79, 0xac, 0x82, 0xbe
        };
        uint8_t ct[16]  = {
            0x55, 0xd2, 0xda, 0x7a, 0x3f, 0xb7, 0x73, 0xb8, 0xa0, 0x73, 0xdb, 0x49, 0x9e, 0x24, 0xbf, 0x62
        };
        uint8_t tag[12] = {
            0xcb, 0xa0, 0x6b, 0xb4, 0xf6, 0xe0, 0x97, 0x19, 0x92, 0x50, 0xb0, 0xd1
        };
        uint8_t result_ct[16], result_pt[16], pt_tag[16], ct_tag[16];
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_GCM));
        symmetric_key_cipher::set_key(aesenc.get(), key, 16);
        symmetric_key_cipher::encrypt_start(aesenc.get(), ctr, 12, nullptr, 0);
        symmetric_key_cipher::encrypt_update(aesenc.get(), result_ct, pt, 16);
        symmetric_key_cipher::encrypt_finish(aesenc.get(), ct_tag, 12);
        for (size_t i=0; i < 16; i++) {
            EXPECT(ct[i] == result_ct[i]);
        }
        for (size_t i=0; i < 12; i++) {
            EXPECT(tag[i] == ct_tag[i]);
        }
        auto aesdec = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_GCM));
        symmetric_key_cipher::set_key(aesdec.get(), key, 16);
        symmetric_key_cipher::decrypt_start(aesdec.get(), ctr, 12, nullptr, 0);
        symmetric_key_cipher::decrypt_update(aesdec.get(), result_pt, result_ct, 16);
        symmetric_key_cipher::decrypt_finish(aesdec.get(), pt_tag, 12);
        for (size_t i=0; i < 16; i++) {
            EXPECT(pt[i] == result_pt[i]);
        }
        for (size_t i=0; i < 12; i++) {
            EXPECT(tag[i] == pt_tag[i]);
        }
    },
    CASE("AES-128 GCM authenticated encryption and decryption 5")
    {
        uint8_t key[16] = {
            0x11, 0xca, 0x26, 0xa3, 0xe3, 0x49, 0x0f, 0x05, 0x03, 0x72, 0x30, 0x1b, 0x0d, 0x39, 0x4c, 0x8b
        };
        uint8_t ctr[1] = {
            0x36
        };
        uint8_t pt[13]  = {
            0x63, 0x31, 0xcd, 0x4b, 0xad, 0xf4, 0x59, 0x18, 0x2c, 0xeb, 0x3e, 0xe1, 0x20
        };
        uint8_t ct[13]  = {
            0x73, 0x17, 0xea, 0x6f, 0xb6, 0x09, 0x78, 0x3c, 0xe7, 0x62, 0xa6, 0xef, 0xdd
        };
        uint8_t tag[4] = {
            0xd0, 0x6f, 0x1f, 0x8a
        };
        uint8_t aad[90] = {
            0xa0, 0x82, 0x13, 0x9c, 0x1c, 0x90, 0xb6, 0xde, 0x9b, 0xe9, 0xef, 0x23, 0x91, 0xd7, 0xe3, 0xa1,
            0xff, 0x3b, 0x66, 0x08, 0x0d, 0x15, 0xe3, 0x42, 0xed, 0x54, 0xc4, 0xcc, 0xc1, 0x2f, 0x21, 0xe3,
            0xb5, 0x49, 0xb0, 0xc3, 0x8d, 0x6e, 0x27, 0xe7, 0xf3, 0xcd, 0x6d, 0x33, 0x43, 0x68, 0x1f, 0x04,
            0x76, 0x1b, 0x52, 0xa0, 0xb3, 0x97, 0x58, 0xc4, 0x98, 0x00, 0x7e, 0xb6, 0x55, 0x22, 0xa9, 0x5f,
            0x9c, 0x67, 0x53, 0x11, 0x29, 0x86, 0x31, 0x59, 0x2b, 0xa8, 0xcc, 0x11, 0xb6, 0xb9, 0x07, 0x4a,
            0x18, 0xd5, 0x18, 0x3e, 0x3e, 0x83, 0x06, 0xe6, 0x3d, 0x09
        };
        uint8_t result_ct[13], result_pt[13], pt_tag[4], ct_tag[4];
        auto aesenc = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_GCM));
        symmetric_key_cipher::set_key(aesenc.get(), key, 16);
        symmetric_key_cipher::encrypt_start(aesenc.get(), ctr, 1, aad, 90);
        symmetric_key_cipher::encrypt_update(aesenc.get(), result_ct, pt, 13);
        symmetric_key_cipher::encrypt_finish(aesenc.get(), ct_tag, 4);
        for (size_t i=0; i < 13; i++) {
            EXPECT(ct[i] == result_ct[i]);
        }
        for (size_t i=0; i < 4; i++) {
            EXPECT(tag[i] == ct_tag[i]);
        }
        auto aesdec = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(SYMKEY_AES_128_GCM));
        symmetric_key_cipher::set_key(aesdec.get(), key, 16);
        symmetric_key_cipher::decrypt_start(aesdec.get(), ctr, 1, aad, 90);
        symmetric_key_cipher::decrypt_update(aesdec.get(), result_pt, result_ct, 13);
        symmetric_key_cipher::decrypt_finish(aesdec.get(), pt_tag, 4);
        for (size_t i=0; i < 13; i++) {
            EXPECT(pt[i] == result_pt[i]);
        }
        for (size_t i=0; i < 4; i++) {
            EXPECT(tag[i] == pt_tag[i]);
        }
    },
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

