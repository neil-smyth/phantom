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
    const char  *iv;
    const char  *plaintext;
    const char  *ciphertext;
};

// Mixture of test vectors from https://www.ietf.org/rfc/rfc3686.txt and
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

aes_ccm_tv tv[] = {
    {
        SYMKEY_AES_128_CTR,
        "2b7e151628aed2a6abf7158809cf4f3c",
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"
        "5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee",
    },
    {
        SYMKEY_AES_128_CTR,
        "ae6852f8121067cc4bf7a5765577f39e",
        "00000030000000000000000000000001",
        "53696e676c6520626c6f636b206d7367",
        "e4095d4fb7a7b3792d6175a3261311b8",
    },
    {
        SYMKEY_AES_128_CTR,
        "7e24067817fae0d743d6ce1f32539163",
        "006cb6dbc0543b59da48d90b00000001",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "5104a106168a72d9790d41ee8edad388eb2e1efc46da57c8fce630df9141be28",
    },
    {
        SYMKEY_AES_128_CTR,
        "7691be035e5020a8ac6e618529f9a0dc",
        "00e0017b27777f3f4a1786f000000001",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223",
        "c1cf48a89f2ffdd9cf4652e9efdb72d74540a42bde6d7836d59a5ceaaef3105325b2072f",
    },
    {
        SYMKEY_AES_192_CTR,
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e94"
        "1e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050",
    },
    {
        SYMKEY_AES_192_CTR,
        "16af5b145fc9f579c175f93e3bfb0eed863d06ccfdb78515",
        "0000004836733c147d6d93cb",
        "53696e676c6520626c6f636b206d7367",
        "4b55384fe259c9c84e7935a003cbe928",
    },
    {
        SYMKEY_AES_192_CTR,
        "7c5cb2401b3dc33c19e7340819e0f69c678c3db8e6f6a91a",
        "0096b03b020c6eadc2cb500d00000001",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "453243fc609b23327edfaafa7131cd9f8490701c5ad4a79cfc1fe0ff42f4fb00",
    },
    {
        SYMKEY_AES_192_CTR,
        "02bf391ee8ecb159b959617b0965279bf59b60a786d3e0fe",
        "0007bdfd5cbd60278dcc0912",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223",
        "96893fc55e5c722f540b7dd1ddf7e758d288bc95c69165884536c811662f2188abee0935",
    },
    {
        SYMKEY_AES_256_CTR,
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6",
        "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    },
    {
        SYMKEY_AES_256_CTR,
        "776beff2851db06f4c8a0542c8696f6c6a81af1eec96b4d37fc1d689e6c1c104",
        "00000060db5672c97aa8f0b200000001",
        "53696e676c6520626c6f636b206d7367",
        "145ad01dbf824ec7560863dc71e3e0c0",
    },
    {
        SYMKEY_AES_256_CTR,
        "f6d66d6bd52d59bb0796365879eff886c66dd51a5b6a99744b50590c87a23884",
        "00faac24c1585ef15a43d87500000001",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "f05e231b3894612c49ee000b804eb2a9b8306b508f839d6a5530831d9344af1c",
    },
    {
        SYMKEY_AES_256_CTR,
        "ff7a617ce69148e4f1726e2f43581de2aa62d9f805532edff1eed687fb54153d",
        "001cc5b751a51d70a1c1114800000001",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223",
        "eb6c52821d0bbbf7ce7594462aca4faab407df866569fd07f48cc0b583d6071f1ec0e6b8",
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
    std::cout << "AES CTR Known Answer Test" << std::endl;

    for (size_t i=1; i < 12; i++) {

        phantom_vector<uint8_t> key    = cstring_to_hex(tv[i].key);
        phantom_vector<uint8_t> pt     = cstring_to_hex(tv[i].plaintext);
        phantom_vector<uint8_t> iv     = cstring_to_hex(tv[i].iv);
        phantom_vector<uint8_t> ref_ct = cstring_to_hex(tv[i].ciphertext);

        phantom_vector<uint8_t> ct(pt.size());
        phantom_vector<uint8_t> rt(pt.size());

        auto cipher_ctx = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(tv[i].keytype));
        symmetric_key_cipher::set_key(cipher_ctx.get(), key.data(), key.size());
        symmetric_key_cipher::encrypt_start(cipher_ctx.get(), iv.data(), iv.size());
        symmetric_key_cipher::encrypt(cipher_ctx.get(), ct.data(), pt.data(), pt.size());
        symmetric_key_cipher::decrypt_start(cipher_ctx.get(), iv.data(), iv.size());
        symmetric_key_cipher::decrypt(cipher_ctx.get(), rt.data(), ct.data(), ct.size());

        for (size_t k=0; k < pt.size(); k++) {
            if (pt[k] != rt[k]) {
                std::cerr << "Error! Plaintext mismatch found in test " << i << ", byte " << k << std::endl;
                return EXIT_FAILURE;
            }
        }
    }

    std::cout << "All tests passed" << std::endl;

    return EXIT_SUCCESS;
}
