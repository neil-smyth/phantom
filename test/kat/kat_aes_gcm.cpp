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

struct aes_gcm_tv
{
    symmetric_key_type_e keytype;
    const char  *key;
    const char  *iv;
    const char  *aad;
    const char  *plaintext;
    const char  *authtag;
    const char  *ciphertext;
};

aes_gcm_tv tv[] = {
    {
        SYMKEY_AES_128_GCM,
        "00000000000000000000000000000000",
        "000000000000000000000000",
        "",
        "",
        "58e2fccefa7e3061367f1d57a4e7455a",
        "",
    },
    {
        SYMKEY_AES_128_GCM,
        "00000000000000000000000000000000",
        "000000000000000000000000",
        "",
        "00000000000000000000000000000000",
        "ab6e47d42cec13bdf53a67b21257bddf",
        "0388dace60b6a392f328c2b971b2fe78",
    },
    {
        SYMKEY_AES_128_GCM,
        "feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b391aafd255",
        "4d5c2af327cd64a62cf35abd2ba6fab4",
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa05"
        "1ba30b396a0aac973d58e091473f5985",
    },
    {
        SYMKEY_AES_128_GCM,
        "feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b39",
        "5bc94fbc3221a5db94fae95ae7121a47",
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa05"
        "1ba30b396a0aac973d58e091",
    },
    {
        SYMKEY_AES_128_GCM,
        "feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbad",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b39",
        "3612d2e79e3b0785561be14aaca2fccb",
        "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b42"
        "4989b5e1ebac0f07c23f4598",
    },
    {
        SYMKEY_AES_128_GCM,
        "feffe9928665731c6d6a8f9467308308",
        "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b5254"
        "16aedbf5a0de6a57a637b39b",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b39",
        "619cc5aefffe0bfa462af43c1699d050",
        "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6f"
        "d62875d2aca417034c34aee5",
    },
    {
        SYMKEY_AES_192_GCM,
        "0e5d6e68f82f32bea3f0b69498c1a31ef6d955cd3d27a2a8",
        "caf72ee1e62e1001e8cfbc63",
        "",
        "",
        "db1a74ffb5f7de26f5742e0942b1b9cb",
        "",
    },
    {
        SYMKEY_AES_192_GCM,
        "7bcf2b2a5f8a9fefef59f36fe591cccd5a44fc0f127bdd6a",
        "05567095ee93e17e974da10e",
        "1e284eaf33f71e074b827f47450356c9",
        "dc2828ee143a6e20e76c5d9562fd65e7",
        "939b708c2e6060f829ce723ccef0f8",
        "b425dd981bb5e82466e0cc6583049727",
    },
    {
        SYMKEY_AES_192_GCM,
        "4105dfd75cb77495adc1ba442cfde0ca1519321769e15dfe",
        "ed8597e64a7f0f31735d8bd5",
        "96633c41c64c7b1598489759fe6d7b8287c199c6de449ebfc1731bf92b1620b11b96af4ea7832612c1517e82ddea9338"
        "c04a02dc7fe2465130ad10fa83a9417f167cfd923a846694150304917eccb9ebde1c711e48f04071a0e0",
        "d7b4f118a71c378b8bc1792e5c",
        "33d834db19bfdf51a3d34b54bf91",
        "36755f02869e0243c809603c38",
    },
    {
        SYMKEY_AES_192_GCM,
        "158aa6459ced7ba416bb1a236796c45695395aa5f2e3fc90",
        "b0",
        "f5f05f1f157f62681c6b3410fae689818010b7ecb05721d753e11eb876316790002901f52fa6a7f991e17d1758d92e7a",
        "3a8a02870d6f61d84bcaf2ddb1",
        "e150663463c05e42",
        "a9f8bd2ff174df5bbe311de231",
    },
    {
        SYMKEY_AES_192_GCM,
        "f88dfb3aec18d831c02b5c1fca570daa04a65ef4c6b91ab7",
        "9d54266f19140efd5b55209428219b9b70d1a8e04cf128e7d75e2dcb60abbbbd7925db36d5b98710e7525286c6ecd528"
        "cfb0dd77d49fa052677bd045bb62c38347abfc5495849139a37d3475a6b8689641cba25f2bda33ab139f5d7f7a0d0b11"
        "1efad96d3bd28624e72c2ecadeb957edc65e3338cc0b938483ea791fbe9af192",
        "72e5a4fd3f2f7ec533ec341d35bd177ca41288c0c91a2ae834dd0a6b9015e3936632ab02f290bdca846a91f463e09376",
        "",
        "2d3d3e03414a24889b617f7aee",
        "",
    },
    {
        SYMKEY_AES_192_GCM,
        "8e130235ac7c930d648a502c9b81ba45cb397c1fb369334e",
        "dabeba450ab9009985576fab76a61a2b7aeb0e2e2883433b550aaec2b8521f39cb0ad3732a39270863f4318ffbcbad71"
        "506ead658310e352bae03ec2a07abe31b1abc5822c105a7b0d796f6a2c5f1b0feabb8278e999ce820492c7a442d35e85"
        "db04bef05cc834aed1b2e77d0974ea4af51531ee6d185795c356cf04b2c5e218",
        "ec90b7b0b33ffe7df1ab0bc4715e7016",
        "24667172615cfee12526c8c6cc5dc501376f179bb538e9eb8bd0e20aa85d2b14",
        "e118825529a74e3d62bcfef4",
        "ce954b47de7c4226c1b4617a6264dd4aa0bd5068e431ed29c04afbe72494a607",
    },
    {
        SYMKEY_AES_256_GCM,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "",
        "",
        "530f8afbc74536b9a963b4f1c4cb738b",
        "",
    },
    {
        SYMKEY_AES_256_GCM,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "",
        "00000000000000000000000000000000",
        "d0d1c8a799996bf0265b98b5d48ab919",
        "cea7403d4d606b6e074ec5d3baf39d18",
    },
    {
        SYMKEY_AES_256_GCM,
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b391aafd255",
        "b094dac5d93471bdec1a502270e3cc6c",
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838"
        "c5f61e6393ba7a0abcc9f662898015ad",
    },
    {
        SYMKEY_AES_256_GCM,
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b39",
        "76fc6ece0f4e1768cddf8853bb2d551b",
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838"
        "c5f61e6393ba7a0abcc9f662",
    },
    {
        SYMKEY_AES_256_GCM,
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbad",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b39",
        "3a337dbf46a792c45e454913fe2ea8f2",
        "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f78"
        "62ac430e64abe499f47c9b1f",
    },
    {
        SYMKEY_AES_256_GCM,
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b5254"
        "16aedbf5a0de6a57a637b39b",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b39",
        "a44a8266ee1c8eb0c8b5d4cf5ae9f19a",
        "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cde"
        "a2418997200ef82e44ae7e3f",
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
    (void) argc;
    (void) argv;
    
    std::cout << "AES GCM Known Answer Test" << std::endl;

    for (size_t i=0; i < 18; i++) {

        phantom_vector<uint8_t> key         = cstring_to_hex(tv[i].key);
        phantom_vector<uint8_t> pt          = cstring_to_hex(tv[i].plaintext);
        phantom_vector<uint8_t> iv          = cstring_to_hex(tv[i].iv);
        phantom_vector<uint8_t> aad         = cstring_to_hex(tv[i].aad);
        phantom_vector<uint8_t> ref_ct      = cstring_to_hex(tv[i].ciphertext);
        phantom_vector<uint8_t> ref_authtag = cstring_to_hex(tv[i].authtag);

        phantom_vector<uint8_t> ct(pt.size());
        phantom_vector<uint8_t> rt(pt.size());
        phantom_vector<uint8_t> authtag(ref_authtag.size());
        phantom_vector<uint8_t> rec_authtag(ref_authtag.size());

        auto cipher_ctx = std::unique_ptr<symmetric_key_ctx>(symmetric_key_cipher::make(tv[i].keytype));
        symmetric_key_cipher::set_key(cipher_ctx.get(), key.data(), key.size());
        symmetric_key_cipher::encrypt_start(cipher_ctx.get(), iv.data(), iv.size(), aad.data(), aad.size());
        symmetric_key_cipher::encrypt(cipher_ctx.get(), ct.data(), pt.data(), pt.size());
        symmetric_key_cipher::encrypt_finish(cipher_ctx.get(), authtag.data(), authtag.size());
        symmetric_key_cipher::decrypt_start(cipher_ctx.get(), iv.data(), iv.size(), aad.data(), aad.size());
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
