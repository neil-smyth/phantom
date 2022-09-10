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

int main(int argc, char *argv[])
{
    std::cout << "AES GCM Known Answer Test" << std::endl;

    for (size_t i=0; i < 12; i++) {

        core::mpz<uint32_t> mpz_key(tv[i].key, 16);
        phantom_vector<uint8_t> key;
        if (0 != strlen(tv[i].key)) {
            mpz_key.get_bytes(key, true);
        }
        key.resize(strlen(tv[i].key)/2);

        core::mpz<uint32_t> mpz_pt(tv[i].plaintext, 16);
        phantom_vector<uint8_t> pt(strlen(tv[i].plaintext)/2);
        if (0 != strlen(tv[i].plaintext)) {
            mpz_pt.get_bytes(pt, true);
        }
        pt.resize(strlen(tv[i].plaintext)/2);

        core::mpz<uint32_t> mpz_iv(tv[i].iv, 16);
        phantom_vector<uint8_t> iv(strlen(tv[i].iv)/2);
        if (0 != strlen(tv[i].iv)) {
            mpz_iv.get_bytes(iv, true);
        }
        iv.resize(strlen(tv[i].iv)/2);

        core::mpz<uint32_t> mpz_aad(tv[i].aad, 16);
        phantom_vector<uint8_t> aad(strlen(tv[i].aad)/2);
        if (0 != strlen(tv[i].aad)) {
            mpz_aad.get_bytes(aad, true);
        }
        aad.resize(strlen(tv[i].aad)/2);

        core::mpz<uint32_t> mpz_ref_authtag(tv[i].authtag, 16);
        phantom_vector<uint8_t> ref_authtag(strlen(tv[i].authtag)/2);
        if (0 != strlen(tv[i].authtag)) {
            mpz_ref_authtag.get_bytes(ref_authtag, true);
        }
        ref_authtag.resize(strlen(tv[i].authtag)/2);

        core::mpz<uint32_t> mpz_ref_ct(tv[i].ciphertext, 16);
        phantom_vector<uint8_t> ref_ct(strlen(tv[i].ciphertext)/2);
        if (0 != strlen(tv[i].ciphertext)) {
            mpz_ref_ct.get_bytes(ref_ct, true);
        }
        ref_ct.resize(strlen(tv[i].ciphertext)/2);

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
