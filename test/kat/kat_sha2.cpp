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


using namespace phantom;  // NOLINT

struct sha2_tv
{
    const char *message;
    const char *digest_224;
    const char *digest_256;
    const char *digest_384;
    const char *digest_512;
};

// Initial test vectors from https://www.di-mgt.com.au/sha_testvectors.html

sha2_tv tv[] = {
    {
        "abc",
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd"
        "454d4423643ce80e2a9ac94fa54ca49f"
    },
    {
        "",
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f"
        "63b931bd47417a81a538327af927da3e"
    },
    {
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
        "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca0"
        "31ad85c7a71dd70354ec631238ca3445"
    },
    {
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrs"
        "mnopqrstnopqrstu",
        "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3",
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
        "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433a"
        "c7d329eeb6dd26545e96e55b874be909"
    },
    {
        "a",
        "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67",
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31b"
        "eb009c5c2c49aa2e4eadb217ad8cc09b"
    },
    {
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
        "b5989713ca4fe47a009f8621980b34e6d63ed3063b2a0a2c867d8a85",
        "50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e",
        "5441235cc0235341ed806a64fb354742b5e5c02a3c5cb71b5f63fb793458d8fdae599c8cd8884943c04f11b31b89f023",
        "b47c933421ea2db149ad6e10fce6c7f93d0752380180ffd7f4629a712134831d77be6091b819ed352c2967a2e2d4fa50"
        "50723c9630691f1a05a7281dbe6c1086"
    },
};

std::string string_to_hex(const std::string& input)
{
    static const char hex_digits[] = "0123456789ABCDEF";

    std::string output;
    output.reserve(input.length() * 2);
    for (unsigned char c : input)
    {
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 15]);
    }
    return output;
}

bool test_message(size_t test_number, hash_alg_e type, const std::string &ref_digest, phantom_vector<uint8_t> &message)
{
    std::unique_ptr<hashing_function> hash;
    phantom_vector<uint8_t> digest;

    core::mpz<uint32_t> mpz_digest(ref_digest.c_str(), 16);
    phantom_vector<uint8_t> ref_digest_bytes;
    mpz_digest.get_bytes(ref_digest_bytes, true);

    hash   = std::unique_ptr<hashing_function>(hashing_function::make(type));
    digest = phantom_vector<uint8_t>(hash->get_length());

    hash->init();
    if (5 == test_number) {
        for (size_t j = 0; j < 16777216; j++) {
            hash->update(message.data(), message.size());
        }
    }
    else if (4 == test_number) {
        for (size_t j = 0; j < 1000000; j++) {
            hash->update(message.data(), message.size());
        }
    }
    else {
        hash->update(message.data(), message.size());
    }
    hash->final(digest.data());

    for (size_t k=0; k < hash->get_length(); k++) {
        if (digest[k] != ref_digest_bytes[k]) {
            return false;
        }
    }

    return true;
}

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;

    std::cout << "SHA2 Known Answer Test" << std::endl;

    for (size_t i=0; i < 6; i++) {

        // Convert the message string to a hex string and then to a byte vector
        std::string hex = string_to_hex(std::string(tv[i].message));
        core::mpz<uint32_t> mpz_message(hex.c_str(), 16);
        phantom_vector<uint8_t> message;
        if (!mpz_message.is_zero()) {
            mpz_message.get_bytes(message, true);
        }

        if (!test_message(i, HASH_SHA2_224, tv[i].digest_224, message)) {
            std::cerr << "Error! SHA-224 message digest mismatch found in test " << i << std::endl;
            return EXIT_FAILURE;
        }

        if (!test_message(i, HASH_SHA2_256, tv[i].digest_256, message)) {
            std::cerr << "Error! SHA-256 message digest mismatch found in test " << i << std::endl;
            return EXIT_FAILURE;
        }

        if (!test_message(i, HASH_SHA2_384, tv[i].digest_384, message)) {
            std::cerr << "Error! SHA-384 message digest mismatch found in test " << i << std::endl;
            return EXIT_FAILURE;
        }

        if (!test_message(i, HASH_SHA2_512, tv[i].digest_512, message)) {
            std::cerr << "Error! SHA-512 message digest mismatch found in test " << i << std::endl;
            return EXIT_FAILURE;
        }
    }

    std::cout << "All tests passed" << std::endl;

    return EXIT_SUCCESS;
}
