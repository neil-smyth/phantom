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
#include <iomanip>

#include "./phantom.hpp"
#include "core/mpz.hpp"


using namespace phantom;  // NOLINT

struct shake_tv
{
    const char *message;
    const char *digest_128;
    const char *digest_256;
};

// Initial test vectors from https://www.di-mgt.com.au/sha_testvectors.html

shake_tv tv[] = {
    {
        "abc",
        "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc844c50af32acd3f2cdd066568706f50"
        "9bc1bdde58295dae3f891a9a0fca5783789a41f8611214ce612394",
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1f"
    },
    {
        "",
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
    },
    {
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "1a96182b50fb8c7e74e0a707788f55e98209b8d9",
        "4d8c2dd2435a0128eefbb8c36f6f87133a7911e1"
    },
    {
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrs"
        "mnopqrstnopqrstu",
        "7b6df6ff181173b6d7898d7ff63fb07b7c237daf471a5ae5602adbccef9ccf4b37e06b4a3543164ffbe0d0557c02f9b2"
        "5ad434005526d88ca04a",
        "98be04516c04cc73593fef3ed0352ea9f6443942d6950e29a372a681c3deaf4535423709b02843948684e029010badcc"
        "0acd8303fc85fdad3eab"
    },
    {
        "a",
        "9d222c79c4ff9d092cf6ca86143aa411e369973808ef97093255826c5572ef58",
        "3578a7a4ca9137569cdf76ed617d31bb994fca9c1bbf8b184013de8234dfd13a"
    },
    {
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
        "f4e546891fa8bacea5a159",
        "3c23f2c994061ff3041d7e"
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

bool test_message(size_t test_number, xof_alg_e type, const std::string &ref_digest, phantom_vector<uint8_t> &message)
{
    std::unique_ptr<hashing_function> hash;
    phantom_vector<uint8_t> digest;

    core::mpz<uint32_t> mpz_digest(ref_digest.c_str(), 16);
    phantom_vector<uint8_t> ref_digest_bytes;
    mpz_digest.get_bytes(ref_digest_bytes, true);

    size_t digest_size = ref_digest_bytes.size();

    hash   = std::unique_ptr<hashing_function>(hashing_function::make(type));
    digest = phantom_vector<uint8_t>(digest_size);

    hash->init();
    if (5 == test_number) {
        for (size_t j = 0; j < 16777216; j++) {
            hash->absorb(message.data(), message.size());
        }
    }
    else if (4 == test_number) {
        for (size_t j = 0; j < 1000000; j++) {
            hash->absorb(message.data(), message.size());
        }
    }
    else {
        hash->absorb(message.data(), message.size());
    }
    hash->final();
    hash->squeeze(digest.data(), digest_size);

    for (size_t k=0; k < digest_size; k++) {
        if (digest[k] != ref_digest_bytes[k]) {
            return false;
        }
    }

    return true;
}

int main(int argc, char *argv[])
{
    std::cout << "SHAKE Known Answer Test" << std::endl;

    for (size_t i=0; i < 6; i++) {

        // Convert the message string to a hex string and then to a byte vector
        std::string hex = string_to_hex(std::string(tv[i].message));
        core::mpz<uint32_t> mpz_message(hex.c_str(), 16);
        phantom_vector<uint8_t> message;
        if (!mpz_message.is_zero()) {
            mpz_message.get_bytes(message, true);
        }

        if (!test_message(i, XOF_SHAKE_128, tv[i].digest_128, message)) {
            std::cerr << "Error! SHAKE-128 message digest mismatch found in test " << i << std::endl;
            return EXIT_FAILURE;
        }

        if (!test_message(i, XOF_SHAKE_256, tv[i].digest_256, message)) {
            std::cerr << "Error! SHAKE-256 message digest mismatch found in test " << i << std::endl;
            return EXIT_FAILURE;
        }
    }

    std::cout << "All tests passed" << std::endl;

    return EXIT_SUCCESS;
}
