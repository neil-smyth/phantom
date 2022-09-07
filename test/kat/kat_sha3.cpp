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

struct sha3_tv
{
    const char *message;
    const char *digest_224;
    const char *digest_256;
    const char *digest_384;
    const char *digest_512;
};

// Initial test vectors from https://www.di-mgt.com.au/sha_testvectors.html

sha3_tv tv[] = {
    {
        "abc",
        "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e39340"
        "57340b4cf408d5a56592f8274eec53f0"
    },
    {
        "",
        "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558"
        "f500199d95b6d3e301758586281dcd26"
    },
    {
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33",
        "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
        "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22",
        "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c0863"
        "46b533b49c030d99a27daf1139d6e75e"
    },
    {
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrs"
        "mnopqrstnopqrstu",
        "543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc",
        "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18",
        "79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7",
        "afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189"
        "ed0fb440d187f382270cb455f21dd185"
    },
    {
        "a",
        "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c",
        "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1",
        "eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340",
        "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266"
        "a8aa18ace8282a0e0db596c90b0a7b87"
    },
    {
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
        "c6d66e77ae289566afb2ce39277752d6da2a3c46010f1e0a0970ff60",
        "ecbbc42cbf296603acb2c6bc0410ef4378bafb24b710357f12df607758b33e2b",
        "a04296f4fcaae14871bb5ad33e28dcf69238b04204d9941b8782e816d014bcb7540e4af54f30d578f1a1ca2930847a12",
        "235ffd53504ef836a1342b488f483b396eabbfe642cf78ee0d31feec788b23d0d18d5c339550dd5958a500d4b95363da"
        "1b5fa18affc1bab2292dc63b7d85097c"
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
    std::cout << "SHA3 Known Answer Test" << std::endl;

    for (size_t i=0; i < 6; i++) {

        // Convert the message string to a hex string and then to a byte vector
        std::string hex = string_to_hex(std::string(tv[i].message));
        core::mpz<uint32_t> mpz_message(hex.c_str(), 16);
        phantom_vector<uint8_t> message;
        if (!mpz_message.is_zero()) {
            mpz_message.get_bytes(message, true);
        }

        if (!test_message(i, HASH_SHA3_224, tv[i].digest_224, message)) {
            std::cerr << "Error! SHA3-224 message digest mismatch found in test " << i << std::endl;
            return EXIT_FAILURE;
        }

        if (!test_message(i, HASH_SHA3_256, tv[i].digest_256, message)) {
            std::cerr << "Error! SHA3-256 message digest mismatch found in test " << i << std::endl;
            return EXIT_FAILURE;
        }

        if (!test_message(i, HASH_SHA3_384, tv[i].digest_384, message)) {
            std::cerr << "Error! SHA3-384 message digest mismatch found in test " << i << std::endl;
            return EXIT_FAILURE;
        }

        if (!test_message(i, HASH_SHA3_512, tv[i].digest_512, message)) {
            std::cerr << "Error! SHA3-512 message digest mismatch found in test " << i << std::endl;
            return EXIT_FAILURE;
        }
    }

    std::cout << "All tests passed" << std::endl;

    return EXIT_SUCCESS;
}
