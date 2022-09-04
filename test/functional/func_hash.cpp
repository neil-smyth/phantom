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
#include "./crypto/random_seed.hpp"
#include "utils/stopwatch.hpp"


using namespace phantom;  // NOLINT

#define NUM_ITER   8192ULL

static inline const char *stringFromEnum(hash_alg_e type)
{
    static const char *strings[] = { "SHA2-224",
                                     "SHA2-256",
                                     "SHA2-384",
                                     "SHA2-512",
                                     "SHA2-512-224",
                                     "SHA2-512-256",
                                     "SHA3-224",
                                     "SHA3-256",
                                     "SHA3-384",
                                     "SHA3-512",
                                   };

    return strings[type];
}

int main(int argc, char *argv[])
{
    std::cout << "Hashing Function Test" << std::endl;

    std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0, &random_seed::seed_cb));

    for (size_t i=0; i < 8; i++) {

        utilities::stopwatch sw_hash;
        uint32_t hash_16_us = 0, hash_512_us = 0, hash_16384_us = 0;

        hash_alg_e type;
        switch (i)
        {
            case 0: type = HASH_SHA2_224; break;
            case 1: type = HASH_SHA2_256; break;
            case 2: type = HASH_SHA2_384; break;
            case 3: type = HASH_SHA2_512; break;
            case 4: type = HASH_SHA3_224; break;
            case 5: type = HASH_SHA3_256; break;
            case 6: type = HASH_SHA3_384; break;
            case 7: type = HASH_SHA3_512; break;
        }

        auto hash = std::unique_ptr<hashing_function>(hashing_function::make(type));

        uint8_t hash_bytes[64];
        phantom_vector<uint8_t> msg(16384);
        rng->get_mem(msg.data(), 16384);

        sw_hash.start();
        for (size_t j=0; j < NUM_ITER; j++) {
            hash->init();
            hash->update(msg.data(), 16);
            hash->final(hash_bytes);
        }
        sw_hash.stop();

        hash_16_us += sw_hash.elapsed_us();

        sw_hash.start();
        for (size_t j=0; j < NUM_ITER; j++) {
            hash->init();
            hash->update(msg.data(), 512);
            hash->final(hash_bytes);
        }
        sw_hash.stop();

        hash_512_us += sw_hash.elapsed_us();

        sw_hash.start();
        for (size_t j=0; j < NUM_ITER; j++) {
            hash->init();
            hash->update(msg.data(), 16384);
            hash->final(hash_bytes);
        }
        sw_hash.stop();

        hash_16384_us += sw_hash.elapsed_us();

        float iter_sec = static_cast<float>(NUM_ITER) * 1000000.0f;

        std::cout << "Hash " << stringFromEnum(type) << std::endl;
        std::cout << "time - 16 bytes  = " << static_cast<float>(hash_16_us)/(NUM_ITER)
                  << " us, " << (16.0f*iter_sec)/(static_cast<float>(hash_16_us) * 1024.0f * 1024.0f)
                  << " MB/sec" << std::endl;
        std::cout << "time - 512 bytes = " << static_cast<float>(hash_512_us)/(NUM_ITER)
                  << " us, " << (512.0f*iter_sec)/(static_cast<float>(hash_512_us) * 1024.0f * 1024.0f)
                  << " MB/sec" << std::endl;
        std::cout << "time - 16 kB     = " << static_cast<float>(hash_16384_us)/(NUM_ITER)
                  << " us, " << (16384.0f*iter_sec)/(static_cast<float>(hash_16384_us) * 1024.0f * 1024.0f)
                  << " MB/sec" << std::endl;
    }

    for (size_t i=0; i < 2; i++) {

        utilities::stopwatch sw_xof;
        uint32_t xof_16_us = 0, xof_512_us = 0, xof_16384_us = 0;

        xof_alg_e type;
        switch (i)
        {
            case 0: type = XOF_SHAKE_128; break;
            case 1: type = XOF_SHAKE_256; break;
        }

        auto xof = std::unique_ptr<hashing_function>(hashing_function::make(type));

        phantom_vector<uint8_t> xof_vec(16384);
        uint8_t *xof_bytes = xof_vec.data();
        phantom_vector<uint8_t> msg(16384);
        rng->get_mem(msg.data(), 16384);

        sw_xof.start();
        for (size_t j=0; j < NUM_ITER; j++) {
            xof->init();
            xof->update(msg.data(), 16);
            xof->final();
            xof->squeeze(xof_bytes, 16);
        }
        sw_xof.stop();

        xof_16_us += sw_xof.elapsed_us();

        sw_xof.start();
        for (size_t j=0; j < NUM_ITER; j++) {
            xof->init();
            xof->update(msg.data(), 512);
            xof->final();
            xof->squeeze(xof_bytes, 512);
        }
        sw_xof.stop();

        xof_512_us += sw_xof.elapsed_us();

        sw_xof.start();
        for (size_t j=0; j < NUM_ITER; j++) {
            xof->init();
            xof->update(msg.data(), 16384);
            xof->final();
            xof->squeeze(xof_bytes, 16384);
        }
        sw_xof.stop();

        xof_16384_us += sw_xof.elapsed_us();

        float iter_sec = static_cast<float>(NUM_ITER) * 1000000.0f;

        std::cout << "XOF " << ((0 == i)? "SHAKE-128" : "SHAKE-256") << std::endl;
        std::cout << "time - 16 bytes  = " << static_cast<float>(xof_16_us)/(NUM_ITER)
                  << " us, " << (16.0f*iter_sec)/(static_cast<float>(xof_16_us) * 1024.0f * 1024.0f)
                  << " MB/sec" << std::endl;
        std::cout << "time - 512 bytes = " << static_cast<float>(xof_512_us)/(NUM_ITER)
                  << " us, " << (512.0f*iter_sec)/(static_cast<float>(xof_512_us) * 1024.0f * 1024.0f)
                  << " MB/sec" << std::endl;
        std::cout << "time - 16 kB     = " << static_cast<float>(xof_16384_us)/(NUM_ITER)
                  << " us, " << (16384.0f*iter_sec)/(static_cast<float>(xof_16384_us) * 1024.0f * 1024.0f)
                  << " MB/sec" << std::endl;
    }

    return EXIT_SUCCESS;
}
