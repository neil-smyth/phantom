/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include "./phantom_types.hpp"

#if defined(__linux__) || defined(__APPLE__)
#include <iostream>
#include <fstream>
#include <iterator>
#endif

#if defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#endif

namespace phantom
{

/// @todo An interface should be provided through the phantom.hpp API to allow
/// users to specify their own callback methods for their platform. They may have
/// hardware RNG's that can be exploited (I got my hands on an HSM :)) or an OS
/// that requires specific support. The library should default to generic OS
/// dependant RNG's (i.e. Linux, OSX, Windows) if the user does not define their
/// own random seed callback.


/**
 * @ingroup random
 * @brief A class used to provide a callback function for CSPRNG bytes
 */
class random_seed
{
public:
    /**
     * @brief A static method used by all schemes to provide random seed bytes
     * 
     * @param len Number of random bytes to generate
     * @param data Byte array in which random bytes are placed
     */
    static void seed_cb(size_t len, uint8_t* data)
    {
#if defined(__linux__) || defined(__APPLE__)
        seed_cb_dev_urandom(len, data);
#else
#if defined(_WIN32)
        seed_cb_windows(len, data);
#endif
#endif
    }

private:
#if defined(__linux__) || defined(__APPLE__)
    /**
     * @brief A static method used by all schemes to provide random seed bytes
     * 
     * @param len Number of random bytes to generate
     * @param data Byte array in which random bytes are placed
     */
    static int32_t seed_cb_dev_urandom(size_t len, uint8_t* data)
    {
        // Open the stream and check for success
        std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
        if (!urandom) {
            return EXIT_FAILURE;
        }

        if (urandom.is_open()) {
            urandom.read(reinterpret_cast<char*>(data), len);  // flawfinder: ignore

            // Close the stream
            urandom.close();

            return urandom.rdstate() ? EXIT_FAILURE : EXIT_SUCCESS;
        }

        return EXIT_FAILURE;
    }
#endif

#if defined(_WIN32)
    static int32_t seed_cb_windows(size_t len, uint8_t* data)
    {
        HCRYPTPROV hCryptProv;
        if (!CryptAcquireContextA(&hCryptProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
            return EXIT_FAILURE;
        }

        size_t num_words = len >> 30;
        for (size_t i = 0; i < num_words; i++) {
            if (!CryptGenRandom(hCryptProv, 1UL << 30, reinterpret_cast<BYTE*>(data) )) {
                return EXIT_FAILURE;
            }
        }

        if (!CryptGenRandom(hCryptProv, len & ((1UL << 30) - 1), reinterpret_cast<BYTE*>(data))) {
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }
#endif
};

}  // namespace phantom
