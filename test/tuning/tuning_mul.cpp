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

#include "crypto/csprng.hpp"
#include "crypto/random_seed.hpp"
#include "core/mpbase.hpp"
#include "utils/stopwatch.hpp"


using namespace phantom;  // NOLINT
using namespace core;     // NOLINT

#define NUM_ITER    64
#define MAX_LIMBS   800

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;
    
    std::cout << "Tuning - Multiplication" << std::endl;

    // Create a PRNG to randomize the input numbers
    std::unique_ptr<csprng> rng = std::unique_ptr<csprng>(csprng::make(0, &random_seed::seed_cb));

    uint32_t time_size[3][MAX_LIMBS] = {0};

    for (size_t i=0; i < NUM_ITER; i++) {

        utilities::stopwatch sw_mul;

        phantom_vector<uint32_t> product(MAX_LIMBS*MAX_LIMBS);
        phantom_vector<uint32_t> x(MAX_LIMBS);
        phantom_vector<uint32_t> y(MAX_LIMBS);
        rng->get_mem(reinterpret_cast<uint8_t*>(x.data()), sizeof(uint32_t)*MAX_LIMBS);
        rng->get_mem(reinterpret_cast<uint8_t*>(y.data()), sizeof(uint32_t)*MAX_LIMBS);

        for (size_t j=16; j < MAX_LIMBS; j++) {

            sw_mul.start();
            mpbase<uint32_t>::mul_gradeschool(product.data(), x.data(), j, y.data(), j);
            sw_mul.stop();

            time_size[0][j] += sw_mul.elapsed_us();
        }
    }

    for (size_t i=0; i < NUM_ITER; i++) {

        utilities::stopwatch sw_mul;

        phantom_vector<uint32_t> product(MAX_LIMBS*MAX_LIMBS);
        phantom_vector<uint32_t> x(MAX_LIMBS);
        phantom_vector<uint32_t> y(MAX_LIMBS);
        rng->get_mem(reinterpret_cast<uint8_t*>(x.data()), sizeof(uint32_t)*MAX_LIMBS);
        rng->get_mem(reinterpret_cast<uint8_t*>(y.data()), sizeof(uint32_t)*MAX_LIMBS);

        phantom_vector<uint32_t> scratch(mpbase<uint32_t>::get_toom22_scratch_size(MAX_LIMBS));

        for (size_t j=16; j < MAX_LIMBS; j++) {

            sw_mul.start();
            mpbase<uint32_t>::mul_toom22(product.data(), x.data(), j, y.data(), j, scratch.data());
            sw_mul.stop();

            time_size[1][j] += sw_mul.elapsed_us();
        }
    }

    for (size_t i=0; i < NUM_ITER; i++) {

        utilities::stopwatch sw_mul;

        phantom_vector<uint32_t> product(MAX_LIMBS*MAX_LIMBS);
        phantom_vector<uint32_t> x(MAX_LIMBS);
        phantom_vector<uint32_t> y(MAX_LIMBS);
        rng->get_mem(reinterpret_cast<uint8_t*>(x.data()), sizeof(uint32_t)*MAX_LIMBS);
        rng->get_mem(reinterpret_cast<uint8_t*>(y.data()), sizeof(uint32_t)*MAX_LIMBS);

        phantom_vector<uint32_t> scratch(mpbase<uint32_t>::get_toom33_scratch_size(MAX_LIMBS));

        for (size_t j=16; j < MAX_LIMBS; j++) {

            sw_mul.start();
            mpbase<uint32_t>::mul_toom33(product.data(), x.data(), j, y.data(), j, scratch.data());
            sw_mul.stop();

            time_size[2][j] += sw_mul.elapsed_us();
        }
    }

    uint32_t found = 0;
    for (size_t j = 16; j < 400; j++) {
        if (found < 3 && time_size[0][j] > time_size[1][j]) {
            found++;
            if (found == 3) {
                std::cout << "MUL_TOOM22_THRESHOLD = " << j << std::endl;
                break;
            }
        }
        else {
            found = 0;
        }
    }

    found = 0;
    for (size_t j = 16; j < 400; j++) {
        if (found < 3 && time_size[1][j] > time_size[2][j]) {
            found++;
            if (found == 3) {
                std::cout << "MUL_TOOM33_THRESHOLD = " << j << std::endl;
                break;
            }
        }
        else {
            found = 0;
        }
    }

    return EXIT_SUCCESS;
}
