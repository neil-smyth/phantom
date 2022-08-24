/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include "./phantom.hpp"


namespace phantom {
namespace core {

/**
 * @brief A struct used to define a small prime number
 */
struct small_prime_s {
    uint32_t p;
    uint32_t g;
    uint32_t s;
};

using small_prime = small_prime_s;

extern const size_t max_bl_small2[];
extern const size_t max_bl_large2[];
extern const small_prime small_primes_u31[522];

#define PHANTOM_NUM_FIRST_PRIMES_8BIT   54
#define PHANTOM_NUM_FIRST_PRIMES        70
extern const uint16_t first_primes_list[PHANTOM_NUM_FIRST_PRIMES];

}  // namespace core
}  // namespace phantom

//
// end of file#
//
