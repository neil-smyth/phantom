/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <cstdint>
#include <cstring>
#include <iostream>
#include "crypto/csprng.hpp"


namespace phantom {
namespace sampling {

/// @class uniform_sampler A class to provide a uniform random sampler
class uniform_sampler
{
public:
    template<typename T, typename S>
    static void vec_sample(csprng* const rng, T *v, size_t n_bits, const S *c, size_t c_len, uint16_t q)
    {
        // Create a bit mask for n_bits
        uint32_t mask = (1 << n_bits) - 1;

        // Reset the output polynomial to all zeros
        for (size_t i = 1 << n_bits; i--;) {
            v[i] = 0;
        }

        // Given the list of coefficient occurences c (in descending order of value),
        // randomly place the correct number of signed coefficients within the
        // polynomial of dimension n.
        for (size_t j = 0; j < c_len; j++) {
            size_t i = 0;
            while (i < c[j]) {
                uint32_t rand = rng->get_u32();
                size_t index = (rand >> 1) & mask;

                // if (0 == v[index]) {
                //     v[index] = (rand & 1)? j-c_len : c_len-j;
                //     i++;
                // }
                T select  = 0 == v[index];
                T update  = c_len - j;
                update   ^= (update ^ -update) & -(rand & 0x1);
                v[index] ^= (v[index] ^ update) & -select;
                i += select;
            }
        }
    }
};

}  // namespace sampling
}  // namespace phantom
