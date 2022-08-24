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
#include "./phantom_memory.hpp"


namespace phantom {
namespace crypto {

/**
 * @ingroup hashing
 * @brief The Keccak core function
 */
class keccak
{
public:
    static void core(uint64_t* _RESTRICT_ st, size_t rounds);

protected:
    alignas(DEFAULT_MEM_ALIGNMENT) static const uint64_t keccakf_rndc[24];
    alignas(DEFAULT_MEM_ALIGNMENT) static const size_t keccakf_rotc[24];
    alignas(DEFAULT_MEM_ALIGNMENT) static const size_t keccakf_piln[24];
    alignas(DEFAULT_MEM_ALIGNMENT) static const size_t i4mod5[5];
    alignas(DEFAULT_MEM_ALIGNMENT) static const size_t i2mod5[5];
    alignas(DEFAULT_MEM_ALIGNMENT) static const size_t i1mod5[5];
};

}  // namespace crypto
}  // namespace phantom
