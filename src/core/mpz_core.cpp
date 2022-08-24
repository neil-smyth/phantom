/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "core/mpz_core.hpp"


namespace phantom {
namespace core {

// Forward declaration of common sizes
template class mpz_core<uint8_t>;
template class mpz_core<uint16_t>;
template class mpz_core<uint32_t>;
#if defined(IS_64BIT)
template class mpz_core<uint64_t>;
#endif

}  // namespace core
}  // namespace phantom
