/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "ecc/prime_point.hpp"


namespace phantom {
namespace elliptic {

// Forward declaration of common sizes
template class prime_point<uint8_t>;
template class prime_point<uint16_t>;
template class prime_point<uint32_t>;
template class prime_point<uint64_t>;

}  // namespace elliptic
}  // namespace phantom
