/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "core/poly.hpp"


namespace phantom {
namespace core {

// Forward declaration of common sizes
template class poly<uint8_t>;
template class poly<uint16_t>;
template class poly<uint32_t>;
#if defined(IS_64BIT)
template class poly<uint64_t>;
#endif

}  // namespace core
}  // namespace phantom
