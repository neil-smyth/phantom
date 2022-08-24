/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "core/ntt_binary.hpp"


namespace phantom {
namespace core {

// Forward declaration of common type declarations
template class ntt_binary<reduction_montgomery<uint32_t>, uint32_t>;

}  // namespace core
}  // namespace phantom
