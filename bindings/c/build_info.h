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

namespace phantom {

typedef struct cfpe       cfpe;
typedef struct cfpe_ctx   cfpe_ctx;

#ifdef __cplusplus
extern "C" {
#endif

    /// Get the semantic version number string for phantom
    const char* build_version();

    /// Get the build's date and time string from phantom
    const char* build_datetime();

    /// Get the compiler details from phantom
    const char* build_compiler();

#ifdef __cplusplus
}
#endif

}  // namespace phantom
