/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "utils/uuid.hpp"

#ifdef ENABLE_LIBUUID
#include <uuid/uuid.h>
#include <iostream>
#endif

namespace phantom {
namespace utilities {


std::string uuid::generate()
{
#ifdef ENABLE_LIBUUID
    uuid_t id;
    uuid_generate_time_safe(id);

    char s[37];
    uuid_unparse_lower(id, s);

    return std::string(s);
#else
    return std::string();
#endif
}


}  // namespace utilities
}  // namespace phantom
