/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "bindings/c/build_info.h"
#include <cstdio>
#include <string>
#include "./phantom.hpp"

extern "C" {


const char* build_version()
{
    return strncpy(new char[phantom::build_info::version().length()],  // flawfinder: ignore
                   phantom::build_info::version().c_str(),
                   phantom::build_info::version().length());
}

const char* build_datetime()
{
    return strncpy(new char[phantom::build_info::build_date().length()],  // flawfinder: ignore
                   phantom::build_info::build_date().c_str(),
                   phantom::build_info::build_date().length());
}

const char* build_compiler()
{
    return strncpy(new char[phantom::build_info::compiler().length()],  // flawfinder: ignore
                   phantom::build_info::compiler().c_str(),
                   phantom::build_info::compiler().length());
    return phantom::build_info::compiler().c_str();
}

}
