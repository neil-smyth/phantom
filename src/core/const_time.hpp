/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include "core/const_time_enabled.hpp"
#include "core/const_time_disabled.hpp"

#if defined(DISABLE_CONSTANT_TIME)
template<typename T>
using const_time = phantom::core::const_time_disabled<T>;
#else
template<typename T>
using const_time = phantom::core::const_time_enabled<T>;
#endif
