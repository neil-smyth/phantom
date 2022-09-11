/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include "test/performance/perf_metrics.hpp"
#include <nlohmann/json.hpp>

using json = nlohmann::json;


class perf_ibe
{
public:
    static json run(phantom::pkc_e pkc_type, size_t duration_us);
};
