/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "./phantom_types.hpp"
#include "test/performance/perf_metrics.hpp"
#include "test/performance/perf_ibe.hpp"
#include <nlohmann/json.hpp>

using json = nlohmann::json;


perf_metrics* perf_metrics::make(phantom::pkc_e pkc_type)
{
    switch (pkc_type)
    {
        case phantom::PKC_IBE_DLP: return new perf_ibe();
        default:                   throw new std::runtime_error("Error! Unknown performance metrics test");
    }
}
