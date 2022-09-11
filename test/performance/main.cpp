/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include <fstream>
#include <iomanip>
#include <iostream>
#include "test/performance/perf_metrics.hpp"
#include <nlohmann/json.hpp>


using json = nlohmann::json;

int main(int argc, char *argv[])
{
    size_t test_duration = 3000000;

    std::cout << "Phantom performance" << std::endl << std::endl;

    json ibe_metrics = std::unique_ptr<perf_metrics>(perf_metrics::make(phantom::PKC_IBE_DLP))->run(test_duration);

    std::ofstream o("phantom_metrics.json");
    o << ibe_metrics.dump(2) << std::endl;

    std::cout << std::endl << "Tests complete - results written to <phantom_metrics.json>" << std::endl;

    return EXIT_SUCCESS;
}
