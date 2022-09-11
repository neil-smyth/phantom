/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include "test/performance/perf_ibe.hpp"
#include "test/performance/perf_kem.hpp"
#include "./phantom.hpp"
#include <nlohmann/json.hpp>


using json = nlohmann::json;

int main(int argc, char *argv[])
{
    size_t test_duration = 3000000;

    std::cout << "Phantom performance" << std::endl << std::endl;

    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream timestamp;
    timestamp << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X");

    json metrics = {
        {"version", phantom::build_info::version()},
        {"build_date", phantom::build_info::build_date()},
        {"compiler", phantom::build_info::compiler()},
        {"timestamp", timestamp.str()},
        {"tests", json::array()}
    };

    metrics["tests"].push_back(perf_ibe::run(phantom::PKC_IBE_DLP,   test_duration));
    metrics["tests"].push_back(perf_kem::run(phantom::PKC_KEM_SABER, test_duration));
    metrics["tests"].push_back(perf_kem::run(phantom::PKC_KEM_KYBER, test_duration));

    std::ofstream o("phantom_metrics.json");
    o << metrics.dump(2) << std::endl;

    std::cout << std::endl << "Tests complete - results written to <phantom_metrics.json>" << std::endl;

    return EXIT_SUCCESS;
}
