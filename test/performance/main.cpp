/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include <chrono>  // NOLINT
#include <fstream>
#include <iomanip>
#include <iostream>
#include "test/performance/perf_ibe.hpp"
#include "test/performance/perf_kem.hpp"
#include "test/performance/perf_kex.hpp"
#include "test/performance/perf_pke.hpp"
#include "test/performance/perf_sig.hpp"
#include "test/performance/perf_sha2.hpp"
#include "test/performance/perf_sha3.hpp"
#include "./phantom.hpp"
#include <nlohmann/json.hpp>


using json = nlohmann::json;

int main(int argc, char *argv[])
{
    size_t test_duration = 1000000;

    std::cout << "Phantom performance" << std::endl << std::endl;

    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream timestamp;
    timestamp << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X");

    phantom::cpu_word_size_e word_size = NATIVE_CPU_WORD_SIZE;
    bool                     masking   = true;

    json metrics = {
        {"version", phantom::build_info::version()},
        {"build_date", phantom::build_info::build_date()},
        {"compiler", phantom::build_info::compiler()},
        {"timestamp", timestamp.str()},
        {"tests", json::array()}
    };

    do {
        json test = {
            {"word_size", static_cast<int>(word_size)},
            {"masking", masking},
            {"testcases", json::array()}
        };

        test["testcases"].push_back(perf_ibe::run(phantom::PKC_IBE_DLP, test_duration, word_size, masking));
        test["testcases"].push_back(perf_kem::run(phantom::PKC_KEM_SABER, test_duration, word_size, masking));
        test["testcases"].push_back(perf_kem::run(phantom::PKC_KEM_KYBER, test_duration, word_size, masking));
        test["testcases"].push_back(perf_kex::run(phantom::PKC_KEY_ECDH, test_duration, word_size, masking));
        test["testcases"].push_back(perf_pke::run(phantom::PKC_PKE_KYBER, test_duration, word_size, masking));
        test["testcases"].push_back(perf_pke::run(phantom::PKC_PKE_SABER, test_duration, word_size, masking));
        test["testcases"].push_back(perf_pke::run(phantom::PKC_PKE_RSAES_OAEP, test_duration, word_size, masking));
        test["testcases"].push_back(perf_sig::run(phantom::PKC_SIG_DILITHIUM, test_duration, word_size, masking));
        test["testcases"].push_back(perf_sig::run(phantom::PKC_SIG_FALCON, test_duration, word_size, masking));
        test["testcases"].push_back(perf_sig::run(phantom::PKC_SIG_ECDSA, test_duration, word_size, masking));
        test["testcases"].push_back(perf_sig::run(phantom::PKC_SIG_EDDSA, test_duration, word_size, masking));
        test["testcases"].push_back(perf_sig::run(phantom::PKC_SIG_RSASSA_PSS, test_duration, word_size, masking));

        metrics["tests"].push_back(test);

        masking = !masking;
    } while (!masking);

    json hash_test = {
            {"word_size", static_cast<int>(word_size)},
            {"masking", masking},
            {"testcases", json::array()}
        };

    hash_test["testcases"].push_back(perf_sha2::run(test_duration));
    hash_test["testcases"].push_back(perf_sha3::run(test_duration));

    metrics["tests"].push_back(hash_test);

    std::ofstream o("phantom_metrics.json");
    o << metrics.dump(2) << std::endl;

    std::cout << std::endl << "Tests complete - results written to <phantom_metrics.json>" << std::endl;

    return EXIT_SUCCESS;
}
