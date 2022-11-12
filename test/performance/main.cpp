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
#if defined(ENABLE_PKC_IBE)
#include "test/performance/perf_ibe.hpp"
#endif
#if defined(ENABLE_PKC_KEM)
#include "test/performance/perf_kem.hpp"
#endif
#if defined(ENABLE_PKC_KEX)
#include "test/performance/perf_kex.hpp"
#endif
#if defined(ENABLE_PKC_PKE)
#include "test/performance/perf_pke.hpp"
#endif
#if defined(ENABLE_PKC_SIG)
#include "test/performance/perf_sig.hpp"
#endif
#if defined(ENABLE_HASH)
#include "test/performance/perf_sha2.hpp"
#include "test/performance/perf_sha3.hpp"
#endif
#if defined(ENABLE_XOF)
#include "test/performance/perf_shake.hpp"
#endif
#include "test/performance/perf_aes.hpp"
#include "./phantom.hpp"
#include <nlohmann/json.hpp>


using json = nlohmann::json;

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;

    const size_t test_duration = 1000000;

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
        {"pkc", json::array()},
        {"hashing", json::object()},
        {"xof", json::object()},
        {"symmetric_key", json::object()}
    };

    (void)test_duration;

    do {
        json test = {
            {"word_size", static_cast<int>(word_size)},
            {"masking", masking},
            {"ibe", json::array()},
            {"kem", json::array()},
            {"kex", json::array()},
            {"pke", json::array()},
            {"sig", json::array()}
        };

#if defined(ENABLE_PKC_IBE)
#if defined(ENABLE_IBE_DLP)
        test["ibe"].push_back(perf_ibe::run(phantom::PKC_IBE_DLP, test_duration, word_size, masking));
#endif
#endif
#if defined(ENABLE_PKC_KEM)
#if defined(ENABLE_KEM_SABER)
        test["kem"].push_back(perf_kem::run(phantom::PKC_KEM_SABER, test_duration, word_size, masking));
#endif
#if defined(ENABLE_KEM_KYBER)
        test["kem"].push_back(perf_kem::run(phantom::PKC_KEM_KYBER, test_duration, word_size, masking));
#endif
#endif
#if defined(ENABLE_PKC_KEX)
#if defined(ENABLE_KEY_EXCHANGE_ECDH)
        test["kex"].push_back(perf_kex::run(phantom::PKC_KEY_ECDH, test_duration, word_size, masking));
#endif
#if defined(ENABLE_PKE_KYBER)
        test["pke"].push_back(perf_pke::run(phantom::PKC_PKE_KYBER, test_duration, word_size, masking));
#endif
#if defined(ENABLE_PKE_SABER)
        test["pke"].push_back(perf_pke::run(phantom::PKC_PKE_SABER, test_duration, word_size, masking));
#endif
#endif
#if defined(ENABLE_PKC_PKE)
#if defined(ENABLE_PKE_RSAES_OAEP)
        test["pke"].push_back(perf_pke::run(phantom::PKC_PKE_RSAES_OAEP, test_duration, word_size, masking));
#endif
#endif
#if defined(ENABLE_PKC_SIG)
#if defined(ENABLE_SIGNATURE_DILITHIUM)
        test["sig"].push_back(perf_sig::run(phantom::PKC_SIG_DILITHIUM, test_duration, word_size, masking));
#endif
#if defined(ENABLE_SIGNATURE_FALCON)
        test["sig"].push_back(perf_sig::run(phantom::PKC_SIG_FALCON, test_duration, word_size, masking));
#endif
#if defined(ENABLE_SIGNATURE_ECDSA)
        test["sig"].push_back(perf_sig::run(phantom::PKC_SIG_ECDSA, test_duration, word_size, masking));
#endif
#if defined(ENABLE_SIGNATURE_EDDSA)
        test["sig"].push_back(perf_sig::run(phantom::PKC_SIG_EDDSA, test_duration, word_size, masking));
#endif
#if defined(ENABLE_SIGNATURE_RSASSA_PSS)
        test["sig"].push_back(perf_sig::run(phantom::PKC_SIG_RSASSA_PSS, test_duration, word_size, masking));
#endif
#endif

        metrics["pkc"].push_back(test);

        masking = !masking;
    } while (!masking);

#if defined(ENABLE_HASH)
    json hashing = {
        {"sha2", perf_sha2::run(test_duration)},
        {"sha3", perf_sha3::run(test_duration)}
    };

    metrics["hashing"] = hashing;
#endif

#if defined(ENABLE_XOF)
    json xof = {
        {"shake", perf_shake::run(test_duration)}
    };

    metrics["xof"] = xof;
#endif

#if defined(ENABLE_CSPRNG) || defined(ENABLE_AES_CTR)|| defined(ENABLE_AES_GCM) || defined(ENABLE_AES_CCM)
    json symmetric_key = {
        {"encryption", json::array()},
        {"auth_encryption", json::array()}
    };

    symmetric_key["encryption"].push_back(perf_aes::run(phantom::SYMKEY_AES_128_ENC, test_duration));
    symmetric_key["encryption"].push_back(perf_aes::run(phantom::SYMKEY_AES_192_ENC, test_duration));
    symmetric_key["encryption"].push_back(perf_aes::run(phantom::SYMKEY_AES_256_ENC, test_duration));
    symmetric_key["encryption"].push_back(perf_aes::run(phantom::SYMKEY_AES_128_CTR, test_duration));
    symmetric_key["encryption"].push_back(perf_aes::run(phantom::SYMKEY_AES_192_CTR, test_duration));
    symmetric_key["encryption"].push_back(perf_aes::run(phantom::SYMKEY_AES_256_CTR, test_duration));
    symmetric_key["auth_encryption"].push_back(perf_aes::run(phantom::SYMKEY_AES_128_GCM, test_duration));
    symmetric_key["auth_encryption"].push_back(perf_aes::run(phantom::SYMKEY_AES_192_GCM, test_duration));
    symmetric_key["auth_encryption"].push_back(perf_aes::run(phantom::SYMKEY_AES_256_GCM, test_duration));
    symmetric_key["auth_encryption"].push_back(perf_aes::run(phantom::SYMKEY_AES_128_CCM, test_duration));
    symmetric_key["auth_encryption"].push_back(perf_aes::run(phantom::SYMKEY_AES_192_CCM, test_duration));
    symmetric_key["auth_encryption"].push_back(perf_aes::run(phantom::SYMKEY_AES_256_CCM, test_duration));

    metrics["symmetric_key"] = symmetric_key;
#endif

    std::ofstream o("phantom_metrics.json");
    o << metrics.dump(2) << std::endl;

    std::cout << std::endl << "Tests complete - results written to <phantom_metrics.json>" << std::endl;

    return EXIT_SUCCESS;
}
