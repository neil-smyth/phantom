/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <new>
#include <string>
#include <vector>

#include "./phantom_types.hpp"

namespace phantom {


/**
 * @ingroup symmetric
 * @brief Format Preserving Encryption
 * 
 * An interface to create FPE objects and provide a common interface (factory method)
 */
class fpe
{
public:
    fpe() {}
    virtual ~fpe() {}

    /// @brief Create a context for the fpe instance based on the user's selected options
    /// @param user_key The user;s key (a byte array)
    /// @param type The tpe of FPE to be used
    /// @param format The FPE format to be used (character set, representation)
    /// @param tweak // The FPE tweak to be used (optional)
    /// @return The FPE context returned in a smart pointer
    static std::unique_ptr<fpe_ctx> create_ctx(const phantom_vector<uint8_t>& user_key,
        fpe_type_e type, fpe_format_e format, const phantom_vector<uint8_t>& tweak);

    /// Single value encryption methods
    /// @{
    static void encrypt_str(std::unique_ptr<fpe_ctx>& ctx, std::string& inout);
    static void encrypt_number(std::unique_ptr<fpe_ctx>& ctx, int& inout, int range);
    static void encrypt_float(std::unique_ptr<fpe_ctx>& ctx, double& inout, int range, int precision);
    static void encrypt_iso8601(std::unique_ptr<fpe_ctx>& ctx, std::string& inout);
    /// @}

    /// Array encryption methods
    /// @{
    static void encrypt_str(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<std::string>& inout);
    static void encrypt_number(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<int>& inout, int range);
    static void encrypt_float(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<double>& inout, int range, int precision);
    static void encrypt_iso8601(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<std::string>& inout);
    /// @}

    /// Single value decryption methods
    /// @{
    static void decrypt_str(std::unique_ptr<fpe_ctx>& ctx, std::string& inout);
    static void decrypt_number(std::unique_ptr<fpe_ctx>& ctx, int& inout, int range);
    static void decrypt_float(std::unique_ptr<fpe_ctx>& ctx, double& inout, int range, int precision);
    static void decrypt_iso8601(std::unique_ptr<fpe_ctx>& ctx, std::string& inout);
    /// @}

    /// Array decryption methods
    /// @{
    static void decrypt_str(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<std::string>& inout);
    static void decrypt_number(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<int>& inout, int range);
    static void decrypt_float(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<double>& inout, int range, int precision);
    static void decrypt_iso8601(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<std::string>& inout);
    /// @}

private:
    /// Map the input value to a 0-based radix equivalent
    static void map(fpe_format_e format, const std::string& in, phantom_vector<uint8_t>& out,
        phantom_vector<pad_code>& pad, uint8_t& radix);

    /// Unmap the 0-based radix equivalent back to the original representation
    static void unmap(fpe_format_e format, const phantom_vector<uint8_t>& in, std::string& out,
        const phantom_vector<pad_code>& pad);

    /// Parse an ISO8601 date/time string and extract the date/time to 1 second granularity
    static bool parse_iso8601(const std::string& iso8601, int& year, int& month, int& day,
        int& hours, int& minutes, int& seconds);

    /// Amend an ISO8601 date/time string with the specified date/time parameters
    static std::string amend_iso8601(const std::string& iso8601, int year, int month, int day,
        int hours, int minutes, int seconds);

    /// Translate year/month/day date parameters to a Rata Die number
    static uint32_t rdn(int y, int m, int d);

    /// Translate a Rata Die number to year/month/day date parameters
    static void inverse_rdn(int rdn, int& year, int& month, int& day);
};

}  // namespace phantom
