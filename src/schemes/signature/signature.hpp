/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include "./phantom.hpp"
#include "schemes/scheme.hpp"


namespace phantom {

/**
 * @brief A pure abstract base class for Signatures
 */
class signature : public scheme
{
public:
    virtual ~signature() {}

    /// @brief Signing of a message
    /// @param ctx The user context containing the key
    /// @param m The input message to be signed
    /// @param s The output signature
    /// @return True on success, false otherwise
    virtual bool sign(const std::unique_ptr<user_ctx>& ctx,
        const phantom_vector<uint8_t>& m, phantom_vector<uint8_t>& s) = 0;

    /// @brief Signing of a message
    /// @param ctx The user context containing the key
    /// @param m The input message to be signed
    /// @param s The output signature
    /// @param c The output signature
    /// @return True on success, false otherwise
    virtual bool sign(const std::unique_ptr<user_ctx>& ctx,
        const phantom_vector<uint8_t>& m, phantom_vector<uint8_t>& s, const phantom_vector<uint8_t>& c)
    {
        return false;
    }

    /// @brief Verification of a message
    /// @param ctx The user context containing the key
    /// @param m The input message to be signed
    /// @param s The input signature
    /// @return True on success, false otherwise
    virtual bool verify(const std::unique_ptr<user_ctx>& ctx,
        const phantom_vector<uint8_t>& m, const phantom_vector<uint8_t>& s) = 0;
    virtual bool verify(const std::unique_ptr<user_ctx>& ctx,
        const phantom_vector<uint8_t>& m, const phantom_vector<uint8_t>& s, const phantom_vector<uint8_t>& c)
    {
        return false;
    }
};

}  // namespace phantom


