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
#include <cstring>
#include <chrono>  // NOLINT
#include <thread>  // NOLINT


namespace phantom {
namespace utilities {

/**
 * @brief A general-purpose class to provide time and sleep functionality
 */
class timing
{
public:
    /// @brief Delay for the specified time period
    /// @param ms Delay period in milliseconds
    static void millisleep(uint32_t ms)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    }

    /// @brief Delay for the specified time period
    /// @param ms Delay period in microseconds
    static void microsleep(uint32_t us)
    {
        std::this_thread::sleep_for(std::chrono::microseconds(us));
    }

    /// @brief Obtain the current time (in milliseconds)
    /// @return A 32-bit representation of the system time in milliseconds
    static uint32_t get_ms()
    {
        std::chrono::time_point<std::chrono::steady_clock> now;
        now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    }

    /// @brief Obtain the current time (in microseconds)
    /// @return A 64-bit representation of the system time in microseconds
    static uint64_t get_us()
    {
        std::chrono::time_point<std::chrono::steady_clock> now;
        now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    }
};

}  // namespace utilities
}  // namespace phantom
