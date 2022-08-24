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
 * @brief Stopwatch functionality used std::chrono
 */
class stopwatch
{
protected:
    std::chrono::time_point<std::chrono::steady_clock> m_start;
    std::chrono::time_point<std::chrono::steady_clock> m_stop;
    bool m_started;

public:
    /// The constructor
    stopwatch();

    /// The destructor
    ~stopwatch();

    /// Starts the timer counter
    void start();

    /// Stops the timer counter
    void stop();

    /// Indicates the number of seconds elapsed
    /// @return Number of seconds elapsed between the most recent set of start() and stop() calls
    double elapsed();

    /// Indicates the number of milliseconds elapsed
    /// @return Number of milliseconds elapsed between the most recent set of start() and stop() calls
    uint32_t elapsed_ms();

    /// Indicates the number of microseconds elapsed
    /// @return Number of microseconds elapsed between the most recent set of start() and stop() calls
    uint32_t elapsed_us();
};

}  // namespace utilities
}  // namespace phantom
