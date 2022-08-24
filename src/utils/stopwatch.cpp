/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "utils/stopwatch.hpp"


namespace phantom {
namespace utilities {


stopwatch::stopwatch() : m_started(false)
{
}

stopwatch::~stopwatch()
{
}

void stopwatch::start()
{
    m_start   = m_stop = std::chrono::steady_clock::now();
    m_started = true;
}

void stopwatch::stop()
{
    m_started = false;
    m_stop    = std::chrono::steady_clock::now();
}

double stopwatch::elapsed()
{
    std::chrono::duration<double> elapsed = m_stop - m_start;
    return elapsed.count();
}

uint32_t stopwatch::elapsed_ms()
{
    std::chrono::duration<double> elapsed = m_stop - m_start;
    std::chrono::milliseconds d = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed);
    return d.count();
}

uint32_t stopwatch::elapsed_us()
{
    std::chrono::duration<double> elapsed = m_stop - m_start;
    std::chrono::microseconds d = std::chrono::duration_cast<std::chrono::microseconds>(elapsed);
    return d.count();
}

}  // namespace utilities
}  // namespace phantom
