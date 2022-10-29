/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "logging/logger.hpp"
#include <sstream>
#include <chrono>  // NOLINT
#include <ctime>
#include <thread>  // NOLINT

namespace phantom {
namespace logging {

#ifdef _ENABLE_LOGGING
logger& debug_logger()
{
    static logger log;
    return log;
}
#endif

logger::logger(std::string basename, std::string extension, size_t max_lines) :
    m_basename(basename),
    m_extension(extension),
    m_max_lines(max_lines),
    m_count(0),
    m_ping_pong(false)
{
    // Create the filename of the log file
    std::stringstream ss;
    ss << basename << "_0." << m_extension;

    // Open the log file and erase it
    m_file.open(ss.str(), std::ios::out | std::ios::trunc);  // flawfinder: ignore
    if (!m_file.is_open()) {
        std::cerr << "ERROR! Log file " << ss.str() << " cannot be opened" << std::endl;
        exit(-1);
    }

    m_start_time = std::chrono::system_clock::now();
}

logger::~logger()
{
    if (m_file.is_open()) {
        m_file.close();
    }
}

void logger::logline(log_level_e base_level, log_level_e level, std::string const &message,
    const char *file, const char *func, int32_t line)
{
    if (base_level < level) {
        return;
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    m_file << std::dec;
    insert_datetime();

    std::thread::id this_id = std::this_thread::get_id();
    m_file << this_id << " ";

    switch (level)
    {
        case LOG_LEVEL_DEBUG:   m_file << "DEBUG   "; break;
        case LOG_LEVEL_WARNING: m_file << "WARNING "; break;
        case LOG_LEVEL_ERROR:   m_file << "ERROR   "; break;
        default:                m_file << "        ";
    }

    m_file << std::setfill(' ')
           << std::setw(30)
           << std::left
           << file
           << std::setw(30)
           << std::left
           << func
           << std::setw(5)
           << std::right
           << line
           << " : "
           << message
           << std::endl;
}

void logger::operator()(log_level_e base_level, log_level_e level, std::string const &message,
    const char *file, const char *func, int32_t line)
{
    logline(base_level, level, message, file, func, line);
    m_file.flush();
    check_lines();
}

void logger::insert_datetime()
{
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch() - m_start_time.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(duration);
    m_file << std::setfill('0') << std::setw(3) << std::right
           << seconds.count();
    m_file << std::setfill(' ') << std::setw(1) << std::right
           << ".";
    m_file << std::setfill('0') << std::setw(10) << std::left
           << (nanoseconds.count() - seconds.count()*1000000000);
    m_file << " ";
}

void logger::check_lines()
{
    m_count++;
    if (m_count == m_max_lines) {
        m_count = 0;
        m_ping_pong = !m_ping_pong;

        if (m_file.is_open()) {
           m_file.close();
        }

        std::stringstream ss;
        ss << m_basename << "_" << ((m_ping_pong)? "0" : "1") << "." << m_extension;

        // Open the log file and erase it
        m_file.open(ss.str(), std::ios::out | std::ios::trunc);  // flawfinder: ignore
        if (!m_file.is_open()) {
            std::cerr << "ERROR! Log file " << ss.str() << " cannot be opened" << std::endl;
            exit(-1);
        }
    }
}

}  // namespace logging
}  // namespace phantom

//
// end of file
//
