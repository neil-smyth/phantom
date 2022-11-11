/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <string>
#include <atomic>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <chrono>  // NOLINT
#include <mutex>  // NOLINT
#include <limits>

#include "./phantom_types.hpp"

#define LOGGER_DEFAULT_BASENAME          "debug"
#define LOGGER_DEFAULT_BASE_EXTENSION    "log"
#define LOGGER_DEFAULT_MAX_LINES         100000

#define ARRAY_LEFT_SPACING               8
#define ARRAY_BYTE_WIDTH                 16
#define ARRAY_BYTE_MARKER                (ARRAY_BYTE_WIDTH - 1)


namespace phantom {
namespace logging {


/**
 * @brief A logging class that ping pongs between two files with a common base name
 */
class logger
{
public:
    /// The logger class is configured upon instantiation
    logger(std::string basename  = LOGGER_DEFAULT_BASENAME,
           std::string extension = LOGGER_DEFAULT_BASE_EXTENSION,
           size_t      max_lines = LOGGER_DEFAULT_MAX_LINES);

    /// The class destructor
    ~logger();

    /// Methods to write log lines
    void operator() (log_level_e        base_level,
                     log_level_e        level,
                     std::string const &message,
                     const char        *file,
                     const char        *func,
                     int32_t            line);

    template<typename T>
    void operator() (log_level_e        base_level,
                     log_level_e        level,
                     std::string const &message,
                     const T           *data,
                     size_t             len,
                     const char        *file,
                     const char        *func,
                     int32_t            line)
    {
        logline(base_level, level, message, file, func, line);
        size_t i;
        for (i=0; i < len; i++) {
            if (0 == (i&ARRAY_BYTE_MARKER)) {
                m_file << std::setfill(' ')
                       << std::setw(ARRAY_LEFT_SPACING)
                       << " ";
            }
            m_file << std::dec
                   << std::setw((std::numeric_limits<T>::digits >> 2)+1)
                   << static_cast<int32_t>(data[i])
                   << " ";
            if (ARRAY_BYTE_MARKER == (i&ARRAY_BYTE_MARKER)) {
                m_file << std::endl;
            }
        }
        if (0 != (ARRAY_BYTE_MARKER&i)) {
            m_file << std::endl;
        }
        m_file.flush();
        check_lines();
    }

protected:
    void insert_datetime();
    void check_lines();
    void logline(log_level_e        base_level,
                 log_level_e        level,
                 std::string const &message,
                 const char        *file,
                 const char        *func,
                 int32_t            line);

    /// The configuration options
    std::string   m_basename;
    std::string   m_extension;
    size_t        m_max_lines;
    size_t        m_count;
    bool          m_ping_pong;

    std::chrono::time_point<std::chrono::system_clock> m_start_time;

    /// The current output file
    std::ofstream m_file;

    /// A mutex for thread-safety
    std::mutex    m_mutex;
};


#ifndef _ENABLE_LOGGING
#define LOG_DEBUG(message_, level_) do {} while (0)
#define LOG_DEBUG_ARRAY(message_, level_, data_, len_) do {} while (0)
#define LOG_WARNING(message_, level_) do {} while (0)
#define LOG_WARNING_ARRAY(message_, level_, data_, len_) do {} while (0)
#define LOG_ERROR(message_, level_) do {} while (0)
#define LOG_ERROR_ARRAY(message_, level_, data_, len_) do {} while (0)
#else
extern logger& debug_logger();

#define LOG(logger_, base_level_, level_, message_)        \
logger_(                                      \
base_level_,                                  \
level_,                                       \
static_cast<std::ostringstream&>(             \
    std::ostringstream().flush() << message_  \
).str(),                                      \
__FILE__,                                     \
__FUNCTION__,                                 \
__LINE__                                      \
);

#define LOG_ARRAY(logger_, base_level_, level_, message_, data_, len_) \
logger_(                                                  \
base_level_,                                              \
level_,                                                   \
static_cast<std::ostringstream&>(                         \
    std::ostringstream().flush() << message_              \
).str(),                                                  \
data_,                                                    \
len_,                                                     \
__FILE__,                                                 \
__FUNCTION__,                                             \
__LINE__                                                  \
);

#define LOG_DEBUG(message_, level_) LOG(logging::debug_logger(), level_, \
    log_level_e::LOG_LEVEL_DEBUG, message_)
#define LOG_DEBUG_ARRAY(message_, level_, data_, len_) LOG_ARRAY(logging::debug_logger(), level_, \
    log_level_e::LOG_LEVEL_DEBUG, message_, data_, len_)
#define LOG_WARNING(message_, level_) LOG(logging::debug_logger(), level_, \
    log_level_e::LOG_LEVEL_WARNING, message_)
#define LOG_WARNING_ARRAY(message_, level_, data_, len_) LOG_ARRAY(logging::debug_logger(), level_, \
    log_level_e::LOG_LEVEL_WARNING, message_, data_, len_)
#define LOG_ERROR(message_, level_) LOG(logging::debug_logger(), level_, \
    log_level_e::LOG_LEVEL_ERROR, message_)
#define LOG_ERROR_ARRAY(message_, level_, data_, len_) LOG_ARRAY(logging::debug_logger(), level_, \
    log_level_e::LOG_LEVEL_ERROR, message_, data_, len_)

#endif  // _ENABLE_LOGGING

}  // namespace logging
}  // namespace phantom


//
// end of file
//
