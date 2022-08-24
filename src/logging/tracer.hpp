/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
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

#include "logging/logger.hpp"


#define TRACE_DEFAULT_BASENAME          "trace"
#define TRACE_DEFAULT_BASE_EXTENSION    "log"
#define TRACE_DEFAULT_MAX_LINES         100000


namespace phantom {
namespace logging {

/// The enumerated trace type
enum trace_type_e {
    TRACE_TYPE_START = 0,
    TRACE_TYPE_STOP,
    TRACE_TYPE_ERROR,
};

/**
 * @brief A tracing class that ping pongs between two files with a common base name
 * 
 */
class tracer : public logger
{
public:
    /// The trace class is configured upon instantiation
    tracer(std::string basename  = TRACE_DEFAULT_BASENAME,
           std::string extension = TRACE_DEFAULT_BASE_EXTENSION,
           size_t      max_lines = TRACE_DEFAULT_MAX_LINES) :
           logger(basename, extension, max_lines)
    {
    }

    /// The class destructor
    ~tracer();

    void traceline(trace_type_e type, std::string const &message,
        const char *file, const char *func, int32_t line);

};


#ifndef _ENABLE_TRACING
#define TRACE_START(_) do {} while (0)
#define TRACE_STOP(_)  do {} while (0)
#define TRACE_ERROR(_) do {} while (0)
#else
extern logger& debug_tracer();

#define LOG(tracer_, type_, message_)         \
tracer_(                                      \
type_,                                        \
static_cast<std::ostringstream&>(             \
    std::ostringstream().flush() << message_  \
).str(),                                      \
__FILE__,                                     \
__FUNCTION__,                                 \
__LINE__                                      \
);

#define TRACE_START(message_) TRACE(debug_tracer(), trace_type_e::TRACE_TYPE_START, message_)
#define TRACE_STOP(message_)  TRACE(debug_tracer(), trace_type_e::TRACE_TYPE_STOP,  message_)
#define TRACE_ERROR(message_) TRACE(debug_tracer(), trace_type_e::TRACE_TYPE_ERROR, message_)

#endif  // _ENABLE_TRACING

}  // namespace logging
}  // namespace phantom
