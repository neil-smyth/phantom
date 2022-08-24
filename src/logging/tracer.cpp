/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "logging/tracer.hpp"
#include <sstream>
#include <chrono>  // NOLINT
#include <ctime>
#include <thread>  // NOLINT

namespace phantom {
namespace logging {

#ifdef _ENABLE_TRACING
tracer& debug_tracer()
{
    static tracer trace;
    return trace;
}
#endif



void tracer::traceline(trace_type_e type, std::string const &message,
    const char *file, const char *func, int32_t line)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    m_file << std::dec;
    insert_datetime();

    std::thread::id this_id = std::this_thread::get_id();
    m_file << this_id << " ";

    switch (type)
    {
        case TRACE_TYPE_START: m_file << "Enter "; break;
        case TRACE_TYPE_STOP:  m_file << "Exit  "; break;
        case TRACE_TYPE_ERROR: m_file << "ERROR "; break;
        default:               m_file << "      ";
    }

    m_file << std::setfill(' ')
        << std::setw(30)
        << std::left
        << file
        << std::setw(5)
        << std::right
        << line
        << " : "
        << message
        << std::endl;
}

}  // namespace logging
}  // namespace phantom
