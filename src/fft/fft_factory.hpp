/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <memory>
#include "fft/fft_avx2.hpp"
#include "fft/fft_generic.hpp"

namespace phantom {

/**
 * @brief Factory class used to create concrete implementations of the fft abstract base class
 * 
 * @tparam T 
 */
template<typename T>
class fft_factory
{
public:
    /**
     * FFT factory method, creates an fft object for the current platform
     * @param logn Length of the data arrays (log base-2)
     */
    static const std::shared_ptr<fft<T>> create(size_t logn)
    {
#if defined(__AVX2__)
        return std::shared_ptr<fft<T>>(new fft_avx2<T>(logn));
#else
        return std::shared_ptr<fft<T>>(new fft_generic<T>(logn));
#endif
    }

};

}  // namespace phantom
