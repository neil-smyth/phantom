/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <type_traits>
#include <cstdint>
#include <cstring>
#include <memory>

#include "core/reduction.hpp"
#include "core/bit_manipulation.hpp"


namespace phantom {
namespace core {

/**
 * @brief A pure virtual base class to define an interface for Number Theoretic Transforms
 * 
 * @tparam T 
 * @tparam std::enable_if<std::is_unsigned<T>::value, T>::type 
 */
template<typename T, typename = typename std::enable_if<std::is_unsigned<T>::value, T>::type>
class ntt_base
{
public:
    virtual ~ntt_base() {}
    virtual void fwd(T *a, size_t logn, size_t stride) = 0;
    virtual void inv(T *a, size_t logn, size_t stride) = 0;

    virtual void mul(T* out, const T *x, const T *y, size_t stride) = 0;
    virtual void sqr(T* out, const T *x, size_t stride) = 0;
    virtual void negate(T* a, size_t stride) = 0;
    virtual bool inverse(T *a, size_t stride) = 0;
};

}  // namespace core
}  // namespace phantom

