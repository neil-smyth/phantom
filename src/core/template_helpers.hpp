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
#include <cmath>
#include <limits>
#include <vector>
#include "./phantom_types.hpp"


namespace phantom {
namespace core {


/// A template method to swap pointers
template <typename T>
void swap_ptrs(T *x, T *y)
{
    T *tmp = x;
    x = y;
    y = tmp;
}

/// A template class which defines a data type equivalent to the template argument data type
template <class T> struct tag { using type = T; };


/// @defgroup half_type_template Template struct's used to define a half-word size
/// @{

/// Template class used to define an unsigned type of half the bit width
template <class > struct half_size;

/// A templated data type defined using the half_size data type
template <class T> using half_size_t = typename half_size<T>::type;

/// A specialized template class that defines half the data size of a uint8_t as a uint8_t
template <> struct half_size<uint8_t> : tag<uint8_t> { };

/// A specialized template class that defines half the data size of a uint16_t as a uint8_t
template <> struct half_size<uint16_t> : tag<uint8_t> { };

/// A specialized template class that defines half the data size of a uint32_t as a uint16_t
template <> struct half_size<uint32_t> : tag<uint16_t> { };

/// A specialized template class that defines half the data size of a uint64_t as a uint32_t
template <> struct half_size<uint64_t> : tag<uint32_t> { };

/// @}


/// @defgroup double_type_template Template struct's used to define a double-word size
/// @{

/// Template class used to define an unsigned type of twice the bit width
template <class > struct next_size;

/// A templated data type defined using the next_size data type
template <class T> using next_size_t = typename next_size<T>::type;

/// A specialized template class that defines twice the data size of a uint8_t as a uint16_t
template <> struct next_size<uint8_t>  : tag<uint16_t> { };

/// A specialized template class that defines twice the data size of a uint16_t as a uint32_t
template <> struct next_size<uint16_t> : tag<uint32_t> { };

/// A specialized template class that defines twice the data size of a uint32_t as a uint64_t
template <> struct next_size<uint32_t> : tag<uint64_t> { };

#if defined(__SIZEOF_INT128__)
/// A specialized template class that defines twice the data size of a uint64_t as a uint128_t
template <> struct next_size<uint64_t> : tag<uint128_t> { };
#else
template <> struct next_size<uint64_t> : tag<uint64_t> { };
#endif
/// @}


/// @defgroup signed_type_template Template struct's used to define an equivalent bit-length signed type
/// @{

/// Template class used to define a signed type equivalent of an unsigned type
template <class > struct signed_type;

/// A templated data type defined using the signed_type data type
template <class T> using signed_type_t = typename signed_type<T>::type;

/// A specialized template class that defines a signed data type of a uint8_t as a int8_t
template <> struct signed_type<uint8_t>   : tag<int8_t> { };

/// A specialized template class that defines a signed data type of a uint16_t as a int16_t
template <> struct signed_type<uint16_t>  : tag<int16_t> { };

/// A specialized template class that defines a signed data type of a uint32_t as a int32_t
template <> struct signed_type<uint32_t>  : tag<int32_t> { };

/// A specialized template class that defines a signed data type of a uint64_t as a int64_t
template <> struct signed_type<uint64_t>  : tag<int64_t> { };

#if defined(__SIZEOF_INT128__)
/// A specialized template class that defines a signed data type of a uint128_t as a int128_t
template <> struct signed_type<uint128_t> : tag<int128_t> { };
#endif
/// @}


/// @defgroup log2_template A templated log base-2 class for commonly used unsigned types
/// @{

/// Template for log2 (unused)
template<class Item>
class bits_log2 {
public:
    static constexpr Item log2() { return 1; }
};

#if defined(__SIZEOF_INT128__)
/// Template specialization for unsigned 128-bit log2
template<> class bits_log2<uint128_t> {
public:
    static constexpr uint128_t value() { return 7; }
};
#endif

/// Template specialization for unsigned 64-bit log2
template<> class bits_log2<uint64_t> {
public:
    static constexpr uint64_t value() { return 6; }
};

/// Template specialization for unsigned 32-bit log2
template<> class bits_log2<uint32_t> {
public:
    static constexpr uint32_t value() { return 5; }
};

/// Template specialization for unsigned 16-bit log2
template<> class bits_log2<uint16_t> {
public:
    static constexpr uint16_t value() { return 4; }
};

/// Template specialization for unsigned 8-bit log2
template<> class bits_log2<uint8_t> {
public:
    static constexpr uint8_t value() { return 3; }
};

///@}

}  // namespace core
}  // namespace phantom
