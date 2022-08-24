/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <cstdint>
#include <cmath>
#include <iomanip>
#include <limits>
#include <vector>

#include "core/mpz.hpp"
#include "ecc/point.hpp"
#include "core/template_helpers.hpp"


namespace phantom {
namespace elliptic {

/** 
 * @brief A prime point on an elliptic curve
 * 
 * A base class for prime elliptic curve coordinates
 */
template<typename T>
class prime_point : public point<T>
{
    static_assert(std::is_same<T, uint8_t>::value  ||
                  std::is_same<T, uint16_t>::value ||
                  std::is_same<T, uint32_t>::value ||
                  std::is_same<T, uint64_t>::value,
                  "number instantiated with unsupported type");

    public:
        virtual ~prime_point() {}

        virtual core::mpz<T>& x() = 0;
        virtual core::mpz<T>& y() = 0;
        virtual core::mpz<T>& z() = 0;
        virtual core::mpz<T>& t() = 0;
        virtual core::mpz<T>& x() const = 0;
        virtual core::mpz<T>& y() const = 0;
        virtual core::mpz<T>& z() const = 0;
        virtual core::mpz<T>& t() const = 0;

        virtual retcode_e ladder_step(const ecc_config<T>& config, point<T>* p_other, const point<T>& p_base)
        {
            return POINT_ERROR;
        }

        virtual bool z_is_one() const = 0;
};

// Forward declaration of common sizes
extern template class prime_point<uint8_t>;
extern template class prime_point<uint16_t>;
extern template class prime_point<uint32_t>;
extern template class prime_point<uint64_t>;

}  // namespace elliptic
}  // namespace phantom
