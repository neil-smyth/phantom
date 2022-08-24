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

#include "core/mp_gf2n.hpp"
#include "ecc/point.hpp"
#include "core/template_helpers.hpp"


namespace phantom {
namespace elliptic {

/** 
 * @brief A binary point on an elliptic curve.
 * An abstract base class for binary elliptic curve coordinates.
 */
template<typename T>
class binary_point : public point<T>
{
    static_assert(std::is_same<T, uint8_t>::value  ||
                  std::is_same<T, uint16_t>::value ||
                  std::is_same<T, uint32_t>::value ||
                  std::is_same<T, uint64_t>::value,
                  "number instantiated with unsupported type");

public:
    virtual ~binary_point() {}

    /// Pure virtual methods for access to coordinates
    /// @{
    virtual core::mp_gf2n<T>& x() = 0;
    virtual core::mp_gf2n<T>& y() = 0;
    virtual core::mp_gf2n<T>& z() = 0;
    virtual core::mp_gf2n<T>& x() const = 0;
    virtual core::mp_gf2n<T>& y() const = 0;
    virtual core::mp_gf2n<T>& z() const = 0;

    virtual bool z_is_one() const = 0;
    /// @}

    /// A Montgomery ladder step
    virtual retcode_e ladder_step(const ecc_config<T>& config, point<T>* p_other, const point<T>& p_base)
    {
        return POINT_ERROR;
    }
};

}  // namespace elliptic
}  // namespace phantom
