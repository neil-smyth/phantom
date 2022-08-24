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
#include <memory>
#include <vector>

#include "core/mpz.hpp"
#include "core/template_helpers.hpp"


namespace phantom {
namespace elliptic {

/// Common parameters used to define the ECC configuration
template<typename T>
struct ecc_config
{
    core::mod_config<T> mod;
    core::mpz<T> order_m;
    core::mpz<T> h;
    core::mpz<T> w;
    bool a_is_minus_3;
    bool a_is_minus_1;
    bool a_is_1;
    bool a_is_zero;
    bool b_is_1;
    std::shared_ptr<core::mp<T>> a;
    std::shared_ptr<core::mp<T>> b;
    std::shared_ptr<core::mp<T>> d;
    size_t bits;

    ecc_config() {}
    virtual ~ecc_config() {}

    /// Copy constructor
    ecc_config(const ecc_config& obj)
    {
        mod = obj.mod;
        order_m = obj.order_m;
        h = obj.h;
        w = obj.w;
        a_is_minus_3 = obj.a_is_minus_3;
        a_is_minus_1 = obj.a_is_minus_1;
        a_is_1 = obj.a_is_1;
        a_is_zero = obj.a_is_zero;
        b_is_1 = obj.b_is_1;
        a = std::shared_ptr<core::mp<T>>(obj.a);
        b = std::shared_ptr<core::mp<T>>(obj.b);
        d = std::shared_ptr<core::mp<T>>(obj.d);
        bits = obj.bits;
    }

    /// Move constructor
    ecc_config(ecc_config&& f)
    :   mod(f.mod),
        order_m(f.order_m),
        h(f.h),
        w(f.w),
        a_is_minus_3(f.a_is_minus_3),
        a_is_minus_1(f.a_is_minus_1),
        a_is_1(f.a_is_1),
        a_is_zero(f.a_is_zero),
        b_is_1(f.b_is_1),
        a(f.a),
        b(f.b),
        d(f.d),
        bits(f.bits)
    {
    }

    /// Operater override for "=" assignment
    ecc_config& operator=(ecc_config&& f)
    {
        mod = f.mod;
        order_m = f.order_m;
        h = f.h;
        w = f.w;
        a_is_minus_3 = f.a_is_minus_3;
        a_is_minus_1 = f.a_is_minus_1;
        a_is_1 = f.a_is_1;
        a_is_zero = f.a_is_zero;
        b_is_1 = f.b_is_1;
        a(f.a);
        b(f.b);
        d(f.d);
        bits = f.bits;
        return *this;
    }
};

/// Enumerated typefor the return code
enum retcode_e {
    POINT_OK = 0,
    POINT_ZERO,
    POINT_DOUBLE,
    POINT_INFINITY,
    POINT_ERROR,
    SECRET_IS_ZERO,
    RECODING_ERROR,
    SCALAR_MUL_ERROR,
};

/// Enumerated type for the point coordinate system
enum type_e {
    POINT_COORD_AFFINE = 0,
    POINT_COORD_PROJECTIVE,
    POINT_COORD_JACOBIAN,
    POINT_COORD_LOPEZ_DAHAB,
    POINT_COORD_CHUDNOVSKY,
    POINT_COORD_EXT_HOMOGENOUS,
};

/// Enumerated type for the field in use
enum field_e {
    WEIERSTRASS_PRIME_FIELD = 0,
    WEIERSTRASS_BINARY_FIELD,
    MONTGOMERY_PRIME_FIELD,
    EDWARDS_PRIME_FIELD,
};


/**
 * @brief Point interface for elliptic curves.
 * A pure virtual base class for elliptic curve points.
 * 
 * @tparam T Data type for multiple-precision arithmetic, typically the native machine word size
 */
template<typename T>
class point
{
public:
    virtual ~point() {}

    /// Getter for the point coordinate system
    virtual type_e type() const = 0;

    /// Getter for the field used
    virtual field_e field() const = 0;

    /// Initialize a point forthe given bit length
    virtual void init(size_t bits) = 0;

    /// Copy a point
    virtual void copy(const point& in) = 0;  // NOLINT

    /// Negate the point
    virtual void negate(const ecc_config<T>& config) = 0;

    /// Determine if the point is at the origin
    virtual bool is_zero() = 0;

    /// Convert multiple precision (x,y) Cartesian coordinates to a point
    virtual retcode_e convert_to(const ecc_config<T>& config, const core::mp<T>& x, const core::mp<T>& y) = 0;

    /// Convert a point to multiple precision (x,y) Cartesian coordinates
    virtual retcode_e convert_from(const ecc_config<T>& config, core::mp<T>* x, core::mp<T>* y) const = 0;

    /// Convert the point to mixed coordinates
    virtual retcode_e convert_to_mixed(const ecc_config<T>& config) = 0;

    /// Recover the y coordinate
    virtual void y_recovery(const ecc_config<T>& config, point<T>& p, point<T>& p_minus) {}

    /// Point doubling
    virtual retcode_e doubling(const ecc_config<T>& config, size_t w) = 0;

    /// Point addition
    virtual retcode_e addition(const ecc_config<T>& config, const point& rhs) = 0;

    /// Montgomery ladder step
    virtual retcode_e ladder_step(const ecc_config<T>& config, point* p_other, const point& p_base) = 0;

    /// Get methods for coordinates
    /// @{
    virtual core::mp<T>& x() = 0;
    virtual core::mp<T>& y() = 0;
    virtual core::mp<T>& z() = 0;
    virtual core::mp<T>& x() const = 0;
    virtual core::mp<T>& y() const = 0;
    virtual core::mp<T>& z() const = 0;
    virtual size_t n() const = 0;
    /// @}
};

}  // namespace elliptic
}  // namespace phantom
