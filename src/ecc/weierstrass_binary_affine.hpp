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

#include "ecc/binary_point.hpp"
#include "core/mp_gf2n.hpp"
#include "core/bit_manipulation.hpp"
#include "core/template_helpers.hpp"


namespace phantom {
namespace elliptic {

/** 
 * @brief Weierstrass binary point with affine coordinates.
 * 
 * All methods to manipulate a binary point for ECC double and add with
 * Weierstrass curves using a affine coordinate system.
 */
template<typename T>
class weierstrass_binary_affine : public binary_point<T>
{
protected:
    /// An elliptic curve weierstrass_binary_affine coordinate
    const type_e m_type;
    size_t m_n;
    core::mp_gf2n<T> m_x;
    core::mp_gf2n<T> m_y;
    core::mp_gf2n<T> m_z;
    bool m_z_is_one;
    core::mp_gf2n<T> m_temp;

    weierstrass_binary_affine() : m_type(POINT_COORD_AFFINE) {}

public:
    weierstrass_binary_affine(const binary_point<T>& obj) : m_type(POINT_COORD_AFFINE)  // NOLINT
    {
        m_n    = obj.n();
        m_x    = core::mp_gf2n<T>(obj.x());
        m_y    = core::mp_gf2n<T>(obj.y());
        m_z    = core::mp_gf2n<T>(obj.z());
        m_z_is_one = obj.z_is_one();
    }

    weierstrass_binary_affine(const ecc_config<T>& config) : m_type(POINT_COORD_AFFINE)  // NOLINT
    {
        m_n = (config.bits + 7) >> 3;
        convert_to(config, core::mp_gf2n<T>(T(0)), core::mp_gf2n<T>(T(0)));
    }

    weierstrass_binary_affine(const ecc_config<T>& config, const core::mp_gf2n<T>& x, const core::mp_gf2n<T>& y) :
        m_type(POINT_COORD_AFFINE)
    {
        convert_to(config, x, y);
        m_n    = (m_x.get_limbsize() < m_y.get_limbsize())? m_y.get_limbsize() : m_x.get_limbsize();
    }

    virtual ~weierstrass_binary_affine() {}

    type_e type() const override
    {
        return POINT_COORD_AFFINE;
    }

    field_e field() const override
    {
        return WEIERSTRASS_BINARY_FIELD;
    }

    void init(size_t bits) override
    {
        m_n = core::bit_manipulation::log2_ceil(bits);
        m_x = core::mp_gf2n<T>();
        m_y = core::mp_gf2n<T>();
    }

    void copy(const point<T>& in) override  // NOLINT
    {
        const binary_point<T>& p = reinterpret_cast<const binary_point<T>&>(in);

        m_n = p.n();
        m_x = const_cast<core::mp_gf2n<T>&>(p.x());
        m_y = const_cast<core::mp_gf2n<T>&>(p.y());
        m_z = const_cast<core::mp_gf2n<T>&>(p.z());
        m_z_is_one = p.z_is_one();
    }

    void negate(const ecc_config<T>& config) override
    {
        (void) config;
        m_y ^= m_x;
    }

    bool is_zero() override
    {
        return m_x.is_zero() && m_y.is_zero();
    }

    retcode_e convert_to(const ecc_config<T>& config, const core::mp<T>& x, const core::mp<T>& y) override
    {
        const core::mp_gf2n<T>& mp_gf2n_x = reinterpret_cast<const core::mp_gf2n<T>&>(x);
        const core::mp_gf2n<T>& mp_gf2n_y = reinterpret_cast<const core::mp_gf2n<T>&>(y);

        m_x = mp_gf2n_x;
        m_y = mp_gf2n_y;
        m_z = core::mp_gf2n<T>(T(1), config.mod.mod);
        m_z_is_one = true;

        return POINT_OK;
    }

    retcode_e convert_from(const ecc_config<T>& config, core::mp<T>* x, core::mp<T>* y) const override
    {
        (void) config;

        core::mp_gf2n<T>& mp_gf2n_x = reinterpret_cast<core::mp_gf2n<T>&>(*x);
        core::mp_gf2n<T>& mp_gf2n_y = reinterpret_cast<core::mp_gf2n<T>&>(*y);

        mp_gf2n_x = m_x;
        mp_gf2n_y = m_y;

        return POINT_OK;
    }

    retcode_e convert_to_mixed(const ecc_config<T>& config) override
    {
        (void) config;
        return POINT_OK;
    }

    retcode_e doubling(const ecc_config<T>& config, size_t w) override
    {
        const core::mp_gf2n<T>& constant_a = dynamic_cast<const core::mp_gf2n<T>&>(*config.a.get());

        do {
            if (m_x == T(0)) {
                return POINT_INFINITY;
            }

            // lambda = x + y / x
            core::mp_gf2n<T> lambda;
            if (!core::mp_gf2n<T>::invert(lambda, m_x)) {
                return POINT_ERROR;
            }
            m_temp.set(m_x).mul(lambda);
            lambda = m_temp.set(m_y).mul(lambda).add(m_x);

            // xr = lambda^2 + lambda + a
            core::mp_gf2n<T> xr(m_x);
            xr.set(lambda).square().add(lambda).add(constant_a);

            // yr = x*2 + (s + 1)*xr
            lambda[0] = lambda[0] ^ 1;
            m_y.set(m_x).square().add(lambda.mul(xr));

            // Overwrite the input point X coordinate with it's new value
            m_x = xr;
        } while (--w);

        return POINT_OK;
    }

    retcode_e addition(const ecc_config<T>& config, const point<T>& rhs) override
    {
        const binary_point<T>& a_rhs = reinterpret_cast<const binary_point<T>&>(rhs);
        const core::mp_gf2n<T>& constant_a = dynamic_cast<const core::mp_gf2n<T>&>(*config.a.get());

        if (m_x == a_rhs.x()) {
            if (m_y == (a_rhs.x() + a_rhs.y())) {
                return POINT_INFINITY;
            }
            else if ((m_x+ m_y) == a_rhs.y()) {
                return doubling(config, 1);
            }
        }

        m_temp.set(a_rhs.x()).add(m_x);

        // lambda = (yb - ya) / (xb - xa)
        core::mp_gf2n<T> temp;
        if (!core::mp_gf2n<T>::invert(temp, m_temp)) {
            return POINT_ERROR;
        }
        core::mp_gf2n<T> lambda = m_temp.set(a_rhs.y()).add(m_y).mul(temp);

        // xr = lambda^2 + lambda + + xa + xb + a
        core::mp_gf2n<T> xr = m_temp.set(lambda).square().add(lambda).add(m_x).add(a_rhs.x()).add(constant_a);

        // yr = lambda*(xa - xr) - ya
        m_y = m_temp.set(m_x).add(xr).mul(lambda).add(xr).add(m_y);

        // Overwrite the input point X coordinate with it's new value
        m_x = xr;

        return POINT_OK;
    }

    core::mp_gf2n<T>& x() override { return m_x; }
    core::mp_gf2n<T>& y() override { return m_y; }
    core::mp_gf2n<T>& z() override { return m_z; }
    core::mp_gf2n<T>& x() const override { return const_cast<core::mp_gf2n<T>&>(m_x); }
    core::mp_gf2n<T>& y() const override { return const_cast<core::mp_gf2n<T>&>(m_y); }
    core::mp_gf2n<T>& z() const override { return const_cast<core::mp_gf2n<T>&>(m_z); }
    bool z_is_one() const override { return m_z_is_one; }
    size_t n() const override { return m_n; }
};

}  // namespace elliptic
}  // namespace phantom
