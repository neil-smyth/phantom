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
#include "ecc/weierstrass_binary_affine.hpp"
#include "core/mp_gf2n.hpp"
#include "core/bit_manipulation.hpp"
#include "core/template_helpers.hpp"


namespace phantom {
namespace elliptic {

/** 
 * @brief Weierstrass binary point with projective coordinates.
 * 
 * All methods to manipulate a binary point for ECC double and add with
 * Weierstrass curves using a projective coordinate system.
 */
template<typename T>
class weierstrass_binary_projective : public binary_point<T>
{
protected:
    /// An elliptic curve weierstrass_binary_projective coordinate
    const type_e m_type;
    size_t m_n;
    core::mp_gf2n<T> m_x;
    core::mp_gf2n<T> m_y;
    core::mp_gf2n<T> m_z;
    bool m_z_is_one;
    core::mp_gf2n<T> m_temp;

    weierstrass_binary_projective() : m_type(POINT_COORD_PROJECTIVE) {}

public:
    weierstrass_binary_projective(const binary_point<T>& obj) : m_type(POINT_COORD_PROJECTIVE)  // NOLINT
    {
        m_n    = obj.n();
        m_x    = core::mp_gf2n<T>(obj.x());
        m_y    = core::mp_gf2n<T>(obj.y());
        m_z    = core::mp_gf2n<T>(obj.z());
        m_z_is_one = obj.z_is_one();
    }

    weierstrass_binary_projective(const ecc_config<T>& config) : m_type(POINT_COORD_PROJECTIVE)  // NOLINT
    {
        m_n = (config.bits + 7) >> 3;
        convert_to(config, core::mp_gf2n<T>(T(0)), core::mp_gf2n<T>(T(0)));
    }

    weierstrass_binary_projective(const ecc_config<T>& config, const weierstrass_binary_affine<T>& obj) :
        m_type(POINT_COORD_PROJECTIVE)
    {
        m_n = obj.n();
        convert_to(config, obj.x(), obj.y());
    }

    weierstrass_binary_projective(const ecc_config<T>& config, const core::mp_gf2n<T>& x, const core::mp_gf2n<T>& y) :
        m_type(POINT_COORD_PROJECTIVE)
    {
        convert_to(config, x, y);
        m_n = (m_z.get_limbsize() < m_y.get_limbsize())?
                    (m_y.get_limbsize() < m_z.get_limbsize())? m_z.get_limbsize() : m_y.get_limbsize() :
                    (m_z.get_limbsize() < m_z.get_limbsize())? m_z.get_limbsize() : m_z.get_limbsize();
    }

    ~weierstrass_binary_projective() {}

    type_e type() const override
    {
        return POINT_COORD_PROJECTIVE;
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
        m_y ^= m_x;
    }

    bool is_zero() override
    {
        return m_x.is_zero() && m_y.is_zero() && m_z.is_zero();
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
        core::mp_gf2n<T>& mp_gf2n_x = reinterpret_cast<core::mp_gf2n<T>&>(*x);
        core::mp_gf2n<T>& mp_gf2n_y = reinterpret_cast<core::mp_gf2n<T>&>(*y);

        core::mp_gf2n<T> inv_z;
        if (!core::mp_gf2n<T>::invert(inv_z, m_z)) {
            return POINT_ERROR;
        }

        // x = x/z
        mp_gf2n_x = m_x * inv_z;

        // y = y/z
        mp_gf2n_y = m_y * inv_z;

        return POINT_OK;
    }

    retcode_e convert_to_mixed(const ecc_config<T>& config) override
    {
        core::mp_gf2n<T> inv_z;
        if (!core::mp_gf2n<T>::invert(inv_z, m_z)) {
            return POINT_ERROR;
        }

        // x = x/z
        m_x *= inv_z;

        // y = y/z
        m_y *= inv_z;

        m_z = core::mp_gf2n<T>(T(1), config.mod.mod);
        m_z_is_one = true;

        return POINT_OK;
    }

    retcode_e doubling(const ecc_config<T>& config, size_t w) override
    {
        const core::mp_gf2n<T>& constant_a = dynamic_cast<const core::mp_gf2n<T>&>(*config.a.get());

        core::mp_gf2n<T> a(m_x), b(m_x), c(m_x), d(m_x), e(m_x);

        do {
            if (m_x == T(0)) {
                return POINT_INFINITY;
            }

            a.set(m_x).square();
            b.set(a).add(m_temp.set(m_y).mul(m_z));
            c.set(m_x).mul(m_z);
            d.set(c).square();
            if (config.a_is_1) {
                e.set(b).square().add(m_temp.set(b).mul(c)).add(d);
            }
            else {
                e.set(b).square().add(m_temp.set(b).mul(c)).add(m_temp.set(constant_a).mul(d));
            }

            m_x.set(c).mul(e);
            m_y.set(b).add(c).mul(e).add(m_temp.set(a).square().mul(c));
            m_z.set(c).mul(d);
            m_z_is_one = false;
        } while (--w);

        return POINT_OK;
    }

    retcode_e addition(const ecc_config<T>& config, const point<T>& rhs) override
    {
        const binary_point<T>& a_rhs = static_cast<const binary_point<T>&>(rhs);

        if (m_x == a_rhs.x()) {
            if (m_y == a_rhs.y()) {
                return doubling(config, 1);
            }
        }

        core::mp_gf2n<T> a(m_x), b(m_x), c(m_x), d(m_x), e(m_x);

        if (a_rhs.z_is_one()) {
            a.set(m_y).add(m_temp.set(m_z).mul(a_rhs.y()));
            b.set(m_x).add(m_temp.set(m_z).mul(a_rhs.x()));
            d.set(m_z);
        }
        else {
            a.set(m_y).mul(a_rhs.z()).add(m_temp.set(m_z).mul(a_rhs.y()));
            b.set(m_x).mul(a_rhs.z()).add(m_temp.set(m_z).mul(a_rhs.x()));
            d.set(m_z).mul(a_rhs.z());
        }
        c.set(b).square();
        if (config.a_is_1) {
            e.set(a).square().add(m_temp.set(a).mul(b)).add(c).mul(d).add(m_temp.set(b).mul(c));
        }
        else {
            const core::mp_gf2n<T>& constant_a = dynamic_cast<const core::mp_gf2n<T>&>(*config.a.get());
            e.set(a).square().add(m_temp.set(a).mul(b)).add(m_temp.set(constant_a).mul(c))
                .mul(d).add(m_temp.set(b).mul(c));
        }

        if (a_rhs.z_is_one()) {
            m_y.mul(b).add(m_temp.set(a).mul(m_x)).mul(c).add(m_temp.set(a).add(b).mul(e));
        }
        else {
            m_y.mul(b).add(m_temp.set(a).mul(m_x)).mul(c).mul(a_rhs.z()).add(m_temp.set(a).add(b).mul(e));
        }
        m_x.set(b).mul(e);
        m_z.set(b).mul(c).mul(d);

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
