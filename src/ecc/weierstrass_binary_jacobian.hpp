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
 * @brief Weierstrass binary point with Jacobian coordinates.
 * 
 * All methods to manipulate a binary point for ECC double and add with
 * Weierstrass curves using a Jacobian coordinate system.
 */
template<typename T>
class weierstrass_binary_jacobian : public binary_point<T>
{
protected:
    /// An elliptic curve weierstrass_binary_jacobian coordinate
    const type_e m_type;
    size_t m_n;
    core::mp_gf2n<T> m_x;
    core::mp_gf2n<T> m_y;
    core::mp_gf2n<T> m_z;
    bool m_z_is_one;
    core::mp_gf2n<T> m_temp;

    weierstrass_binary_jacobian() : m_type(POINT_COORD_JACOBIAN) {}

public:
    weierstrass_binary_jacobian(const binary_point<T>& obj) : m_type(POINT_COORD_JACOBIAN)  // NOLINT
    {
        m_n    = obj.n();
        m_x    = core::mp_gf2n<T>(obj.x());
        m_y    = core::mp_gf2n<T>(obj.y());
        m_z    = core::mp_gf2n<T>(obj.z());
        m_z_is_one = obj.z_is_one();
    }

    weierstrass_binary_jacobian(const ecc_config<T>& config) : m_type(POINT_COORD_JACOBIAN)  // NOLINT
    {
        m_n = (config.bits + 7) >> 3;
        convert_to(config, core::mp_gf2n<T>(T(0)), core::mp_gf2n<T>(T(0)));
    }

    weierstrass_binary_jacobian(const ecc_config<T>& config, const weierstrass_binary_affine<T>& obj) :
        m_type(POINT_COORD_JACOBIAN)
    {
        m_n = obj.n();
        convert_to(config, obj.x(), obj.y());
    }

    weierstrass_binary_jacobian(const ecc_config<T>& config, const core::mp_gf2n<T>& x, const core::mp_gf2n<T>& y) :
        m_type(POINT_COORD_JACOBIAN)
    {
        convert_to(config, x, y);
        m_n = (m_z.get_limbsize() < m_y.get_limbsize())?
                    (m_y.get_limbsize() < m_z.get_limbsize())? m_z.get_limbsize() : m_y.get_limbsize() :
                    (m_z.get_limbsize() < m_z.get_limbsize())? m_z.get_limbsize() : m_z.get_limbsize();
    }

    ~weierstrass_binary_jacobian() {}

    type_e type() const override
    {
        return POINT_COORD_JACOBIAN;
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
        m_z = core::mp_gf2n<T>();
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
        m_y ^= m_x * m_z;
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

        // y = y/z*3
        mp_gf2n_x.set(inv_z).square();
        mp_gf2n_y.set(inv_z).mul(mp_gf2n_x).mul(m_y);

        // x = x/z*2
        mp_gf2n_x.mul(m_x);

        return POINT_OK;
    }

    retcode_e convert_to_mixed(const ecc_config<T>& config) override
    {
        core::mp_gf2n<T> inv_z, temp;
        if (!core::mp_gf2n<T>::invert(inv_z, m_z)) {
            return POINT_ERROR;
        }

        // y = y/z*3
        temp.set(inv_z).square();
        m_y.mul(temp).mul(inv_z);

        // x = x/z*2
        m_x.mul(temp);

        m_z = core::mp_gf2n<T>(T(1), config.mod.mod);
        m_z_is_one = true;

        return POINT_OK;
    }

    retcode_e doubling(const ecc_config<T>& config, size_t w) override
    {
        const core::mp_gf2n<T>& constant_b = dynamic_cast<const core::mp_gf2n<T>&>(*config.b.get());

        core::mp_gf2n<T> a(m_x), b(m_x), c(m_x), d(m_x);

        do {
            if (m_x == T(0)) {
                return POINT_INFINITY;
            }

            a.set(m_x).square();
            b.set(a).square();
            c.set(m_z).square();
            d.set(m_x).mul(c);

            if (config.b_is_1) {
                m_x.set(c).square().square().add(b);
            }
            else {
                m_x.set(c).square().square().mul(constant_b).add(b);
            }
            m_y.mul(m_z).add(a).add(d).mul(m_x).add(m_temp.set(b).mul(d));
            m_z.set(d);
            m_z_is_one = false;
        } while (--w);

        return POINT_OK;
    }

    retcode_e addition(const ecc_config<T>& config, const point<T>& rhs) override
    {
        const binary_point<T>& a_rhs = static_cast<const binary_point<T>&>(rhs);
        const core::mp_gf2n<T>& constant_a = dynamic_cast<const core::mp_gf2n<T>&>(*config.a.get());

        if (m_x == a_rhs.x()) {
            if (m_y == a_rhs.y()) {
                return doubling(config, 1);
            }
        }

        core::mp_gf2n<T> a(m_x), b(m_x), c(m_x), d(m_x), e(m_x), f(m_x), g(m_x), h(m_x), i(m_x);

        if (a_rhs.z_is_one()) {
            a.set(m_x);
            c.set(m_y);
        }
        else {
            a.set(a_rhs.z()).square();
            c.set(a).mul(m_y).mul(a_rhs.z());
            a.mul(m_x);
        }
        b.set(m_z).square();
        d.set(b).mul(m_z).mul(a_rhs.y());
        b.mul(a_rhs.x());
        e.set(a).add(b);
        f.set(c).add(d);
        g.set(e).mul(m_z);
        h.set(f).mul(a_rhs.x()).add(m_temp.set(g).mul(a_rhs.y()));
        if (a_rhs.z_is_one()) {
            m_z.set(g);
        }
        else {
            m_z.set(g).mul(a_rhs.z());
        }
        i.set(f).add(m_z);
        if (config.a_is_1) {
            m_x.set(m_z).square().add(f.mul(i)).add(m_temp.set(e).square().mul(e));
        }
        else if (config.a_is_zero) {
            m_x.set(f).mul(i).add(m_temp.set(e).square().mul(e));
        }
        else {
            m_x.set(m_z).square().mul(constant_a).add(f.mul(i)).add(m_temp.set(e).square().mul(e));
        }
        m_y.set(i).mul(m_x).add(g.square().mul(h));

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
