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

#include "ecc/prime_point.hpp"
#include "core/mpz.hpp"
#include "core/bit_manipulation.hpp"
#include "core/template_helpers.hpp"


namespace phantom {
namespace elliptic {

/** 
 * @brief Weierstrass prime point with affine coordinates.
 * 
 * All methods to manipulate a prime point for ECC double and add with
 * Weierstrass curves using a affine coordinate system.
 */
template<typename T>
class weierstrass_prime_affine : public prime_point<T>
{
protected:
    /// An elliptic curve weierstrass_prime_affine coordinate
    const type_e m_type;
    size_t m_n;
    core::mpz<T> m_x;
    core::mpz<T> m_y;
    core::mpz<T> m_z;
    core::mpz<T> m_t;
    bool m_z_is_one;
    core::mpz<T> m_temp;

    weierstrass_prime_affine() : m_type(POINT_COORD_AFFINE) {}

public:
    weierstrass_prime_affine(const prime_point<T>& obj) : m_type(POINT_COORD_AFFINE)  // NOLINT
    {
        m_n    = obj.n();
        m_x    = core::mpz<T>(obj.x());
        m_y    = core::mpz<T>(obj.y());
        m_z    = core::mpz<T>(obj.z());
        m_z_is_one = obj.z_is_one();
    }

    weierstrass_prime_affine(const ecc_config<T>& config) : m_type(POINT_COORD_AFFINE)  // NOLINT
    {
        m_n = (config.bits + 7) >> 3;
        convert_to(config, core::mpz<T>(T(0)), core::mpz<T>(T(0)));
    }

    weierstrass_prime_affine(const ecc_config<T>& config, const core::mpz<T>& x, const core::mpz<T>& y) :
        m_type(POINT_COORD_AFFINE)
    {
        convert_to(config, x, y);
        m_n    = (m_x.get_limbsize() < m_y.get_limbsize())? m_y.get_limbsize() : m_x.get_limbsize();
    }

    ~weierstrass_prime_affine() {}

    type_e type() const override
    {
        return POINT_COORD_AFFINE;
    }

    field_e field() const override
    {
        return WEIERSTRASS_PRIME_FIELD;
    }

    void init(size_t bits) override
    {
        m_n = core::bit_manipulation::log2_ceil(bits);
        m_x = core::mpz<T>();
        m_y = core::mpz<T>();
        m_z = core::mpz<T>();
    }

    void copy(const point<T>& in) override  // NOLINT
    {
        const prime_point<T>& p = reinterpret_cast<const prime_point<T>&>(in);

        m_n = p.n();
        m_x = p.x();
        m_y = p.y();
        m_z = p.z();
        m_z_is_one = p.z_is_one();
    }

    void negate(const ecc_config<T>& config) override
    {
        m_y.negate().add_mod(config.mod.mod, config.mod);
    }

    bool is_zero() override
    {
        return m_x.is_zero() && m_y.is_zero();
    }

    retcode_e convert_to(const ecc_config<T>& config, const core::mp<T>& x, const core::mp<T>& y) override
    {
        const core::mpz<T>& mpz_x = reinterpret_cast<const core::mpz<T>&>(x);
        const core::mpz<T>& mpz_y = reinterpret_cast<const core::mpz<T>&>(y);

        m_x = mpz_x;
        m_y = mpz_y;
        m_z = core::mpz<T>(T(1));
        m_z_is_one = true;
        m_x.mod_positive(config.mod);
        m_y.mod_positive(config.mod);

        if (config.mod.reduction == core::REDUCTION_MONTGOMERY) {
            m_x.mul_mont(config.mod.mont_R2, config.mod);
            m_y.mul_mont(config.mod.mont_R2, config.mod);
            m_z.mul_mont(config.mod.mont_R2, config.mod);
        }

        return POINT_OK;
    }

    retcode_e convert_from(const ecc_config<T>& config, core::mp<T>* x, core::mp<T>* y) const override
    {
        core::mpz<T>& mpz_x = reinterpret_cast<core::mpz<T>&>(*x);
        core::mpz<T>& mpz_y = reinterpret_cast<core::mpz<T>&>(*y);

        const core::mpz<T>* ref_x;
        const core::mpz<T>* ref_y;
        core::mpz<T> temp_x, temp_y;

        if (config.mod.reduction == core::REDUCTION_MONTGOMERY) {
            temp_x = m_x;
            temp_y = m_y;
            temp_x.reduce_mont(config.mod);
            temp_y.reduce_mont(config.mod);
            ref_x = &temp_x;
            ref_y = &temp_y;
        }
        else {
            ref_x = &m_x;
            ref_y = &m_y;
        }

        mpz_x = *ref_x;
        mpz_y = *ref_y;

        return POINT_OK;
    }

    retcode_e convert_to_mixed(const ecc_config<T>& config) override
    {
        (void) config;
        return POINT_OK;
    }

    static weierstrass_prime_affine<T> decompression(const ecc_config<T>& config, const core::mpz<T>& x)
    {
        const core::mpz<T>& constant_a = dynamic_cast<const core::mpz<T>&>(*config.a.get());
        const core::mpz<T>& constant_b = dynamic_cast<const core::mpz<T>&>(*config.b.get());

        // lambda = (x^3 + ax + b)
        core::mpz<T> t = ((((x * x).reduce(config.mod) * x).reduce(config.mod) +
            (x * constant_a).reduce(config.mod)) + constant_b);

        // yr = lambda*(xp - xr) - yp
        auto a = weierstrass_prime_affine<T>(config, x, t.sqrt().reduce(config.mod));

        return a;
    }

    retcode_e doubling(const ecc_config<T>& config, size_t w) override
    {
        const core::mpz<T>& constant_a = dynamic_cast<const core::mpz<T>&>(*config.a.get());

        do {
            if (m_y == T(0)) {
                return POINT_INFINITY;
            }

            // lambda = (3x^2 + a) / 2y
            core::mpz<T> lambda;
            if (!core::mpz<T>::invert(lambda, m_temp.set(m_y).add_mod(m_y, config.mod), config.mod.mod)) {
                return POINT_ERROR;
            }

            core::mpz<T> x_2;
            x_2.set(m_x).square_mod(config.mod);
            m_temp.set(x_2).add_mod(x_2, config.mod).add_mod(x_2, config.mod);
            lambda = m_temp.add_mod(constant_a, config.mod).mul_mod(lambda, config.mod);

            // xr = lambda^2 - 2*x
            core::mpz<T> xr = lambda;
            xr.square_mod(config.mod).sub_mod(m_temp.set(m_x).add_mod(m_x, config.mod), config.mod);

            // yr = -lambda*(xr - x) - y
            m_temp.set(xr).sub_mod(m_x, config.mod).mul_mod(lambda, config.mod).negate().sub_mod(m_y, config.mod);
            m_y.swap(m_temp);

            // Overwrite the input point X coordinate with it's new value
            m_x.swap(xr);
        } while (--w);

        return POINT_OK;
    }

    retcode_e addition(const ecc_config<T>& config, const point<T>& rhs) override
    {
        const prime_point<T>& a_rhs = reinterpret_cast<const prime_point<T>&>(rhs);

        if (m_x == a_rhs.x()) {
            if (m_y != a_rhs.y()) {
                return POINT_INFINITY;
            }
            else {
                return doubling(config, 1);
            }
        }

        // lambda = (yb - ya) / (xb - xa)
        core::mpz<T> temp;
        if (!core::mpz<T>::invert(temp, m_temp.set(a_rhs.x()).sub_mod(m_x, config.mod), config.mod.mod)) {
            return POINT_ERROR;
        }
        core::mpz<T> lambda = m_temp.set(a_rhs.y()).sub_mod(m_y, config.mod).mul_mod(temp, config.mod);

        // xr = lambda^2 - xa - xb
        core::mpz<T> xr =
            m_temp.set(lambda).square_mod(config.mod).sub_mod(m_x, config.mod).sub_mod(a_rhs.x(), config.mod);

        // yr = lambda*(xa - xr) - ya
        m_y.swap(m_temp.set(m_x).sub_mod(xr, config.mod).mul_mod(lambda, config.mod).sub_mod(m_y, config.mod));

        // Overwrite the input point X coordinate with it's new value
        m_x.swap(xr);

        return POINT_OK;
    }

    core::mpz<T>& x() override { return m_x; }
    core::mpz<T>& y() override { return m_y; }
    core::mpz<T>& z() override { return m_z; }
    core::mpz<T>& t() override { return m_t; }
    core::mpz<T>& x() const override { return const_cast<core::mpz<T>&>(m_x); }
    core::mpz<T>& y() const override { return const_cast<core::mpz<T>&>(m_y); }
    core::mpz<T>& z() const override { return const_cast<core::mpz<T>&>(m_z); }
    core::mpz<T>& t() const override { return const_cast<core::mpz<T>&>(m_t); }
    bool z_is_one() const override { return m_z_is_one; }
    size_t n() const override { return m_n; }
};

}  // namespace elliptic
}  // namespace phantom
