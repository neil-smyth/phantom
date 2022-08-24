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
#include "ecc/weierstrass_prime_affine.hpp"


namespace phantom {
namespace elliptic {

/** 
 * @brief Weierstrass prime point with Jacobian coordinates.
 * 
 * All methods to manipulate a prime point for ECC double and add with
 * Weierstrass curves using a Jacobian coordinate system.
 */
template<typename T>
class weierstrass_prime_jacobian : public prime_point<T>
{
protected:
    /// An elliptic curve weierstrass_prime_jacobian coordinate
    const type_e m_type;
    size_t m_n;
    core::mpz<T> m_x;
    core::mpz<T> m_y;
    core::mpz<T> m_z;
    core::mpz<T> m_t;
    bool m_z_is_one;

    core::mpz<T> m_u1;
    core::mpz<T> m_u2;
    core::mpz<T> m_v1;
    core::mpz<T> m_v2;
    core::mpz<T> m_w;
    core::mpz<T> m_a;

    weierstrass_prime_jacobian() : m_type(POINT_COORD_JACOBIAN) {}

public:
    weierstrass_prime_jacobian(const prime_point<T>& obj) : m_type(POINT_COORD_JACOBIAN)  // NOLINT
    {
        m_n = obj.n();
        m_x = core::mpz<T>(obj.x());
        m_y = core::mpz<T>(obj.y());
        m_z = core::mpz<T>(obj.z());
        m_z_is_one = obj.z_is_one();
    }

    weierstrass_prime_jacobian(const ecc_config<T>& config) : m_type(POINT_COORD_JACOBIAN)  // NOLINT
    {
        m_n = (config.bits + 7) >> 3;
        convert_to(config, core::mpz<T>(T(0)), core::mpz<T>(T(0)));
    }

    weierstrass_prime_jacobian(const ecc_config<T>& config, const prime_point<T>& obj) : m_type(POINT_COORD_JACOBIAN)
    {
        m_n = obj.n();
        m_x = obj.x();
        m_y = obj.y();
        m_z = obj.z();
        m_z_is_one = obj.z_is_one();
    }

    weierstrass_prime_jacobian(const ecc_config<T>& config, const core::mpz<T>& x, const core::mpz<T>& y) :
        m_type(POINT_COORD_JACOBIAN)
    {
        convert_to(config, x, y);
        m_n = (m_z.get_limbsize() < m_y.get_limbsize())?
                    (m_y.get_limbsize() < m_z.get_limbsize())? m_z.get_limbsize() : m_y.get_limbsize() :
                    (m_z.get_limbsize() < m_z.get_limbsize())? m_z.get_limbsize() : m_z.get_limbsize();
    }

    ~weierstrass_prime_jacobian() {}

    type_e type() const override
    {
        return m_type;
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
        return m_x.is_zero() && m_y.is_zero() && m_z.is_zero();
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
        const core::mpz<T>* ref_x;
        const core::mpz<T>* ref_y;
        const core::mpz<T>* ref_z;
        core::mpz<T> temp_x, temp_y, temp_z;

        core::mpz<T>& mpz_x = reinterpret_cast<core::mpz<T>&>(*x);
        core::mpz<T>& mpz_y = reinterpret_cast<core::mpz<T>&>(*y);

        /*std::cout << "convert_from x = " << m_x.get_str(16) << std::endl;
        std::cout << "             y = " << m_y.get_str(16) << std::endl;
        std::cout << "             z = " << m_z.get_str(16) << std::endl;*/

        if (config.mod.reduction == core::REDUCTION_MONTGOMERY) {
            temp_x = m_x;
            temp_y = m_y;
            temp_z = m_z;
            temp_x.reduce_mont(config.mod);
            temp_y.reduce_mont(config.mod);
            temp_z.reduce_mont(config.mod);
            ref_x = &temp_x;
            ref_y = &temp_y;
            ref_z = &temp_z;
        }
        else {
            ref_x = &m_x;
            ref_y = &m_y;
            ref_z = &m_z;
        }

        core::mpz<T> inv_z, inv_z_2;
        if (!core::mpz<T>::invert(inv_z, *ref_z, config.mod.mod)) {
            return POINT_ERROR;
        }
        inv_z_2 = (inv_z * inv_z).mod(config.mod);

        // x = x/z
        mpz_x = (*ref_x * inv_z_2).mod(config.mod);

        // y = y/z
        mpz_y = (*ref_y * inv_z_2 * inv_z).mod(config.mod);

        /*std::cout << "convert_from x = " << mpz_x.get_str(16) << std::endl;
        std::cout << "             y = " << mpz_y.get_str(16) << std::endl;*/

        return POINT_OK;
    }

    retcode_e convert_to_mixed(const ecc_config<T>& config) override
    {
        const core::mpz<T>* ref_x;
        const core::mpz<T>* ref_y;
        const core::mpz<T>* ref_z;
        core::mpz<T> temp_x, temp_y, temp_z;

        if (config.mod.reduction == core::REDUCTION_MONTGOMERY) {
            temp_x = m_x;
            temp_y = m_y;
            temp_z = m_z;
            temp_x.mul_mont(T(1), config.mod);
            temp_y.mul_mont(T(1), config.mod);
            temp_z.mul_mont(T(1), config.mod);
            ref_x = &temp_x;
            ref_y = &temp_y;
            ref_z = &temp_z;
        }
        else {
            ref_x = &m_x;
            ref_y = &m_y;
            ref_z = &m_z;
        }

        core::mpz<T> inv_z, inv_z_2;
        if (!core::mpz<T>::invert(inv_z, *ref_z, config.mod.mod)) {
            return POINT_ERROR;
        }
        inv_z_2 = (inv_z * inv_z).mod(config.mod);

        // x = x/z
        m_x = (*ref_x * inv_z_2).mod(config.mod);

        // y = y/z
        m_y = (*ref_y * inv_z_2 * inv_z).mod(config.mod);

        m_z = core::mpz<T>(T(1));
        m_z_is_one = true;

        if (config.mod.reduction == core::REDUCTION_MONTGOMERY) {
            m_x.mul_mont(config.mod.mont_R2, config.mod);
            m_y.mul_mont(config.mod.mont_R2, config.mod);
            m_z.mul_mont(config.mod.mont_R2, config.mod);
        }

        return POINT_OK;
    }

    static weierstrass_prime_jacobian<T> decompression(const ecc_config<T>& config, const core::mpz<T>& x)
    {
        // lambda = (x^3 + ax + b)
        core::mpz<T> t = ((((x * x).mod(config.mod) * x).mod(config.mod) +
            (x * config.a).mod(config.mod)) + config.b);

        // yr = lambda*(xp - xr) - yp
        auto a = weierstrass_prime_affine<T>(config, x, t.sqrt().mod(config.mod));
        auto p = weierstrass_prime_jacobian<T>(config, a);

        return p;
    }

    retcode_e doubling(const ecc_config<T>& config, size_t w) override
    {
        const core::mpz<T>& constant_a = dynamic_cast<const core::mpz<T>&>(*config.a.get());

        core::mpz<T> a;

        do {
            if (y() == T(0)) {
                return POINT_INFINITY;
            }

            m_w.set(m_y).square_mod(config.mod);
            m_v1.set(m_w);
            m_v1.mul_mod(m_x, config.mod);
            m_v1.add_mod(m_v1, config.mod);
            m_v1.add_mod(m_v1, config.mod);

            if (config.a_is_minus_3) {
                m_u2.set(m_z).square_mod(config.mod);
                a.set(m_x).add_mod(m_u2, config.mod).mul_mod(m_x.sub_mod(m_u2, config.mod), config.mod);
                m_u1.set(a).add_mod(a, config.mod).add_mod(a, config.mod);
            }
            else {
                m_u2.set(m_z).square_mod(config.mod).square_mod(config.mod).mul_mod(constant_a, config.mod);
                a.set(m_x).square_mod(config.mod);
                m_u1.set(a).add_mod(a, config.mod).add_mod(a, config.mod).add_mod(m_u2, config.mod);
            }

            m_x.set(m_u1).square_mod(config.mod).sub_mod(m_v1, config.mod).sub_mod(m_v1, config.mod);

            m_z.mul_mod(m_y, config.mod);
            m_z.add_mod(m_z, config.mod);
            m_z_is_one = false;

            m_w.square_mod(config.mod);
            m_w.add_mod(m_w, config.mod);
            m_w.add_mod(m_w, config.mod);
            m_w.add_mod(m_w, config.mod);
            m_y.swap(m_v1.sub_mod(m_x, config.mod).mul_mod(m_u1, config.mod).sub_mod(m_w, config.mod));
        } while (--w);

        return POINT_OK;
    }

    retcode_e addition(const ecc_config<T>& config, const point<T>& rhs) override
    {
        const prime_point<T>& p_rhs = reinterpret_cast<const prime_point<T>&>(rhs);

        if (p_rhs.z_is_one()) {
            m_a.set(m_z).square_mod(config.mod);

            m_u1.set(m_x);
            m_v1.set(m_y);
        }
        else {
            m_w.set(p_rhs.z()).square_mod(config.mod);
            m_a.set(m_z).square_mod(config.mod);

            m_u1.set(m_x).mul_mod(m_w, config.mod);
            m_v1.set(m_y).mul_mod(m_w, config.mod).mul_mod(p_rhs.z(), config.mod);
        }
        m_u2.set(p_rhs.x()).mul_mod(m_a, config.mod);
        m_v2.set(p_rhs.y()).mul_mod(m_a, config.mod).mul_mod(m_z, config.mod);

        if (m_u1 == m_u2) {
            if (m_v1 != m_v2) {
                return POINT_INFINITY;
            }
            else {
                return doubling(config, 1);
            }
        }

        // H = u2 - u1, R = v2 - v1
        m_w.set(m_u2).sub_mod(m_u1, config.mod);
        m_a.set(m_v2).sub_mod(m_v1, config.mod);

        // z3 = H * z1 * z2
        if (p_rhs.z_is_one()) {
            m_z.mul_mod(m_w, config.mod);
        }
        else {
            m_z.mul_mod(m_w, config.mod).mul_mod(p_rhs.z(), config.mod);
        }

        // y3 = R
        m_y.set(m_a);

        // u2 = H^2
        m_u2.set(m_w).square_mod(config.mod);

        // R = R^2, v2 = R^3
        m_a.square_mod(config.mod);
        m_v2.set(m_a).mul_mod(m_y, config.mod);

        // x3 = R^2 - H^3 - 2*u1*H^2
        m_u1.mul_mod(m_u2, config.mod);
        m_x.set(m_a).sub_mod(core::mpz<T>::clone(m_w).mul_mod(m_u2, config.mod), config.mod)
            .sub_mod(m_u1, config.mod).sub_mod(m_u1, config.mod);

        // y3 = R*(u1*H^2 - x3) - s1*H^3
        m_u1.sub_mod(m_x, config.mod);
        m_y.mul_mod(m_u1, config.mod).sub_mod(m_u2.mul_mod(m_w, config.mod).mul_mod(m_v1, config.mod), config.mod);

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
