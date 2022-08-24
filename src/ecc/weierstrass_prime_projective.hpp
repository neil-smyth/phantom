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
 * @brief Weierstrass prime point with projective coordinates.
 * 
 * All methods to manipulate a prime point for ECC double and add with
 * Weierstrass curves using a projective coordinate system.
 */
template<typename T>
class weierstrass_prime_projective : public prime_point<T>
{
protected:
    /// An elliptic curve weierstrass_prime_projective coordinate
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

    weierstrass_prime_projective() : m_type(POINT_COORD_PROJECTIVE) {}

public:
    weierstrass_prime_projective(const prime_point<T>& obj) : m_type(POINT_COORD_PROJECTIVE)  // NOLINT
    {
        m_n = obj.n();
        m_x = core::mpz<T>(obj.x());
        m_y = core::mpz<T>(obj.y());
        m_z = core::mpz<T>(obj.z());
        m_z_is_one = obj.z_is_one();
    }

    weierstrass_prime_projective(const ecc_config<T>& config) : m_type(POINT_COORD_PROJECTIVE)  // NOLINT
    {
        m_n = (config.bits + 7) >> 3;
        convert_to(config, core::mpz<T>(T(0)), core::mpz<T>(T(0)));
    }

    weierstrass_prime_projective(const ecc_config<T>& config, const weierstrass_prime_affine<T>& obj) :
        m_type(POINT_COORD_PROJECTIVE)
    {
        m_n = obj.n();
        m_x = obj.x();
        m_y = obj.y();
        m_z = obj.z();
        m_z_is_one = obj.z_is_one();
    }

    weierstrass_prime_projective(const ecc_config<T>& config, const core::mpz<T>& x, const core::mpz<T>& y) :
        m_type(POINT_COORD_PROJECTIVE)
    {
        convert_to(config, x, y);
        m_n = (m_z.get_limbsize() < m_y.get_limbsize())?
                    (m_y.get_limbsize() < m_z.get_limbsize())? m_z.get_limbsize() : m_y.get_limbsize() :
                    (m_z.get_limbsize() < m_z.get_limbsize())? m_z.get_limbsize() : m_z.get_limbsize();
    }

    ~weierstrass_prime_projective() {}

    type_e type() const override
    {
        return POINT_COORD_PROJECTIVE;
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
        const weierstrass_prime_projective<T>& p = reinterpret_cast<const weierstrass_prime_projective<T>&>(in);
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

        core::mpz<T> inv_z;
        if (!core::mpz<T>::invert(inv_z, *ref_z, config.mod.mod)) {
            return POINT_ERROR;
        }

        // x = x/z
        mpz_x = (*ref_x * inv_z).mod(config.mod);

        // y = y/z
        mpz_y = (*ref_y * inv_z).mod(config.mod);

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

        core::mpz<T> inv_z;
        if (!core::mpz<T>::invert(inv_z, *ref_z, config.mod.mod)) {
            return POINT_ERROR;
        }

        // x = x/z
        m_x = (*ref_x * inv_z).mod(config.mod);

        // y = y/z
        m_y = (*ref_y * inv_z).mod(config.mod);

        m_z = core::mpz<T>(T(1));
        m_z_is_one = true;

        if (config.mod.reduction == core::REDUCTION_MONTGOMERY) {
            m_x.mul_mont(config.mod.mont_R2, config.mod);
            m_y.mul_mont(config.mod.mont_R2, config.mod);
            m_z.mul_mont(config.mod.mont_R2, config.mod);
        }

        return POINT_OK;
    }

    static weierstrass_prime_projective<T> decompression(const ecc_config<T>& config, const core::mpz<T>& x)
    {
        const core::mpz<T>& constant_a = dynamic_cast<const core::mpz<T>&>(*config.a.get());
        const core::mpz<T>& constant_b = dynamic_cast<const core::mpz<T>&>(*config.b.get());

        // lambda = (x^3 + ax + b)
        core::mpz<T> t = ((((x * x).reduce(config.mod) * x).reduce(config.mod) +
            (x * constant_a).reduce(config.mod)) + constant_b);

        // yr = lambda*(xp - xr) - yp
        auto a = weierstrass_prime_affine<T>(config, x, t.sqrt().reduce(config.mod));
        auto p = weierstrass_prime_projective<T>(config, a);

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

            // w = a * z^2 + 3 * x^2
            if (config.a_is_minus_3) {
                m_v2.set(m_x).square_mod(config.mod);
                m_w.set(m_z).square_mod(config.mod);
                m_w = m_v2.sub_mod(m_w, config.mod);
                m_w.add_mod(m_v2, config.mod).add_mod(m_v2, config.mod);
            }
            else {
                a.set(m_x).square_mod(config.mod);
                m_v2.set(a).add_mod(a, config.mod).add_mod(a, config.mod);
                m_w.set(m_z).square_mod(config.mod).mul_mod(constant_a, config.mod).add_mod(m_v2, config.mod);
            }

            // s = y * z
            m_u1.set(m_y).mul_mod(m_z, config.mod);

            // b = x * y * s
            m_u2.set(m_x).mul_mod(m_y, config.mod).mul_mod(m_u1, config.mod);

            // h = w^2 - 8 * b
            a.set(m_u2).add_mod(m_u2, config.mod);
            a.add_mod(a, config.mod);
            a.add_mod(a, config.mod);
            m_v1.set(m_w).square_mod(config.mod).sub_mod(a, config.mod);

            // x = 2 * h * s
            m_x.set(m_v1).mul_mod(m_u1, config.mod).add_mod(m_x, config.mod);

            // y = w*(4*b - h) - 8*y^2*s^2
            assert(!m_u2.is_negative());
            assert(!m_v1.is_negative());
            m_u2.add_mod(m_u2, config.mod).add_mod(m_u2, config.mod);
            m_u2.sub_mod(m_v1, config.mod);
            m_u2.mul_mod(m_w, config.mod);
            m_y.square_mod(config.mod).mul_mod(core::mpz<T>::clone(m_u1).square_mod(config.mod), config.mod);
            m_y.add_mod(m_y, config.mod).add_mod(m_y, config.mod).add_mod(m_y, config.mod);
            m_y.negate().add_mod(config.mod.mod, config.mod).add_mod(m_u2, config.mod);

            // z = 8 * s^3
            m_z.set(m_u1).pow_mod(3, config.mod);
            m_z.add_mod(m_z, config.mod);
            m_z.add_mod(m_z, config.mod);
            m_z.add_mod(m_z, config.mod);
            m_z_is_one = false;
        } while (--w);

        return POINT_OK;
    }

    retcode_e addition(const ecc_config<T>& config, const point<T>& rhs) override
    {
        const prime_point<T>& p_rhs = reinterpret_cast<const prime_point<T>&>(rhs);

        if (x() == p_rhs.x()) {
            if (y() != p_rhs.y()) {
                return POINT_INFINITY;
            }
            else {
                return doubling(config, 1);
            }
        }

        // u1 = b.y * a.z
        m_u1.set(p_rhs.y()).mul_mod(m_z, config.mod);

        // u2 = a.y * b.z
        m_u2.set(m_y);
        if (!p_rhs.z_is_one()) {
            m_u2.mul_mod(p_rhs.z(), config.mod);
        }

        // v1 = b.x * a.z
        m_v1.set(p_rhs.x()).mul_mod(m_z, config.mod);

        // v2 = a.x * b.z
        m_v2.set(m_x);
        if (!p_rhs.z_is_one()) {
            m_v2.mul_mod(p_rhs.z(), config.mod);
        }

        // u1 = u1 - u2
        m_u1.sub_mod(m_u2, config.mod);

        // v1 = v1 - v2
        m_v1.sub_mod(m_v2, config.mod);

        // w = v1^2
        m_w.set(m_v1).square_mod(config.mod);

        // v2 = w * v2 = v1*2 * v2
        m_v2.mul_mod(m_w, config.mod);

        // a = w * v1 = v1^3
        m_a.set(m_w).mul_mod(m_v1, config.mod);

        // w = a.z * b.z
        m_w.set(m_z);
        if (!p_rhs.z_is_one()) {
            m_w.mul_mod(p_rhs.z(), config.mod);
        }

        // z = w * v1^3 = a.z * b.z * v1*3
        m_z.set(m_w).mul_mod(m_a, config.mod);

        // y = a * u2 = v1^3 * u2
        m_y.set(m_u2).mul_mod(m_a, config.mod);

        // a = w * u1^2 - u2 = w * u1^2 - 2 * v2 - v1^3
        m_a = core::mpz<T>::clone(m_u1).square_mod(config.mod).mul_mod(m_w, config.mod)
            .sub_mod(m_v2, config.mod).sub_mod(m_v2, config.mod).sub_mod(m_a, config.mod);

        // x = v1 * a = v1 * (w * u1^2 - 2 * v2 - v1^3)
        m_x.set(m_v1).mul_mod(m_a, config.mod);

        // y = u1 * (v1*2 * v2 - a) - y
        m_y = m_v2.sub_mod(m_a, config.mod).mul_mod(m_u1, config.mod).sub_mod(m_y, config.mod);

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
