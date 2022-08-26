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
#include "core/bit_manipulation.hpp"
#include "core/template_helpers.hpp"
#include "ecc/prime_point.hpp"


namespace phantom {
namespace elliptic {

/** 
 * @brief Edwards prime point with projective coordinates.
 * 
 * All methods to manipulate a prime point for ECC double and add with
 * Edwards curves using a affine coordinate system.
 */
template<typename T>
class edwards_prime_affine : public prime_point<T>
{
protected:
    /// An elliptic curve edwards_prime_affine coordinate
    const type_e m_type;
    size_t m_n;
    core::mpz<T> m_x;
    core::mpz<T> m_y;
    core::mpz<T> m_z;
    core::mpz<T> m_t;
    bool m_z_is_one;

    edwards_prime_affine() : m_type(POINT_COORD_AFFINE) {}

public:
    edwards_prime_affine(const prime_point<T>& obj) : m_type(POINT_COORD_AFFINE)  // NOLINT
    {
        m_n = obj.n();
        m_x = core::mpz<T>(obj.x());
        m_y = core::mpz<T>(obj.y());
        m_z = core::mpz<T>(obj.z());
        m_z_is_one = obj.z_is_one();
        m_t = core::mpz<T>(obj.t());
    }

    edwards_prime_affine(const ecc_config<T>& config) : m_type(POINT_COORD_AFFINE)  // NOLINT
    {
        m_n = (config.bits + 7) >> 3;
        convert_to(config, core::mpz<T>(T(0)), core::mpz<T>(T(0)));
    }

    edwards_prime_affine(const ecc_config<T>& config, const prime_point<T>& obj) : m_type(POINT_COORD_AFFINE)
    {
        m_n = obj.n();
        m_x = obj.x();
        m_y = obj.y();
        m_z = obj.z();
        m_z_is_one = obj.z_is_one();
        m_t = obj.t();
    }

    edwards_prime_affine(const ecc_config<T>& config, const core::mpz<T>& x, const core::mpz<T>& y) :
        m_type(POINT_COORD_AFFINE)
    {
        convert_to(config, x, y);
        m_n = (m_z.get_limbsize() < m_y.get_limbsize())?
                    (m_y.get_limbsize() < m_z.get_limbsize())? m_z.get_limbsize() : m_y.get_limbsize() :
                    (m_z.get_limbsize() < m_z.get_limbsize())? m_z.get_limbsize() : m_z.get_limbsize();
    }

    virtual ~edwards_prime_affine() {}

    type_e type() const override
    {
        return POINT_COORD_AFFINE;
    }

    field_e field() const override
    {
        return MONTGOMERY_PRIME_FIELD;
    }

    void init(size_t bits) override
    {
        m_n = core::bit_manipulation::log2_ceil(bits);
        m_x = core::mpz<T>();
        m_y = core::mpz<T>();
        m_z = core::mpz<T>();
        m_t = core::mpz<T>();
    }

    void copy(const point<T>& in) override  // NOLINT
    {
        const edwards_prime_affine<T>& p = reinterpret_cast<const edwards_prime_affine<T>&>(in);
        m_n = p.n();
        m_x = p.x();
        m_y = p.y();
        m_z = p.z();
        m_z_is_one = p.z_is_one();
        m_t = p.t();
    }

    void negate(const ecc_config<T>& config) override
    {
        m_x.negate().add_mod(config.mod.mod, config.mod);
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

        m_t.set(m_x).mul_mod(m_y, config.mod);

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
        return POINT_OK;
    }

    retcode_e doubling(const ecc_config<T>& config, size_t w) override
    {
        core::mpz<T> a, b, c, d, e;

        a.set(m_x).square_mod(config.mod);
        b.set(m_y).square_mod(config.mod);
        c.set(a).add_mod(b, config.mod);

        // lambda_x = 1 / (x^2.y^2)
        core::mpz<T> lambda_x;
        if (!core::mpz<T>::invert(lambda_x, c, config.mod.mod)) {
            return POINT_ERROR;
        }

        m_x.mul_mod(m_y, config.mod);
        m_x.add_mod(m_x, config.mod);
        m_x.mul_mod(lambda_x, config.mod);

        c.set(T(2)).sub_mod(a, config.mod).sub_mod(b, config.mod);

        // lambda_y = 1 / (2 - x^2 - y^2)
        core::mpz<T> lambda_y;
        if (!core::mpz<T>::invert(lambda_y, c, config.mod.mod)) {
            return POINT_ERROR;
        }

        m_y.set(b).sub_mod(a, config.mod).mul_mod(lambda_y, config.mod);

        return POINT_OK;
    }

    retcode_e addition(const ecc_config<T>& config, const point<T>& rhs) override
    {
        const prime_point<T>& p_rhs = reinterpret_cast<const prime_point<T>&>(rhs);
        const core::mpz<T>& constant_d = dynamic_cast<const core::mpz<T>&>(*config.d.get());

        if (x() == p_rhs.x()) {
            if (y() != p_rhs.y()) {
                return POINT_INFINITY;
            }
            else {
                return doubling(config, 1);
            }
        }

        core::mpz<T> a, b, c, d, e;

        a.set(m_x).mul_mod(p_rhs.x(), config.mod);
        b.set(m_y).mul_mod(p_rhs.y(), config.mod);
        c.set(a).mul_mod(constant_d, config.mod).mul_mod(b, config.mod);

        // lambda_x = 1 / (1 + d.x1.x2.y1.y2)
        d.set(T(1)).add_mod(c, config.mod);
        core::mpz<T> lambda_x;
        if (!core::mpz<T>::invert(lambda_x, d, config.mod.mod)) {
            return POINT_ERROR;
        }

        m_x.mul_mod(p_rhs.y(), config.mod);
        e.set(p_rhs.x()).mul_mod(m_y, config.mod);
        m_x.add_mod(e, config.mod).mul_mod(lambda_x, config.mod);

        // lambda_y = 1 / (1 - d.x1.x2.y1.y2)
        d.set(T(1)).sub_mod(c, config.mod);
        core::mpz<T> lambda_y;
        if (!core::mpz<T>::invert(lambda_y, d, config.mod.mod)) {
            return POINT_ERROR;
        }

        m_y.set(b).sub_mod(a, config.mod).mul_mod(lambda_y, config.mod);

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
