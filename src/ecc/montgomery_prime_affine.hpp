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
 * @brief Montgomery prime point with affine coordinates.
 * 
 * All methods to manipulate a prime point for ECC double and add with
 * Montgomery curves using a affine coordinate system.
 */
template<typename T>
class montgomery_prime_affine : public prime_point<T>
{
protected:
    /// An elliptic curve montgomery_prime_affine coordinate
    const type_e m_type;
    size_t m_n;
    core::mpz<T> m_x;
    core::mpz<T> m_y;
    core::mpz<T> m_z;
    core::mpz<T> m_t;
    bool m_z_is_one;

    montgomery_prime_affine() : m_type(POINT_COORD_AFFINE) {}

public:
    montgomery_prime_affine(const prime_point<T>& obj) : m_type(POINT_COORD_AFFINE)  // NOLINT
    {
        m_n = obj.n();
        m_x = core::mpz<T>(obj.x());
        m_y = core::mpz<T>(obj.y());
        m_z = core::mpz<T>(obj.z());
        m_z_is_one = obj.z_is_one();
        m_t = core::mpz<T>(obj.t());
    }

    montgomery_prime_affine(const ecc_config<T>& config) : m_type(POINT_COORD_AFFINE)  // NOLINT
    {
        m_n = (config.bits + 7) >> 3;
        convert_to(config, core::mpz<T>(T(0)), core::mpz<T>(T(0)));
    }

    montgomery_prime_affine(const ecc_config<T>& config, const prime_point<T>& obj) : m_type(POINT_COORD_AFFINE)
    {
        m_n = obj.n();
        m_x = obj.x();
        m_y = obj.y();
        m_z = obj.z();
        m_z_is_one = obj.z_is_one();
        m_t = obj.t();
    }

    montgomery_prime_affine(const ecc_config<T>& config, const core::mpz<T>& x, const core::mpz<T>& y) :
        m_type(POINT_COORD_AFFINE)
    {
        convert_to(config, x, y);
        m_n = (m_z.get_limbsize() < m_y.get_limbsize())?
                    (m_y.get_limbsize() < m_z.get_limbsize())? m_z.get_limbsize() : m_y.get_limbsize() :
                    (m_z.get_limbsize() < m_z.get_limbsize())? m_z.get_limbsize() : m_z.get_limbsize();
    }

    virtual ~montgomery_prime_affine() {}

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
        const montgomery_prime_affine<T>& p = reinterpret_cast<const montgomery_prime_affine<T>&>(in);
        m_n = p.n();
        m_x = p.x();
        m_y = p.y();
        m_z = p.z();
        m_z_is_one = p.z_is_one();
        m_t = p.t();
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

        /*const core::mpz<T>& constant_a = dynamic_cast<const core::mpz<T>&>(*config.a.get());

        core::mpz<T> a, b, c;
        std::cout << "* x = " << m_x.get_str(16) << std::endl;
        a.set(m_x).square_mod(config.mod);
        b.set(m_x).mul_mod(a, config.mod);
        a.mul_mod(constant_a, config.mod);
        b.add_mod(a, config.mod).add_mod(m_x, config.mod);
        std::cout << "* y^2 = " << b.get_str(16) << std::endl;*/


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
        const core::mpz<T>& constant_a = dynamic_cast<const core::mpz<T>&>(*config.a.get());
        const core::mpz<T>& constant_b = dynamic_cast<const core::mpz<T>&>(*config.b.get());

#if 1
        do {
            if (y() == T(0)) {
                return POINT_INFINITY;
            }

            core::mpz<T> a, b, c, d, e, f;

            // lambda = 1 / (2.B.y1)
            core::mpz<T> lambda;
            a.set(m_y).add_mod(m_y, config.mod).mul_mod(constant_b, config.mod);
            if (!core::mpz<T>::invert(lambda, a, config.mod.mod)) {
                return POINT_ERROR;
            }

            b.set(m_x).square_mod(config.mod);
            a.set(b).add_mod(b, config.mod).add_mod(b, config.mod);  // 3.x^2
            b.set(constant_a).mul_mod(m_x, config.mod);  // A.x
            b.add_mod(b, config.mod);  // 2.A.x
            a.add_mod(b, config.mod).add_mod(T(1), config.mod);
            a.mul_mod(lambda, config.mod);  // (3.x^2 + 2.A.x + 1)/(2.B.y1)

            c.set(a).square_mod(config.mod);  // c = ((3.x^2 + 2.A.x + 1)/(2.B.y1))^2

            e.set(constant_b).mul_mod(c, config.mod);
            e.sub_mod(constant_a, config.mod).sub_mod(m_x, config.mod).sub_mod(m_x, config.mod);

            // f = (3*x^2 + 2*a*x + 1) * (1 / 2*b*y) * (x1 - x3) - y
            f.set(m_x).sub_mod(e, config.mod).mul_mod(a, config.mod).sub_mod(m_y, config.mod);

            m_x = e;
            m_y = f;
        } while (--w);
#else
        do {
            if (y() == T(0)) {
                return POINT_INFINITY;
            }

            core::mpz<T> a, b, c, d, e, f;

            a.set(m_x).square_mod(config.mod);
            b.set(constant_a).mul_mod(m_x, config.mod).add_mod(a, config.mod).add_mod(T(1), config.mod);
            b.mul_mod(m_x, config.mod);
            b.add_mod(b, config.mod);
            b.add_mod(b, config.mod);

            // lambda = 1 / 2by
            core::mpz<T> lambda;
            if (!core::mpz<T>::invert(lambda, b, config.mod.mod)) {
                return POINT_ERROR;
            }

            m_x.set(a).sub_mod(T(1), config.mod).square_mod(config.mod).mul_mod(lambda, config.mod);

            m_z_is_one = false;
        } while (--w);

        core::mpz<T> a, b, c;
        a.set(m_x).square_mod(config.mod);
        b.set(m_x).mul_mod(a, config.mod);
        a.mul_mod(constant_a, config.mod);
        b.add_mod(a, config.mod).add_mod(m_x, config.mod);
        m_y = b.sqrt_mod(config.mod);
#endif

        return POINT_OK;
    }

    retcode_e addition(const ecc_config<T>& config, const point<T>& rhs) override
    {
        const prime_point<T>& p_rhs = reinterpret_cast<const prime_point<T>&>(rhs);
        const core::mpz<T>& constant_a = dynamic_cast<const core::mpz<T>&>(*config.a.get());
        const core::mpz<T>& constant_b = dynamic_cast<const core::mpz<T>&>(*config.b.get());

        if (x() == p_rhs.x()) {
            if (y() != p_rhs.y()) {
                return POINT_INFINITY;
            }
            else {
                return doubling(config, 1);
            }
        }

        core::mpz<T> a, b, c, d, e, f;

        // lambda = 1 / (x2 - x1)
        core::mpz<T> lambda;
        if (!core::mpz<T>::invert(lambda, a.set(p_rhs.x()).sub_mod(m_x, config.mod), config.mod.mod)) {
            return POINT_ERROR;
        }

        a.set(p_rhs.y()).sub_mod(m_y, config.mod).mul_mod(lambda, config.mod);

        c.set(a).square_mod(config.mod);  // c = ((y2-y1)/(x2-x1))^2

        e.set(constant_b).mul_mod(c, config.mod);
        e.sub_mod(constant_a, config.mod).sub_mod(m_x, config.mod).sub_mod(p_rhs.x(), config.mod);

        // f = (3*x^2 + 2*a*x + 1) * (1 / 2*b*y) * (x1 - x3) - y
        f.set(m_x).sub_mod(e, config.mod).mul_mod(a, config.mod).sub_mod(m_y, config.mod);

        m_x = e;
        m_y = f;

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
