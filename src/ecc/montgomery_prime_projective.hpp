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
#include "ecc/montgomery_prime_affine.hpp"


namespace phantom {
namespace elliptic {

/** 
 * @brief Montgomery prime point with projective coordinates.
 * 
 * All methods to manipulate a prime point for ECC double and add with
 * Montgomery curves using a projective coordinate system.
 */
template<typename T>
class montgomery_prime_projective : public prime_point<T>
{
protected:
    /// An elliptic curve montgomery_prime_projective coordinate
    const type_e m_type;
    size_t m_n;
    core::mpz<T> m_x;
    core::mpz<T> m_y;
    core::mpz<T> m_z;
    core::mpz<T> m_t;
    bool m_z_is_one;

    montgomery_prime_projective() : m_type(POINT_COORD_PROJECTIVE) {}

public:
    montgomery_prime_projective(const prime_point<T>& obj) : m_type(POINT_COORD_PROJECTIVE)  // NOLINT
    {
        m_n = obj.n();
        m_x = core::mpz<T>(obj.x());
        m_y = core::mpz<T>(obj.y());
        m_z = core::mpz<T>(obj.z());
        m_z_is_one = obj.z_is_one();
        m_t = core::mpz<T>(obj.t());
    }

    montgomery_prime_projective(const ecc_config<T>& config) : m_type(POINT_COORD_PROJECTIVE)  // NOLINT
    {
        m_n = (config.bits + 7) >> 3;
        convert_to(config, core::mpz<T>(T(0)), core::mpz<T>(T(0)));
    }

    montgomery_prime_projective(const ecc_config<T>& config, const prime_point<T>& obj) : m_type(POINT_COORD_PROJECTIVE)
    {
        m_n = obj.n();
        m_x = obj.x();
        m_y = obj.y();
        m_z = obj.z();
        m_z_is_one = obj.z_is_one();
        m_t = obj.t();
    }

    montgomery_prime_projective(const ecc_config<T>& config, const core::mpz<T>& x, const core::mpz<T>& y) :
        m_type(POINT_COORD_PROJECTIVE)
    {
        convert_to(config, x, y);
        m_n = (m_z.get_limbsize() < m_y.get_limbsize())?
                    (m_y.get_limbsize() < m_z.get_limbsize())? m_z.get_limbsize() : m_y.get_limbsize() :
                    (m_z.get_limbsize() < m_z.get_limbsize())? m_z.get_limbsize() : m_z.get_limbsize();
    }

    virtual ~montgomery_prime_projective() {}

    type_e type() const override
    {
        return POINT_COORD_PROJECTIVE;
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
        const montgomery_prime_projective<T>& p = reinterpret_cast<const montgomery_prime_projective<T>&>(in);
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

    void okeya_sakurai(const ecc_config<T>& config, const core::mpz<T>& x, const core::mpz<T>& y,
        core::mpz<T>& X1, core::mpz<T>& Y1, core::mpz<T>& Z1, const core::mpz<T>& X2, const core::mpz<T>& Z2)
    {
        const core::mpz<T>& constant_a = dynamic_cast<const core::mpz<T>&>(*config.a.get());
        const core::mpz<T>& constant_b = dynamic_cast<const core::mpz<T>&>(*config.b.get());

        core::mpz<T> t1, t2, t3, t4;

        t1.set(x).mul_mod(Z1, config.mod);
        t2.set(X1).add_mod(t1, config.mod);
        t3.set(X1).sub_mod(t1, config.mod).square_mod(config.mod).mul_mod(X2, config.mod);  // X2.(X1 - x.Z1)^2
        t1.set(constant_a).add_mod(constant_a, config.mod).mul_mod(Z1, config.mod);   // 2.A.Z1
        t2.add_mod(t1, config.mod);  // X1 + x.Z1 + 2.A.Z1
        t4.set(x).mul_mod(X1, config.mod).add_mod(Z1, config.mod);  // x.X1 + Z1
        t2.mul_mod(t4, config.mod);  // (X1 + x.Z1 + 2.A.Z1)(x.X1 + Z1)
        t1.mul_mod(Z1, config.mod);  // 2.A.Z1^2
        t2.sub_mod(t1, config.mod).mul_mod(Z2, config.mod);  // Z2[(X1 + x.Z1 + 2.A.Z1)(x.X1 + Z1) - 2.A.Z1^2]
        Y1.set(t2).sub_mod(t3, config.mod);
        t1.set(y).add_mod(y, config.mod)
            .mul_mod(Z1, config.mod)
            .mul_mod(Z2, config.mod);
        X1.mul_mod(t1, config.mod);
        Z1.mul_mod(t1, config.mod);
    }

    void y_recovery(const ecc_config<T>& config, point<T>& p, point<T>& p_minus) override
    {
        montgomery_prime_projective<T>& mont_p = reinterpret_cast<montgomery_prime_projective<T>&>(p);
        montgomery_prime_projective<T>& mont_p_minus = reinterpret_cast<montgomery_prime_projective<T>&>(p_minus);

        okeya_sakurai(config, mont_p.x(), mont_p.y(), m_x, m_y, m_z, mont_p_minus.x(), mont_p_minus.z());
    }

    retcode_e convert_from(const ecc_config<T>& config, core::mp<T>* x, core::mp<T>* y) const override
    {
        core::mpz<T>& mpz_x = reinterpret_cast<core::mpz<T>&>(*x);
        core::mpz<T>& mpz_y = reinterpret_cast<core::mpz<T>&>(*y);

        const core::mpz<T>* ref_x, *ref_y, *ref_z;
        core::mpz<T> temp_x, temp_y, temp_z;

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

        mpz_x = (*ref_x * inv_z).mod(config.mod);
        mpz_y = (*ref_y * inv_z).mod(config.mod);

        return POINT_OK;
    }

    retcode_e convert_to_mixed(const ecc_config<T>& config) override
    {
        return POINT_OK;
    }

    retcode_e doubling(const ecc_config<T>& config, size_t w) override
    {
        const core::mpz<T>& constant_a24 = dynamic_cast<const core::mpz<T>&>(*config.d.get());
        const core::mpz<T>& constant_b = dynamic_cast<const core::mpz<T>&>(*config.b.get());

        do {
            if (y() == T(0)) {
                return POINT_INFINITY;
            }

            core::mpz<T> a, b, c, d, e, f, g, h, t, u, v;

            a.set(m_x).add_mod(m_z, config.mod).square_mod(config.mod);
            b.set(m_x).sub_mod(m_z, config.mod).square_mod(config.mod);
            c.set(a).sub_mod(b, config.mod);

            m_x.set(a).mul_mod(b, config.mod);

            d.set(constant_a24).mul_mod(c, config.mod);
            m_z.set(b).add_mod(d, config.mod)
                .mul_mod(c, config.mod);

            m_z_is_one = false;
        } while (--w);

        return POINT_OK;
    }

    retcode_e addition(const ecc_config<T>& config, const point<T>& rhs) override
    {
        return POINT_OK;

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

        core::mpz<T> a, b, c, d;

        a.set(m_x).sub_mod(m_z, config.mod);
        b.set(p_rhs.x()).add_mod(p_rhs.z(), config.mod);
        c.set(m_x).add_mod(m_z, config.mod);
        d.set(p_rhs.x()).sub_mod(p_rhs.z(), config.mod);

        a.mul_mod(b, config.mod);
        c.mul_mod(d, config.mod);

        b.set(a).add_mod(c, config.mod).square_mod(config.mod);
        d.set(a).sub_mod(c, config.mod).square_mod(config.mod);

        a.set(p_rhs.z()).mul_mod(b, config.mod);
        b.set(p_rhs.x()).mul_mod(d, config.mod);

        m_x = a;
        m_z = b;

        return POINT_OK;
    }

    retcode_e ladder_step(const ecc_config<T>& config, point<T>* p_other, const point<T>& p_base) override
    {
        prime_point<T>& p_rhs = reinterpret_cast<prime_point<T>&>(*p_other);
        const prime_point<T>& p_g = reinterpret_cast<const prime_point<T>&>(p_base);
        const core::mpz<T>& constant_a24 = dynamic_cast<const core::mpz<T>&>(*config.d.get());
        const core::mpz<T>& constant_b = dynamic_cast<const core::mpz<T>&>(*config.b.get());

        if (x() == p_rhs.x()) {
            if (y() != p_rhs.y()) {
                return POINT_INFINITY;
            }
            else {
                return doubling(config, 1);
            }
        }

        core::mpz<T> a, b, c, d;

        a.set(m_x).sub_mod(m_z, config.mod);
        b.set(p_rhs.x()).add_mod(p_rhs.z(), config.mod);
        c.set(m_x).add_mod(m_z, config.mod);
        d.set(p_rhs.x()).sub_mod(p_rhs.z(), config.mod);

        a.mul_mod(b, config.mod);
        c.mul_mod(d, config.mod);

        b.set(a).add_mod(c, config.mod).square_mod(config.mod);
        d.set(a).sub_mod(c, config.mod).square_mod(config.mod);

        if (p_g.z_is_one()) {
            m_x.set(b);
        }
        else {
            m_x.set(p_g.z()).mul_mod(b, config.mod);
        }
        m_z.set(p_g.x()).mul_mod(d, config.mod);

        a.set(p_rhs.x()).add_mod(p_rhs.z(), config.mod).square_mod(config.mod);
        b.set(p_rhs.x()).sub_mod(p_rhs.z(), config.mod).square_mod(config.mod);
        c.set(a).sub_mod(b, config.mod);

        p_rhs.x().set(a).mul_mod(b, config.mod);

        d.set(constant_a24).mul_mod(c, config.mod);
        p_rhs.z().set(b).add_mod(d, config.mod).mul_mod(c, config.mod);

        m_z_is_one = false;

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
