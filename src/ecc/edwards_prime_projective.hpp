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
 * Edwards curves using a projective coordinate system.
 */
template<typename T>
class edwards_prime_projective : public prime_point<T>
{
protected:
    /// An elliptic curve edwards_prime_projective coordinate
    const type_e m_type;
    size_t m_n;
    core::mpz<T> m_x;
    core::mpz<T> m_y;
    core::mpz<T> m_z;
    core::mpz<T> m_t;
    bool m_z_is_one;

    edwards_prime_projective() : m_type(POINT_COORD_PROJECTIVE) {}

public:
    edwards_prime_projective(const prime_point<T>& obj) : m_type(POINT_COORD_PROJECTIVE)  // NOLINT
    {
        m_n = obj.n();
        m_x = core::mpz<T>(obj.x());
        m_y = core::mpz<T>(obj.y());
        m_z = core::mpz<T>(obj.z());
        m_z_is_one = obj.z_is_one();
        m_t = core::mpz<T>(obj.t());
    }

    edwards_prime_projective(const ecc_config<T>& config) : m_type(POINT_COORD_PROJECTIVE)  // NOLINT
    {
        m_n = (config.bits + 7) >> 3;
        convert_to(config, core::mpz<T>(T(0)), core::mpz<T>(T(0)));
    }

    edwards_prime_projective(const ecc_config<T>& config, const prime_point<T>& obj) : m_type(POINT_COORD_PROJECTIVE)
    {
        m_n = obj.n();
        m_x = obj.x();
        m_y = obj.y();
        m_z = obj.z();
        m_z_is_one = obj.z_is_one();
        m_t = obj.t();
    }

    edwards_prime_projective(const ecc_config<T>& config, const core::mpz<T>& x, const core::mpz<T>& y) :
        m_type(POINT_COORD_PROJECTIVE)
    {
        convert_to(config, x, y);
        m_n = (m_z.get_limbsize() < m_y.get_limbsize())?
                    (m_y.get_limbsize() < m_z.get_limbsize())? m_z.get_limbsize() : m_y.get_limbsize() :
                    (m_z.get_limbsize() < m_z.get_limbsize())? m_z.get_limbsize() : m_z.get_limbsize();
    }

    virtual ~edwards_prime_projective() {}

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
        const edwards_prime_projective<T>& p = reinterpret_cast<const edwards_prime_projective<T>&>(in);
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

        return POINT_OK;
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
        const core::mpz<T>& constant_d = dynamic_cast<const core::mpz<T>&>(*config.d.get());

        core::mpz<T> a, b, c, d, e, f;

        do {
            a.set(m_x).mul_mod(m_y, config.mod);   // x.y
            b.set(m_z).square_mod(config.mod);     // z^2
            c.set(b).square_mod(config.mod);       // z^4
            d.set(constant_d).mul_mod(a, config.mod).mul_mod(a, config.mod);  // d.x^2.y^2
            e.set(c).sub_mod(d, config.mod);       // Z^4 - d.x^2.y^2
            f.set(c).add_mod(d, config.mod);       // Z^4 + d.x^2.y^2
            c.set(m_x).square_mod(config.mod);     // x^2

            m_x.set(a).add_mod(a, config.mod).mul_mod(b, config.mod).mul_mod(e, config.mod);
            m_y.square_mod(config.mod);
            if (config.a_is_minus_1) {
                m_y.add_mod(c, config.mod);
            }
            else {
                m_y.sub_mod(c, config.mod);
            }
            m_y.mul_mod(b, config.mod).mul_mod(f, config.mod);
            m_z.set(e).mul_mod(f, config.mod);
        } while (--w);

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

        core::mpz<T> a, b, c, d, e, f;

        a.set(m_x).mul_mod(p_rhs.y(), config.mod);   // x1.y2
        b.set(p_rhs.x()).mul_mod(m_y, config.mod);   // x2.y1
        c.set(m_z).mul_mod(p_rhs.z(), config.mod);   // z1.z2
        d.set(constant_d).mul_mod(a, config.mod).mul_mod(b, config.mod);   // d.x1.x2.y1.y2
        e.set(c).square_mod(config.mod);   // z1^2.z2^2
        f.set(e).add_mod(d, config.mod);   // z1^2.z2^2 + d.x1.x2.y1.y2
        e.sub_mod(d, config.mod);          // z1^2.z2^2 - d.x1.x2.y1.y2

        d.set(m_x).mul_mod(p_rhs.x(), config.mod);
        m_x.set(a).add_mod(b, config.mod).mul_mod(c, config.mod).mul_mod(e, config.mod);
        m_y.mul_mod(p_rhs.y(), config.mod);
        if (config.a_is_minus_1) {
            m_y.add_mod(d, config.mod);
        }
        else {
            m_y.sub_mod(d, config.mod);
        }
        m_y.mul_mod(c, config.mod).mul_mod(f, config.mod);
        m_z.set(e).mul_mod(f, config.mod);

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
