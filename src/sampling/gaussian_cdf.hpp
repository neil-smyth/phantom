/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <cmath>
#include <iostream>
#include <iomanip>
#include <memory>
#include "sampling/gaussian.hpp"
#include "core/const_time.hpp"
#include "./phantom_memory.hpp"
#include "core/bit_manipulation.hpp"


#define LONGDOUBLE_M_2_SQRTPI  1.128379167095512573896158903121545172L
#define LONGDOUBLE_M_SQRT1_2   0.707106781186547524400844362104849039L


namespace phantom {
namespace sampling {

/**
 * @brief A concrete implementation of the gaussian base class to provide a Gauusian Cumulative Distribution Function
 * 
 * @tparam U Data type for samples (must be signed)
 * @tparam P Internal data type used for computation (must be unsigned)
 */
template<typename U, typename P>
class gaussian_cdf : public gaussian<U, P>
{
    using S = typename std::make_signed<U>::type;

public:
    gaussian_cdf(std::shared_ptr<csprng> rng, float sigma, float tail) :
        m_use_kl_divergence(false),
        m_k(0),
        m_rng(rng)
    {
        size_t bits = core::bit_manipulation::log2_ceil(static_cast<P>(tail * sigma));

        // Store the size of the distribution
        m_cdf_size = (1 << bits);

        // Allocate memory for the pre-computed Gaussian distribution
        m_cdf = phantom_vector<P>(m_cdf_size);

        // 2/sqrt(2*Pi) * (1 << 64) / sigma
        long double d = LONGDOUBLE_M_2_SQRTPI * LONGDOUBLE_M_SQRT1_2 * 18446744073709551616.0L / sigma;

        // Fill the distribution from 0 to maximum, ensuring that overflow
        // is taken into account
        long double e = -0.5L / (sigma * sigma);
        long double s = 0.5L * d;
        m_cdf[0] = 0;
        size_t i;
        long double j = 1, ej = e;
        for (i=1; i < m_cdf_size-1; i++) {
            m_cdf[i] = std::round(s);
            if (0 == m_cdf[i])        // overflow
                break;
            s += d * expl(ej * j++);
            if (m_cdf[i-1] > m_cdf[i]) {
                break;
            }
            ej += e;
        }
        for (; i < m_cdf_size; i++) {
            m_cdf[i] = ~static_cast<P>(0);
        }

        m_steps = 0;
        U st = m_cdf_size >> 1;
        while (st > 0) {
            m_steps++;
            st >>= 1;
        }
    }

    virtual ~gaussian_cdf() {}

    U get_signed_sample() override
    {
        P x = m_rng->get<P>();

        U a = binary_search(x, m_cdf.data(), m_cdf_size, m_steps);

        U sign = static_cast<U>(x) & 1;
        return const_time<U>::if_condition_is_true(sign, -a) +
               const_time<U>::if_condition_is_false(sign, a);
    }

    U get_unsigned_sample() override
    {
        P x = m_rng->get<P>();

        U a = binary_search(x, m_cdf.data(), m_cdf_size, m_steps);

        return a;
    }

private:
    static U binary_search(P x, const P *l, U n, const size_t steps)
    {
        // Given the table l of length n, return the address in the table
        // that satisfies the condition x >= l[b]

        U a  = 0;
        U st = n >> 1;

        for (size_t i=0; i < steps; i++) {
            U b = a + st;
            U c = static_cast<U>(const_time<P>::cmp_lessthan(l[b], x));
            a = const_time<U>::if_condition_is_true(c, b) +
                const_time<U>::if_condition_is_false(c, a);
            st >>= 1;
        }

        return a;
    }


    phantom_vector<P> m_cdf;
    size_t            m_cdf_size;
    size_t            m_steps;

    const bool        m_use_kl_divergence;  ///< Flag indicating Kullback-Leibler divergence is enabled
    const S           m_k;                  ///< Kullback-Leibler divergence constant
    const std::shared_ptr<csprng> m_rng;    ///< The CSPRNG used throughout phantom
};

}  // namespace sampling
}  // namespace phantom
