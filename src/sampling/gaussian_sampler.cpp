/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "sampling/gaussian_sampler.hpp"
#include "sampling/gaussian_cdf.hpp"
#include <cmath>
#include <iostream>

namespace phantom {
namespace sampling {


gaussian_sampler::gaussian_sampler(std::shared_ptr<csprng> rng, uint16_t q,
    float base_sigma, size_t max_slevels, size_t log_base, size_t precision,
    size_t max_flips, float eta)
{
    long double t, s, base_sigma2;
    double inv_two_eta_2 = 1.0 / (2.0 * eta * eta);

    m_q            = q;
    m_prng         = rng;
    m_base_sampler = std::unique_ptr<gaussian<int32_t, uint64_t>>(
        new gaussian_cdf<int32_t, uint64_t>(m_prng, base_sigma, 10.0f));

    // Allocate memory for each of the wide noise samplers
    m_log_base = log_base;
    m_base_centre = std::vector<float>(1 << m_log_base);
    double step = 1.0 / pow(2, m_log_base);
    for (size_t i = 0; i < 1U << m_log_base; i++) {
        m_base_centre[i] = i * step;
    }

    // Build a recursive structure for the wide noise samplers
    gaussian<int32_t, uint64_t> *sampler = m_base_sampler.get();
    m_max_slevels = max_slevels;
    m_wide_sigma2 = static_cast<long double>(base_sigma) * static_cast<long double>(base_sigma);
    base_sigma2   = m_wide_sigma2;
    m_combiners = std::vector<std::unique_ptr<gaussian_combiner<int32_t, uint64_t>>>(m_max_slevels-1);
    for (size_t i = 0; i < m_max_slevels-1; i++) {
        int32_t z1, z2;
        z1 = static_cast<int32_t>(floor(sqrt(m_wide_sigma2 * inv_two_eta_2)));
        z2 = (z1 > 1)? z1 - 1 : 1;
        m_combiners[i] = std::unique_ptr<gaussian_combiner<int32_t, uint64_t>>(
            new gaussian_combiner<int32_t, uint64_t>(sampler, q, z1, z2, 0 == i));
        m_wide_sigma2 = (z1*z1 + z2*z2) * m_wide_sigma2;
        sampler       = m_combiners[i].get();
    }
    m_inv_wide_sigma2 = 1 / m_wide_sigma2;

    // Ensure that (precision - flips) is divisable by b by reducing the number of flips
    m_k     = static_cast<int32_t>(ceil(static_cast<double>(precision - max_flips) / m_log_base));
    m_flips = precision - m_log_base * m_k;
    m_mask  = (1UL << m_log_base) - 1;

    m_rr_sigma2 = 1;
    t = 1.0 / (1UL << (2*m_log_base));
    s = 1.0;
    for (size_t i = m_k-1; i--;) {
        s *= t;
        m_rr_sigma2 += s;
    }
    m_rr_sigma2 *= base_sigma2;
}

gaussian_sampler::~gaussian_sampler()
{
}

int32_t gaussian_sampler::sample(double sigma2, double centre)
{
    double x, c, ci;
    gaussian_combiner<int32_t, uint64_t> *combiner = m_combiners[m_max_slevels - 2].get();

    // Use the Gauss combiner network to obtain a sample
    x  = combiner->get_signed_sample();

    // Modify the sample according to the center position
    c  = centre + x*(sqrt((sigma2 - m_rr_sigma2) * m_inv_wide_sigma2));
    ci = floor(c);
    c -= ci;

    int32_t v = static_cast<int32_t>(c) + flip_and_round(c);

    // Return the centered sample (floored) added to the rounded
    // fractional difference
    return v;
}

int32_t gaussian_sampler::round(int64_t centre)
{
    for (size_t i=0; i < m_k; i++) {
        int32_t sample = m_base_centre[m_mask & centre] + m_base_sampler->get_signed_sample();
        if ((m_mask & centre) > 0 && centre < 0) {
            sample--;
        }
        for (size_t j=0; j < m_log_base; j++) {
            // Traditional division by 2, quotient rounded towards zero,
            // remainder same sign as dividend
            centre = (centre + ((centre >> 63) & 1)) >> 1;
        }
        centre += sample;
    }
    return centre;
}

int32_t gaussian_sampler::flip_and_round(double centre)
{
    int      i, j;
    size_t   precision = m_flips + m_log_base * m_k;
    int64_t  c         = static_cast<int64_t>((centre * (1UL << precision)));
    int64_t  base_c    = (c >> m_flips);
    int64_t  rbit;
    uint64_t rbits     = 0;
    int64_t  check;

    for (i = m_flips-1, j = 0U; i >= 0; i--, j++) {
        // Generate 64 random bits rather than sequentially generating
        // individual random bits
        j &= 0x3f;
        if (0 == j) {
            rbits = m_prng->get_u64();
        }

        // Obtain a random bit and remove it from the LSB of the random bit buffer
        rbit    = rbits & 0x1;
        rbits >>= 1;

        // If the indexed bit position of the scaled centre indicates
        // the correct rounding position then round towards zero
        check = (c >> i) & 1;
        if (rbit > check) {
            return round(base_c);
        }
        if (rbit < check) {
            return round(base_c + 1);
        }
    }
    return round(base_c + 1);
}

}  // namespace sampling
}  // namespace phantom
