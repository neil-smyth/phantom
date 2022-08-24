/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include "sampling/gaussian.hpp"
#include <limits>
#include <memory>
#include <vector>


namespace phantom {
namespace sampling {

/**
 * @brief A Gaussian sampler node that provides signed/unsigned samples
 * 
 * @tparam T Data type for samples (must be signed)
 * @tparam P Internal data type used for computation (must be unsigned)
 */
template<typename T, typename P>
class gaussian_combiner : public gaussian<T, P>
{
public:
    /// Create a single level of a Gauss combiner, with the base sampler at
    /// the bottom of the network of combiners
    gaussian_combiner(gaussian<T, P> *gauss, T q, T z1, T z2, bool is_base)
    {
        // Set all of the configuration parameters associated with this combiner
        m_gauss   = gauss;
        m_q       = q;
        m_z1      = z1;
        m_z2      = z2;
        m_is_base = is_base;
    }

    /// Free all resources associated with a Gauss combiner
    virtual ~gaussian_combiner()
    {
    }

    // A recursive function used to create a sample from a base sampler
    T get_signed_sample() override
    {
        T x = m_z1 * m_gauss->get_signed_sample() + m_z2 * m_gauss->get_signed_sample();
        return x;
    }

    // A recursive function used to create a sample from a base sampler
    T get_unsigned_sample() override
    {
        T x = m_z1 * m_gauss->get_unsigned_sample() + m_z2 * m_gauss->get_unsigned_sample();
        return x;
    }

private:
    gaussian<T, P> *m_gauss;
    T               m_q;
    T               m_z1;
    T               m_z2;
    bool            m_is_base;
};


/**
 * @brief A class to provide a Gaussian random sampler
 * 
 * Composed of a network of gaussian_combiner objects
 */
class gaussian_sampler
{
public:
    /// The create function associated with the M&W bootstrap Gaussian sampler
    gaussian_sampler(std::shared_ptr<csprng> rng, uint16_t q, float base_sigma,
        size_t max_slevels, size_t log_base, size_t precision,
        size_t max_flips, float eta);

    ~gaussian_sampler();

    int32_t sample(double sigma2, double centre);

private:
    // Round a sample generated at the base sigma and the specified center
    int32_t round(int64_t centre);

    /// Round centre up or down depending on biased coin flip
    int32_t flip_and_round(double centre);

    std::shared_ptr<csprng> m_prng;
    std::vector<std::unique_ptr<gaussian_combiner<int32_t, uint64_t>>> m_combiners;
    std::unique_ptr<gaussian<int32_t, uint64_t>> m_base_sampler;
    std::vector<float> m_base_centre;
    size_t             m_max_slevels;
    size_t             m_k;
    int32_t            m_q;
    size_t             m_flips;
    size_t             m_log_base;
    uint64_t           m_mask;
    long double        m_wide_sigma2;
    long double        m_inv_wide_sigma2;
    long double        m_rr_sigma2;
};

}  // namespace sampling
}  // namespace phantom


