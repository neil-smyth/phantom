/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include "core/const_time.hpp"
#include "crypto/csprng.hpp"


namespace phantom {
namespace sampling {

/**
 * @brief A base class for Gaussian sample generation
 * 
 * @tparam T Data type for samples (must be signed)
 * @tparam P Internal data type used for computation (must be unsigned)
 * @tparam std::enable_if<std::is_signed<T>::value, T>::type Check for signed T
 * @tparam std::enable_if<std::is_unsigned<P>::value, P>::type Check for unsigned P
 */
template<typename T,
         typename P,
         typename = typename std::enable_if<std::is_signed<T>::value, T>::type,
         typename = typename std::enable_if<std::is_unsigned<P>::value, P>::type>
class gaussian
{
public:
    enum discard_rate_e {
        SAMPLE_DISCARD_LO = 0,
        SAMPLE_DISCARD_MD,
        SAMPLE_DISCARD_HI,
    };

    virtual ~gaussian() {}

    virtual void set_discard(discard_rate_e rate)
    {
        m_discard = rate;
        m_thresh  = get_threshold(m_discard);
    }

    virtual discard_rate_e get_discard() const
    {
        return m_discard;
    }

    virtual T get_signed_sample() = 0;
    virtual T get_unsigned_sample() = 0;

private:
    static uint32_t get_threshold(discard_rate_e discard)
    {
        return (SAMPLE_DISCARD_LO == discard)? 1 << (32 - 4) :
               (SAMPLE_DISCARD_MD == discard)? 1 << (32 - 2) :
               (SAMPLE_DISCARD_HI == discard)? 1 << (32 - 1) :
                                               0;
    }

    size_t discard_sample()
    {
        if (0 == m_thresh) {
            return 0;
        }
        else {
            T rnd = m_prng->get<T>();
            return const_time<T>::cmp_lessthan(rnd, m_thresh);
        }
    }

    std::shared_ptr<csprng> m_prng;
    discard_rate_e          m_discard;
    uint32_t                m_thresh;
};

}  // namespace sampling
}  // namespace phantom


