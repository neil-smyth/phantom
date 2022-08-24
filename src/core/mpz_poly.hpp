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
#include <cmath>
#include <iomanip>
#include <limits>
#include <vector>

#include "core/mpbase.hpp"
#include "core/mp.hpp"
#include "core/template_helpers.hpp"


namespace phantom {
namespace core {

template<typename T>
class mpz;

/** 
 * @brief Multiple precision polynomial class
 * 
 * Common methods for use within the mpz class
 */
template<typename T>
class mpz_poly : public mp<T>
{
    static_assert(std::is_same<T, uint8_t>::value  ||
                  std::is_same<T, uint16_t>::value ||
                  std::is_same<T, uint32_t>::value ||
                  std::is_same<T, uint64_t>::value,
                  "number instantiated with unsupported type");

    using S = signed_type_t<T>;

    phantom_vector<mpz<T>> m_poly;


public:
    /// Constructors
    /// @{

    // Default constructor
    mpz_poly()
    {
        // Initialise to zero
        m_poly = phantom_vector<mpz<T>>();
    }

    /// Copy constructor from base type
    explicit mpz_poly(const mp<T>& obj)
    {
        auto local = dynamic_cast<const mpz_poly&>(obj);
        m_poly = local.m_poly;
    }

    /// Copy constructor
    mpz_poly(const mpz_poly& obj)
    {
        m_poly = obj.m_poly;
    }


    /// @}


    /// Destructor
    /// @{

    /// Default destructor
    virtual ~mpz_poly()
    {
    }

    /// @}


};

}  // namespace core
}  // namespace phantom
