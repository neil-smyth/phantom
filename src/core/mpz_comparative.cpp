/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "core/mpz.hpp"


namespace phantom {
namespace core {


/// Compare two mpz objects (using references to base class objects)
template<typename T>
int32_t mpz<T>::cmp(const mp<T>& in) const
{
    return mpz_core<T>::cmp(get_limbs().data(), is_negative(), get_limbs().size(),
        in.get_limbs().data(), in.is_negative(), in.get_limbs().size());
}

/// Compare to a double value (double is converted to integer and rounded towards zero)
template<typename T>
int32_t mpz<T>::cmp_d(double in) const
{
    return mpz_core<T>::cmp_d(get_limbs().data(), m_sign, get_limbs().size(), in);
}

/// Compare to an unsigned integer
template<typename T>
int32_t mpz<T>::cmp_ui(T in) const
{
    if (0 == get_limbsize()) {
        // lhs is zero, so do a simple comparison of zero to rhs
        return (0 == in)? 0 : -1;
    }
    else if (!m_sign && get_limbsize() > 1) {
        // lhs is a multiple precision positive integer, so it is larger than
        return 1;
    }
    else if (m_sign) {
        // We are comparing to an unsigned number, so any negative lhs will be less than
        return -1;
    }
    else {
        // Both the rhs and lhs are non-zero single precision positive integers
        return (m_limbs[0] > in) - (m_limbs[0] < in);
    }
}

/// Compare to a signed integer
template<typename T>
int32_t mpz<T>::cmp_si(S in) const
{
    if (0 == get_limbsize()) {
        // lhs is zero, so do a simple comparison of zero to rhs
        return (0 == in)? 0 : (in < 0)? 1 : -1;
    }
    else if (m_sign && 1 < get_limbsize()) {
        // If this is a multiple-precision negative integer it must be less than rhs
        return -1;
    }
    else if (in >= 0) {
        // rhs and lhs are both non-negative, use the unsigned integer routine to compare
        return cmp_ui(in);
    }
    else if (!m_sign) {
        // rhs is negative and lhs is positive then the result must be greater than
        return 1;
    }
    else {
        // lhs is single-precision negative and rhs is negative so compare their single precision magnitudes
        T temp1 = m_limbs[0];
        T temp2 = -(static_cast<T>(in + 1) - 1);
        return (temp1 < temp2) - (temp1 > temp2);
    }
}

/// Compare two mpz objects in terms of the absolute magnitude
template<typename T>
int32_t mpz<T>::cmpabs(const mp<T>& in) const
{
    // Compare the two limb arrays which are stored in an absolute format
    return mpz_core<T>::cmpabs(get_limbs().data(), get_limbsize(), in.get_limbs().data(), in.get_limbs().size());
}

/// Compare an mpz object and a double in terms of their absolute magnitudes
template<typename T>
int32_t mpz<T>::cmpabs_d(double in) const
{
    return mpz_core<T>::cmpabs_d(get_limbs().data(), get_limbs().size(), in);
}

// Calculate the integer size in bits of the mpz object given a specific base
template<typename T>
size_t mpz<T>::sizeinbase(size_t base) const
{
    return mpz_core<T>::sizeinbase(get_limbs().data(), get_limbsize(), base);
}

/// Swap the mpz pbjects
template<typename T>
void mpz<T>::swap(mp<T>& in)  // NOLINT
{
    // Swap the limb vectors and the sign
    m_limbs.swap(const_cast<phantom_vector<T>&>(in.get_limbs()));
    bool in_sign = in.is_negative();
    bit_manipulation::swap<bool>(m_sign, in_sign);  // NOLINT
    in.set_sign(in_sign);
}

/// Return the number of limb words used by the mpz object
template<typename T>
size_t mpz<T>::get_limbsize() const
{
    return m_limbs.size();
}


// Forward declaration of common sizes
template class mpz<uint8_t>;
template class mpz<uint16_t>;
template class mpz<uint32_t>;
#if defined(IS_64BIT)
template class mpz<uint64_t>;
#endif

}  // namespace core
}  // namespace phantom
