/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "core/mpbase.hpp"


namespace phantom {
namespace core {


/**
 * @brief Convert an array to REDC form, r = B^n * u mod m
 * 
 * @param r_limbs Residual
 * @param u_limbs U
 * @param un U length
 * @param m_limbs M
 * @param mn Modulus length
 */
template<typename T>
void mpbase<T>::redcify(T* r_limbs, const T* u_limbs, size_t un, const T* m_limbs, size_t mn)
{
    // Create a temporary array where u is copied to the upper words, i.e. scratch = B*n * u
    phantom_vector<T> scratch(un + mn), q_limbs(un + 1);
    copy(scratch.data() + mn, u_limbs, un);

    // Use div_qr to calculate the remainder of scratch divided by the modulus
    div_qr(q_limbs.data(), scratch.data(), un + mn, m_limbs, mn);

    // Copy the remainder to form the residual output
    copy(r_limbs, scratch.data(), mn);
}

/**
 * Montgomery reduction (REDC) with a single-word inverse
 * @param r_limbs Residual
 * @param u_limbs U
 * @param m_limbs M
 * @param n M
 * @param invm Inverse of modulus
 */
template<typename T>
T mpbase<T>::redc_1(T* r_limbs, T* u_limbs, const T* m_limbs, size_t n, T invm)
{
    assert(n > 0);

    for (int j = n - 1; j >= 0; j--) {
        T cy = addmul_1(u_limbs, m_limbs, n, (u_limbs[0] * invm) & LIMB_MASK);
        assert(u_limbs[0] == 0);
        u_limbs[0] = cy;
        u_limbs++;
    }

    return add_n(r_limbs, u_limbs, u_limbs - n, n);
}

/**
 * Montgomery reduction (REDC) with a single-word inverse with carry fix
 * @param r_limbs Residual
 * @param u_limbs U
 * @param m_limbs M
 * @param n M
 * @param invm Inverse of modulus
 */
template<typename T>
void mpbase<T>::redc_1_fix(T* r_limbs, T* u_limbs, const T* m_limbs, size_t n, T invm)
{
    T cy = redc_1(r_limbs, u_limbs, m_limbs, n, invm);
    if (cy != 0) {
        sub_n(r_limbs, r_limbs, m_limbs, n);
    }
}

/**
 * Montgomery reduction (REDC) with a double-word inverse
 * @param r_limbs Residual
 * @param u_limbs U
 * @param m_limbs M
 * @param n M
 * @param i_limbs Inverse of modulus
 */
template<typename T>
T mpbase<T>::redc_2(T* r_limbs, T* u_limbs, const T* m_limbs, size_t n, const T* i_limbs)
{
    T q[2];
    T upn;
    T cy;

    assert(n > 0);

    if (0 != (n & 1)) {
        u_limbs[0] = addmul_1(u_limbs, m_limbs, n, (u_limbs[0] * i_limbs[0]) & LIMB_MASK);
        u_limbs++;
    }

    for (int j = n - 2; j >= 0; j -= 2) {
        number<T>::umul2_lo(&q[1], &q[0], i_limbs[1], i_limbs[0], u_limbs[1], u_limbs[0]);
        upn = u_limbs[n];  // addmul_2 will overwrite this so store here
        u_limbs[1] = addmul_2(u_limbs, m_limbs, n, q);
        u_limbs[0] = u_limbs[n];
        u_limbs[n] = upn;
        u_limbs += 2;
    }

    return add_n(r_limbs, u_limbs, u_limbs - n, n);
}

/**
 * Montgomery reduction (REDC) with an n-word inverse
 * @param r_limbs Residual
 * @param u_limbs U
 * @param m_limbs M
 * @param n M
 * @param i_limbs Inverse of modulus
 */
template<typename T>
void mpbase<T>::redc_n(T* r_limbs, T* u_limbs, const T* m_limbs, size_t n, const T* i_limbs)
{
    assert(n > 8);

    size_t rn = mulmod_bnm1_next_size(n);

    T* scratch = reinterpret_cast<T*>(aligned_malloc(sizeof(T) * (n + rn + mulmod_bnm1_size(rn, n, n))));

    // Calculate the lower half of U * I and reduce
    T* xp = scratch;
    mul_low_n(xp, u_limbs, i_limbs, n);

    T* yp = scratch + n;
    mulmod_bnm1(yp, rn, xp, n, m_limbs, n, scratch + n + rn);

    assert(2 * n > rn);

    // Correct the wrap around
    T cy = sub_n(yp + rn, yp, u_limbs, 2*n - rn);
    sub_1(yp + 2*n - rn, yp + 2*n - rn, rn, cy);

    cy = sub_n(r_limbs, u_limbs + n, yp + n, n);
    if (cy != 0) {
        add_n(r_limbs, r_limbs, m_limbs, n);
    }

    // Free our intermediate storage
    aligned_free(scratch);
}


// Forward declaration of common type declarations
/// @{
template class mpbase<uint8_t>;
template class mpbase<uint16_t>;
template class mpbase<uint32_t>;
template class mpbase<uint64_t>;
/// @}

}  // namespace core
}  // namespace phantom
