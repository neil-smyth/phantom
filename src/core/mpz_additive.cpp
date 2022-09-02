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



/// Negate the mpz object
template<typename T>
mpz<T>& mpz<T>::negate()
{
    set_sign(!this->is_negative());
    return *this;
}

/// Calculate the absolute of the mpz object
template<typename T>
mpz<T> mpz<T>::abs() const
{
    mpz out = *this;
    out.set_sign(false);
    return out;
}

/// Add the two mpz integers as absolute values
template<typename T>
int32_t mpz<T>::abs_add(const mpz& in1, const mpz& in2)
{
    int32_t in1_used = in1.get_limbsize();
    int32_t in2_used = in2.get_limbsize();
    int32_t max_used = (in1_used < in2_used)? in2_used : in1_used;

    m_limbs.resize(max_used + 1);
    int32_t used = mpz_core<T>::abs_add(m_limbs.data(), in1.get_limbs().data(), in1_used,
        in2.get_limbs().data(), in2_used);
    m_limbs.resize(used);
    return used;
}

/// Subtract the two mpz integers as absolute values
template<typename T>
int32_t mpz<T>::abs_sub(const mpz& in1, const mpz& in2)
{
    // Determine relative absolute sizes of the inputs
    int32_t in1_used = in1.get_limbsize();
    int32_t in2_used = in2.get_limbsize();
    int32_t max_used = (in1_used < in2_used)? in2_used : in1_used;

    m_limbs.resize(max_used);
    int32_t used = mpz_core<T>::abs_sub(m_limbs.data(), in1.get_limbs().data(), in1_used,
        in2.get_limbs().data(), in2_used);
    m_limbs.resize((used < 0)? -used : used);

    return used;
}

/// Add an mpz integer and an unsigned integer as absolute values
template<typename T>
int32_t mpz<T>::abs_add(const mpz& in1, T in2)
{
    m_limbs.resize(in1.get_limbsize() + 1);
    int32_t used = mpz_core<T>::abs_add(m_limbs.data(), in1.m_limbs.data(), in1.get_limbsize(), in2);
    m_limbs.resize(used);
    return used;
}

/// Subtract an mpz integer and an unsigned integer as absolute values
template<typename T>
int32_t mpz<T>::abs_sub(const mpz& in1, T in2)
{
    int32_t used = in1.get_limbsize();
    m_limbs.resize((used < 1)? 1 : used);
    used = mpz_core<T>::abs_sub(m_limbs.data(), in1.get_limbs().data(), used, in2);
    m_limbs.resize((used < 0)? -used : used);
    return static_cast<int32_t>(used);
}

/// Add an unsigned integer to an mpz object
template<typename T>
void mpz<T>::add(const mpz<T>& in1, T in2)
{
    if (!in1.is_negative()) {
        this->abs_add(in1, in2);
        m_sign = false;
    }
    else {
        int32_t res = -this->abs_sub(in1, in2);
        m_sign = res < 0;
    }
}

/// Subtract an unsigned integer from an mpz object
template<typename T>
void mpz<T>::sub(const mpz<T>& in1, T in2)
{
    if (!in1.is_negative()) {
        int32_t res = this->abs_sub(in1, in2);
        m_sign = res < 0;
    }
    else {
        this->abs_add(in1, in2);
        m_sign = true;
    }
}

/// Add an unsigned integer to an mpz object
template<typename T>
mpz<T>& mpz<T>::add(T in2)
{
    this->add(*this, in2);
    return *this;
}

/// Subtract an unsigned integer from an mpz object
template<typename T>
mpz<T>& mpz<T>::sub(T in2)
{
    this->sub(*this, in2);
    return *this;
}

/// Add an mpz object to an mpz object
template<typename T>
void mpz<T>::add(const mpz<T>& in1, const mpz<T>& in2)
{
    if (in1.is_negative() ^ in2.is_negative()) {
        int32_t res;
        if (in1.is_negative()) {
            res = this->abs_sub(in2, in1);
        }
        else {
            res = this->abs_sub(in1, in2);
        }
        m_sign = res < 0;
    }
    else {
        this->abs_add(in1, in2);
        m_sign = in1.is_negative();
    }
}

/// Subtract an mpz object from an mpz object
template<typename T>
void mpz<T>::sub(const mpz<T>& in1, const mpz<T>& in2)
{
    if (in1.is_negative() ^ in2.is_negative()) {
        this->abs_add(in1, in2);
        m_sign = in1.is_negative();
    }
    else {
        int32_t res = this->abs_sub(in1, in2);
        m_sign = res < 0;
    }
}

/// Add an mpz object to an mpz object
template<typename T>
mpz<T>& mpz<T>::add(const mpz<T>& in2)
{
    this->add(*this, in2);
    return *this;
}

/// Subtract an mpz object from an mpz object
template<typename T>
mpz<T>& mpz<T>::sub(const mpz<T>& in2)
{
    this->sub(*this, in2);
    return *this;
}

/// Add an mpz object and reduce
template<typename T>
mpz<T>& mpz<T>::add_mod(const mpz<T>& in2, const mod_config<T>& cfg)
{
    this->add(*this, in2);
    this->mod_positive(cfg);
    return *this;
}

/// Subtract an mpz object and reduce
template<typename T>
mpz<T>& mpz<T>::sub_mod(const mpz<T>& in2, const mod_config<T>& cfg)
{
    this->sub(*this, in2);
    this->mod_positive(cfg);
    return *this;
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
