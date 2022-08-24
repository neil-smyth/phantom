/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "core/mpz.hpp"


namespace phantom {
namespace core {


// Default constructor
template<typename T>
mpz<T>::mpz()
{
    // Initialise to zero
    m_limbs.resize(0);
    m_sign  = false;
}

/// Copy constructor from base type
template<typename T>
mpz<T>::mpz(const mp<T>& obj)  // NOLINT
{
    auto local = dynamic_cast<const mpz&>(obj);
    m_limbs = local.m_limbs;
    m_sign  = local.m_sign;
}

/// Copy constructor
template<typename T>
mpz<T>::mpz(const mpz& obj)
{
    m_limbs = obj.m_limbs;
    m_sign  = obj.m_sign;
}

template<typename T>
mpz<T>::mpz(const phantom_vector<T>& vec, bool sign)
{
    m_limbs = phantom_vector<T>(vec.begin(), vec.end());
    m_sign  = sign;
}

template<typename T>
mpz<T>& mpz<T>::set(const mpz& obj)
{
    m_limbs = obj.m_limbs;
    m_sign  = obj.m_sign;
    return *this;
}

template<typename T>
mpz<T> mpz<T>::clone(const mpz& obj)
{
    mpz out;
    out.m_limbs = obj.m_limbs;
    out.m_sign  = obj.m_sign;
    return out;
}

/// Constructor with raw byte array initialization
template<typename T>
mpz<T>::mpz(uint8_t* data, size_t n)
{
    mpz temp;
    m_limbs.resize((n + sizeof(T) - 1)/sizeof(T));
    m_sign  = false;

    for (size_t i=n; i--;) {
        temp = this->mul_2exp(8);
        this->add(temp, data[i]);
    }
}

/// Constructor that initializes from an unsigned integer
template<typename T>
mpz<T>::mpz(T data)  // NOLINT
{
    m_sign  = false;

    if (0 == data) {
        // If zero then simply assign a used length of zero
        m_limbs.resize(0);
    }
    else {
        // Modify the limb length to single precision and set the value
        m_limbs.resize(1);
        m_limbs[0] = data;
    }
}

/// Constructor that initializes from an signed integer
template<typename T>
mpz<T>::mpz(S data)  // NOLINT
{
    if (0 == data) {
        // If zero then simply assign a used length of zero
        m_limbs.resize(0);
        m_sign     = false;
    }
    else if (data > 0) {
        m_limbs.resize(1);
        m_limbs[0] = data;
        m_sign     = false;
    }
    else {
        // Modify the limb length to single precision and set the value
        m_limbs.resize(1);
        m_limbs[0] = -(static_cast<T>(data + 1) - 1);
        m_sign     = true;
    }
}

/// Constructor that initializes from a double
template<typename T>
mpz<T>::mpz(double data)  // NOLINT
{
    static const double b     = 2.0 * static_cast<double>(LIMB_HIGHBIT);
    static const double b_inv = 1.0 / b;

    // Check for x is NaN, zero or infinity, set the value to zero if so
    if (data != data || data == data * 0.5) {
        m_limbs.resize(0);
        m_sign  = false;
        return;
    }

    // Determine the sign and obtain the absolute value of the input floating point value,
    // if less than 1 then the result is zero.
    m_sign = data < 0.0;
    data   = (m_sign)? -data : data;
    if (data < 1.0) {
        m_limbs.resize(0);
        m_sign  = false;
        return;
    }

    // Determine the required number of limb words required to store the result
    // and scale the input floating point value.
    size_t used;
    for (used=1; data >= b; used++) {
        data *= b_inv;
    }

    // Resize the output MP integer
    m_limbs.resize(used);

    // Iteratively expand the fractional component from most to least significant word
    T fix    = static_cast<T>(data);
    data    -= static_cast<double>(fix);
    m_limbs[--used] = fix;
    while (used--) {
        data         *= b;
        fix           = static_cast<T>(data);
        data         -= static_cast<double>(fix);
        m_limbs[used] = fix;
    }
}

template<typename T>
mpz<T>::mpz(const char* str, size_t base)
{
    limbstring<T>::set_str(m_limbs, m_sign, str, base);
}



template<typename T> mpz<T>::operator double()   const { return get_d();                     }
template<typename T> mpz<T>::operator float()    const { return static_cast<float>(get_d()); }
template<typename T> mpz<T>::operator uint8_t()  const { return get_ui();                    }
template<typename T> mpz<T>::operator uint16_t() const { return get_ui();                    }
template<typename T> mpz<T>::operator uint32_t() const { return get_ui();                    }
template<typename T> mpz<T>::operator uint64_t() const { return get_ui();                    }
template<typename T> mpz<T>::operator int8_t()   const { return get_si();                    }
template<typename T> mpz<T>::operator int16_t()  const { return get_si();                    }
template<typename T> mpz<T>::operator int32_t()  const { return get_si();                    }
template<typename T> mpz<T>::operator int64_t()  const { return get_si();                    }


template<typename T>
const T mpz<T>::operator[](size_t index) const
{
    if (0 == index && this->get_limbsize() == 0) {
        return 0;
    }
    if (index >= this->get_limbsize()) {
        throw std::out_of_range("index is out of range");
    }
    return this->m_limbs[index];
}

template<typename T>
T& mpz<T>::operator[](size_t index)
{
    if (index >= this->get_limbsize()) {
        throw std::out_of_range("index is out of range");
    }
    if (0 == index && this->get_limbsize() == 0) {
        this->m_limbs.push_back(0);
    }
    return this->m_limbs[index];
}

template<typename T>
mpz<T>& mpz<T>::operator+=(const mpz& rhs)
{
    mpz in = *this;
    this->add(in, rhs);
    return *this;
}

template<typename T>
mpz<T>& mpz<T>::operator+=(T rhs)
{
    mpz in = *this;
    this->add(in, rhs);
    return *this;
}

template<typename T>
mpz<T> mpz<T>::operator+(const mpz& rhs) const
{
    mpz out;
    out.add(*this, rhs);
    return out;
}

template<typename T>
mpz<T> mpz<T>::operator+(T rhs) const
{
    mpz out;
    out.add(*this, rhs);
    return out;
}

template<typename T>
mpz<T> mpz<T>::operator+(S rhs) const
{
    mpz out;
    if (rhs < 0) {
        out.sub(*this, static_cast<T>(-rhs));
    }
    else {
        out.add(*this, static_cast<T>(rhs));
    }
    return out;
}

template<typename T>
mpz<T>& mpz<T>::operator++()
{
    mpz out = *this;
    this->add(out, T(1));
    return *this;
}

template<typename T>
mpz<T> mpz<T>::operator++(int)  // NOLINT
{
    mpz out = *this;
    ++*this;
    return out;
}

template<typename T>
mpz<T>& mpz<T>::operator-=(const mpz& rhs)
{
    mpz in = *this;
    this->sub(in, rhs);
    return *this;
}

template<typename T>
mpz<T>& mpz<T>::operator-=(T rhs)
{
    mpz in = *this;
    this->sub(in, rhs);
    return *this;
}

template<typename T>
mpz<T> mpz<T>::operator-(const mpz& rhs) const
{
    mpz out;
    out.sub(*this, rhs);
    return out;
}

template<typename T>
mpz<T> mpz<T>::operator-(T rhs) const
{
    mpz out;
    out.sub(*this, rhs);
    return out;
}

template<typename T>
mpz<T> mpz<T>::operator-(S rhs) const
{
    mpz out;
    if (rhs < 0) {
        out.add(*this, static_cast<T>(-rhs));
    }
    else {
        out.sub(*this, static_cast<T>(rhs));
    }
    return out;
}

template<typename T>
mpz<T>& mpz<T>::operator--()
{
    mpz out = *this;
    this->sub(out, T(1));
    return *this;
}

template<typename T>
mpz<T> mpz<T>::operator--(int)  // NOLINT
{
    mpz out = *this;
    --*this;
    return out;
}

template<typename T>
mpz<T> mpz<T>::operator-() const
{
    mpz out = *this;
    out.negate();
    return out;
}

template<typename T>
mpz<T> mpz<T>::operator*(const mpz& rhs) const
{
    mpz out;
    mul(out, *this, rhs);
    return out;
}

template<typename T>
mpz<T> mpz<T>::operator*(T rhs) const
{
    mpz out;
    mul_ui(out, *this, rhs);
    return out;
}

template<typename T>
mpz<T> mpz<T>::operator*(S rhs) const
{
    mpz out;
    mul_si(out, *this, rhs);
    return out;
}

template<typename T>
mpz<T> mpz<T>::operator*(double rhs) const
{
    mpz out;
    mpz rhs_d(rhs);
    mul(out, *this, rhs_d);
    return out;
}

template<typename T>
mpz<T> mpz<T>::operator/(const mpz& d) const
{
    mpz out;
    tdiv_q(out, *this, d);
    return out;
}

template<typename T>
mpz<T> mpz<T>::operator/(T d) const
{
    mpz out;
    tdiv_q_ui(out, *this, d);
    return out;
}

template<typename T>
mpz<T> mpz<T>::operator%(const mpz& d) const
{
    mpz out;
    tdiv_r(out, *this, d);
    return out;
}

template<typename T>
mpz<T> mpz<T>::operator%(T d) const
{
    mpz out;
    tdiv_r_ui(out, *this, d);
    return out;
}

template<typename T>
mpz<T> mpz<T>::operator&(const mpz& d) const
{
    mpz out;
    out.bitwise_and(*this, d);
    return out;
}

template<typename T>
mpz<T>& mpz<T>::operator&=(const mpz& d)
{
    mpz in = *this;
    this->bitwise_and(in, d);
    return *this;
}

template<typename T>
mpz<T> mpz<T>::operator|(const mpz& d) const
{
    mpz out;
    out.bitwise_or(*this, d);
    return out;
}

template<typename T>
mpz<T>& mpz<T>::operator|=(const mpz& d)
{
    mpz in = *this;
    this->bitwise_or(in, d);
    return *this;
}

template<typename T>
mpz<T> mpz<T>::operator^(const mpz& d) const
{
    mpz out;
    out.bitwise_xor(*this, d);
    return out;
}

template<typename T>
mpz<T>& mpz<T>::operator^=(const mpz& d)
{
    mpz in = *this;
    this->bitwise_xor(in, d);
    return *this;
}

template<typename T>
mpz<T> mpz<T>::operator<<(int bits) const
{
    mpz out;
    out.lshift(*this, bits);
    return out;
}

template<typename T>
mpz<T>& mpz<T>::operator<<(int bits)
{
    mpz in = *this;
    this->lshift(in, bits);
    return *this;
}

template<typename T>
mpz<T>& mpz<T>::operator<<=(int bits)
{
    mpz in = *this;
    this->lshift(in, bits);
    return *this;
}

template<typename T>
mpz<T> mpz<T>::operator>>(int bits) const
{
    mpz out;
    out.rshift(*this, bits);
    return out;
}

template<typename T>
mpz<T>& mpz<T>::operator>>(int bits)
{
    mpz in = *this;
    this->rshift(in, bits);
    return *this;
}

template<typename T>
mpz<T>& mpz<T>::operator>>=(int bits)
{
    mpz in = *this;
    this->rshift(in, bits);
    return *this;
}

template<typename T>
mpz<T>& mpz<T>::operator=(const mpz& rhs)
{
    m_sign = rhs.is_negative();
    m_limbs = rhs.m_limbs;
    return *this;
}

template<typename T>
mpz<T>& mpz<T>::operator=(T rhs)
{
    this->m_limbs.resize(1);
    this->m_limbs[0] = rhs;
    this->m_sign = false;
    return *this;
}

template<typename T>
mpz<T>& mpz<T>::operator=(S rhs)
{
    if (0 == rhs) {
        this->m_limbs.resize(0);
        this->m_sign = false;
    }
    else {
        this->m_limbs.resize(1);
        if (rhs < 0) {
            this->m_limbs[0] = -(static_cast<T>(rhs + 1) - 1);
            this->m_sign = true;
        }
        else {
            this->m_limbs[0] = static_cast<T>(rhs);
            this->m_sign = false;
        }
    }
    return *this;
}

template<typename T>
mpz<T>& mpz<T>::operator=(double rhs)
{
    mpz local(rhs);
    m_limbs = local.m_limbs;
    m_sign  = local.m_sign;
    return *this;
}

template<typename T>
bool mpz<T>::operator==(const mpz& rhs)
{
    return 0 == this->cmp(rhs);
}

template<typename T>
bool mpz<T>::operator==(T rhs)
{
    return 0 == this->cmp_ui(rhs);
}

template<typename T>
bool mpz<T>::operator==(S rhs)
{
    return 0 == this->cmp_si(rhs);
}

template<typename T>
bool mpz<T>::operator==(double rhs)
{
    return 0 == this->cmp_d(rhs);
}

template<typename T>
bool mpz<T>::operator!=(const mpz& rhs)
{
    return 0 != this->cmp(rhs);
}

template<typename T>
bool mpz<T>::operator!=(T rhs)
{
    return 0 != this->cmp_ui(rhs);
}

template<typename T>
bool mpz<T>::operator!=(S rhs)
{
    return 0 != this->cmp_si(rhs);
}

template<typename T>
bool mpz<T>::operator!=(double rhs)
{
    return 0 != this->cmp_d(rhs);
}

template<typename T>
bool mpz<T>::operator<=(const mpz& rhs)
{
    return 1 != this->cmp(rhs);
}

template<typename T>
bool mpz<T>::operator<=(T rhs)
{
    return 1 != this->cmp_ui(rhs);
}

template<typename T>
bool mpz<T>::operator<=(S rhs)
{
    return 1 != this->cmp_si(rhs);
}

template<typename T>
bool mpz<T>::operator<=(double rhs)
{
    return 1 != this->cmp_d(rhs);
}

template<typename T>
bool mpz<T>::operator<(const mpz& rhs)
{
    return -1 == this->cmp(rhs);
}

template<typename T>
bool mpz<T>::operator<(T rhs)
{
    return -1 == this->cmp_ui(rhs);
}

template<typename T>
bool mpz<T>::operator<(S rhs)
{
    return -1 == this->cmp_si(rhs);
}

template<typename T>
bool mpz<T>::operator<(double rhs)
{
    return -1 == this->cmp_d(rhs);
}

template<typename T>
bool mpz<T>::operator>=(const mpz& rhs)
{
    return -1 != this->cmp(rhs);
}

template<typename T>
bool mpz<T>::operator>=(T rhs)
{
    return -1 != this->cmp_ui(rhs);
}

template<typename T>
bool mpz<T>::operator>=(S rhs)
{
    return -1 != this->cmp_si(rhs);
}

template<typename T>
bool mpz<T>::operator>=(double rhs)
{
    return -1 != this->cmp_d(rhs);
}

template<typename T>
bool mpz<T>::operator>(const mpz& rhs)
{
    return 1 == this->cmp(rhs);
}

template<typename T>
bool mpz<T>::operator>(T rhs)
{
    return 1 == this->cmp_ui(rhs);
}

template<typename T>
bool mpz<T>::operator>(S rhs)
{
    return 1 == this->cmp_si(rhs);
}

template<typename T>
bool mpz<T>::operator>(double rhs)
{
    return 1 == this->cmp_d(rhs);
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
