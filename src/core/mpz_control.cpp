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


/// Return a flag indicating that the mpz object is zero
template<typename T>
bool mpz<T>::is_zero() const
{
    return 0 == m_limbs.size();
}

/// Return a flag indicating that the mpz object is one
template<typename T>
bool mpz<T>::is_one() const
{
    return 1 == m_limbs.size() && 1 == m_limbs[0];
}

/// Return a flag indicating that the mpz object is negative
template<typename T>
bool mpz<T>::is_negative() const
{
    return m_sign;
}

/// Set the sign flag to the defined value
template<typename T>
void mpz<T>::set_sign(bool sign)
{
    m_sign = sign;
}

// Memory pre-allocation and value set to zero
template<typename T>
void mpz<T>::zero_init(size_t n)
{
    m_limbs = phantom_vector<T>(n);
    m_sign  = false;
}

/// Return a flag indicating if the defined bit is asserted
template<typename T>
bool mpz<T>::tstbit(size_t bit_index) const
{
    // Calculate the limb index - divide the bit_index by the bits per limb
    size_t idx = bit_index >> bits_log2<T>::value();

    if (get_limbsize() <= idx) {
        // If the limb index exceeds the number of used limb words the output
        // is the sign extended to infinity
        return m_sign;
    }
    else {
        // For the limb word being tested we determine the number of bits to shift
        // to obtain the bit in the LSB position
        size_t shift = bit_index & ((1 << bits_log2<T>::value()) - 1);
        size_t word  = m_limbs[idx];
        bool   bit   = (word >> shift) & 0x1;

        // Determine if the number is negative as the two's complement must be used
        if (m_sign) {
            // There are non-zero lower order bits present in the word
            if (shift > 0 && (word << (std::numeric_limits<T>::digits - shift)) > 0) {
                return !bit;
            }

            // Check for non-zero low order bits present in lower order words
            while (idx--) {
                if (m_limbs[idx]) {
                    return !bit;
                }
            }
        }

        return bit;
    }
}

template<typename T>
void mpz<T>::setbit(size_t bit_index)
{
    // If the bit is currently unset then assert the bit and perform carry propagation
    if (!tstbit(bit_index)) {
        size_t used  = get_limbsize();
        size_t word  = bit_index >> bits_log2<T>::value();  // Divide the bit_index by the number of limb bits
        T      bit   = T(1) << (bit_index & ((1 << bits_log2<T>::value()) - 1));

        if (m_sign) {
            // The number is negative so subtract and recalculate the used words (ignoring LSW's)
            mpbase<T>::sub_1(m_limbs.data() + word, m_limbs.data() + word, used - word, bit);
            used = mpbase<T>::normalized_size(m_limbs.data(), used);
            m_limbs.resize(used);
        }
        else if (word < used) {
            // The number is zero or positive and the bit index is within range (assuming carry propagation
            // can occur) then add the bit at the appropriate position and carry any bits
            T carry = mpbase<T>::add_1(m_limbs.data() + word, m_limbs.data() + word, used - word, bit);
            if (carry) {
                m_limbs.push_back(carry);
            }
        }
        else {
            // The number is zero or positive and out of range so allocate more storage,
            // set the bit and zero any new bits
            m_limbs.resize(word + 1);
            m_limbs[word] = bit;
            std::fill(m_limbs.begin() + used, m_limbs.begin() + used + word, 0);
        }
    }
}

template<typename T>
void mpz<T>::unsetbit(size_t bit_index)
{
    // If the bit is currently set then de-assert the bit and perform carry propagation
    if (tstbit(bit_index)) {
        size_t used  = get_limbsize();
        size_t word  = bit_index >> bits_log2<T>::value();  // Divide the bit_index by the number of limb bits
        T      bit   = T(1) << (bit_index & ((1 << bits_log2<T>::value()) - 1));

        if (m_sign) {
            // The number is negative so add and recalculate the used words (ignoring LSW's)
            mpbase<T>::add_1(m_limbs.data() + word, m_limbs.data() + word, used - word, bit);
            used = mpbase<T>::normalized_size(m_limbs.data(), used);
            m_limbs.resize(used);
        }
        else if (word < used) {
            // The number is zero or positive and the bit index is within range (assuming carry propagation
            // can occur) then add the bit at the appropriate position and carry any bits
            T carry = mpbase<T>::sub_1(m_limbs.data() + word, m_limbs.data() + word, used - word, bit);
            if (carry) {
                m_limbs.push_back(carry);
            }
        }
    }
}

template<typename T>
size_t mpz<T>::make_odd(mpz& r)
{
    mpz temp = r;
    T limb = temp[0];

    // Obtain the number of trailing zeros in the MP integer
    size_t i = 0;
    while (0 == limb) {
        limb = temp[++i];
    }
    int32_t count = bit_manipulation::ctz(limb);

    // Now normalise the input by right shifting the zeros away
    // making it an odd number
    size_t shift = i * std::numeric_limits<T>::digits + count;
    tdiv_q_2exp(r, temp, shift);

    // Return the number of normalised bits
    return shift;
}

template<typename T>
T mpz<T>::get_ui() const
{
    // Simply return the least significant limb, or zero for the special
    // case of a zero value
    return (0 == get_limbsize())? 0 : m_sign? -m_limbs[0] : m_limbs[0];
}

template<typename T>
signed_type_t<T> mpz<T>::get_si() const
{
    if (get_limbsize() >= 0) {
        // If non-negative use the mpz_get_ui() function
        return static_cast<S>(get_ui());
    }
    else {
        // If negative cast back to a positive value
        return (S(-1) - static_cast<S>((m_limbs[0] - 1) & ~(std::numeric_limits<T>::digits - 1)));
    }
}

template<typename T>
double mpz<T>::get_d() const
{
    static const double b = 2.0 * static_cast<double>(LIMB_HIGHBIT);

    // Determine the number of limbs, if zero then terminate early
    bool sign  = m_sign;
    int32_t used  = get_limbsize();
    if (0 == used) {
        return 0.0;
    }

    // Iteratively generate the floating point equivalent
    double res = m_limbs[--used];
    while (used > 0) {
        res *= b;
        res += m_limbs[--used];
    }

    // Apply the correct sign
    res = (sign)? -res : res;

    return res;
}

template<typename T>
void mpz<T>::get_bytes(phantom_vector<uint8_t>& bytes, bool little_endian) const
{
    if (this->is_zero()) {
        bytes.resize(1);
        bytes[0] = 0;
        return;
    }

    size_t num_bytes = std::numeric_limits<T>::digits >> 3;
    size_t n         = (this->sizeinbase(2) + 7) >> 3;

    bytes.resize(n);

    T mask = num_bytes - 1;
    T w = 0;
    for (size_t i=0; i < n; i++) {
        if (0 == (i & mask)) {
            w = m_limbs[i >> (bits_log2<T>::value() - 3)];
        }

        bytes[i] = w & 0xff;
        w >>= 8;
    }

    if (little_endian) {
        std::reverse(bytes.begin(), bytes.end());
    }
}

template<>
void mpz<uint8_t>::get_bytes(phantom_vector<uint8_t>& bytes, bool little_endian) const
{
    if (this->is_zero()) {
        bytes.resize(1);
        bytes[0] = 0;
        return;
    }

    size_t n = m_limbs.size();
    bytes.resize(n);

    std::copy(m_limbs.begin(), m_limbs.begin() + n, bytes.begin());
    if (little_endian) {
        std::reverse(bytes.begin(), bytes.end());
    }
}

template<typename T>
void mpz<T>::set_bytes(const phantom_vector<uint8_t>& bytes, bool little_endian)
{
    m_limbs.resize((8 * bytes.size() + std::numeric_limits<T>::digits - 1) >> bits_log2<T>::value());

    T mask = (1 << (bits_log2<T>::value() - 3)) - 1;
    T w = 0;
    if (little_endian) {
        for (size_t i=0; i < bytes.size(); i++) {
            w |= (static_cast<T>(bytes[bytes.size() - 1 - i])) << 8*(i & mask);
            if (mask == (i & mask)) {
                m_limbs[i >> (bits_log2<T>::value() - 3)] = w;
                w = 0;
            }
        }
    }
    else {
        for (size_t i=0; i < bytes.size(); i++) {
            w |= (static_cast<T>(bytes[i])) << 8*(i & mask);
            if (mask == (i & mask)) {
                m_limbs[i >> (bits_log2<T>::value() - 3)] = w;
                w = 0;
            }
        }
    }
    if (bytes.size() & mask) {
        m_limbs[bytes.size() >> (bits_log2<T>::value() - 3)] = w;
    }

    size_t size = mpbase<T>::normalized_size(m_limbs.data(), m_limbs.size());
    m_limbs.resize(size);

    m_sign = false;
}

template<typename T>
void mpz<T>::get_words(phantom_vector<T>& words) const
{
    if (this->is_zero()) {
        words.resize(1);
        words[0] = 0;
        return;
    }

    words = phantom_vector<T>(m_limbs);
}

template<typename T>
void mpz<T>::set_words(const phantom_vector<T>& words)
{
    m_limbs = phantom_vector<T>(words);

    auto used = mpbase<T>::normalized_size(m_limbs.data(), m_limbs.size());
    m_limbs.resize(used);
    m_sign = false;
}

template<typename T>
void mpz<T>::set_words(const phantom_vector<T>& words, size_t n)
{
    m_limbs = phantom_vector<T>(words.begin(), words.begin() + n);

    auto used = mpbase<T>::normalized_size(m_limbs.data(), n);
    m_limbs.resize(used);
    m_sign = false;
}

template<typename T>
std::string mpz<T>::get_str(size_t base, bool uppercase) const
{
    return limbstring<T>::get_str(*this, base, uppercase);
}

template<typename T>
const phantom_vector<T>& mpz<T>::get_limbs() const
{
    return m_limbs;
}

template<typename T>
phantom_vector<T>& mpz<T>::get_limbs()
{
    return m_limbs;
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
