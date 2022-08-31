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
#include <string>
#include <vector>

#include "core/mpbase.hpp"
#include "core/mp.hpp"
#include "core/mpz.hpp"
#include "core/gf2n.hpp"
#include "core/template_helpers.hpp"


namespace phantom {
namespace core {

/** 
 * @brief Template class for multiple-precision Galois Field arithmetic
 * 
 * GF(2^n) finite field arithmetic methods derived from mp class
 */
template<typename T>
class mp_gf2n : public mp<T>
{
    static_assert(std::is_same<T, uint8_t>::value  ||
                    std::is_same<T, uint16_t>::value ||
                    std::is_same<T, uint32_t>::value ||
                    std::is_same<T, uint64_t>::value,
            "number instantiated with unsupported type");

    using S = signed_type_t<T>;

    phantom_vector<T> m_poly;
    phantom_vector<T> m_modulus;
    std::vector<int> m_mod_bits;


public:
    /// Constructors
    /// @{

    // Default constructor
    mp_gf2n()
    {
        // Initialise to zero
        m_poly = phantom_vector<T>();
        m_modulus = phantom_vector<T>();
        m_mod_bits = std::vector<int>();
    }

    // Copy constructor with mpz modulus
    mp_gf2n(const mpz<T>& mod)  // NOLINT
    {
        // Initialise to zero
        m_poly = phantom_vector<T>();
        m_modulus = mod.get_limbs();
        m_mod_bits = std::vector<int>();
        compute_mod_bits(m_modulus, m_mod_bits);
    }

    // Copy constructor with vector modulus
    mp_gf2n(const phantom_vector<T>& mod)  // NOLINT
    {
        // Initialise to zero
        m_poly = phantom_vector<T>();
        m_modulus = mod;
        m_mod_bits = std::vector<int>();
        compute_mod_bits(m_modulus, m_mod_bits);
    }

    // Copy constructor from vector type with modulus
    mp_gf2n(const phantom_vector<T>& in, const phantom_vector<T>& mod)
    {
        // Initialise to zero
        m_poly = in;
        m_modulus = mod;
        m_mod_bits = std::vector<int>();
        compute_mod_bits(m_modulus, m_mod_bits);
    }

    // Copy constructor from mpz type with modulus
    mp_gf2n(const mpz<T>& in, const mpz<T>& mod)
    {
        // Initialise to zero
        m_poly = in.get_limbs();
        m_modulus = mod.get_limbs();
        m_mod_bits = std::vector<int>();
        compute_mod_bits(m_modulus, m_mod_bits);
    }

    /// Copy constructor from base type
    mp_gf2n(const mp<T>& obj)  // NOLINT
    {
        auto local = dynamic_cast<const mp_gf2n&>(obj);
        m_poly = local.m_poly;
        m_modulus = local.m_modulus;
        m_mod_bits = local.m_mod_bits;
    }

    /// Copy constructor
    mp_gf2n(const mp_gf2n& obj)
    {
        m_poly = obj.m_poly;
        m_modulus = obj.m_modulus;
        m_mod_bits = obj.m_mod_bits;
    }

    // Copy constructor from strings
    mp_gf2n(const char* p, const char* m, size_t base)
    {
        bool dummy;
        limbstring<T>::set_str(m_poly, dummy, p, base);
        limbstring<T>::set_str(m_modulus, dummy, m, base);
        m_mod_bits = std::vector<int>();
        compute_mod_bits(m_modulus, m_mod_bits);
    }

    // Copy constructor from single linb with vector modulus
    mp_gf2n(T rhs, const phantom_vector<T>& mod)
    {
        // Initialise to zero
        m_poly = phantom_vector<T>(1);
        m_poly[0] = rhs;
        m_modulus = mod;
        m_mod_bits = std::vector<int>();
        compute_mod_bits(m_modulus, m_mod_bits);
    }

    mp_gf2n& operator=(const mp_gf2n& rhs)
    {
        mp_gf2n local(rhs);
        m_poly = local.m_poly;
        m_modulus = local.m_modulus;
        m_mod_bits = local.m_mod_bits;
        return *this;
    }

    mp_gf2n& operator=(T rhs)
    {
        m_poly = phantom_vector<T>(1);
        m_poly[0] = rhs;
        m_modulus = phantom_vector<T>();
        m_mod_bits = std::vector<int>();
        return *this;
    }

    mp_gf2n& operator=(S rhs)
    {
        m_poly = phantom_vector<T>(1);
        m_poly[0] = rhs;
        m_modulus = phantom_vector<T>();
        m_mod_bits = std::vector<int>();
        return *this;
    }

    mp_gf2n& operator=(double rhs)
    {
        m_poly = phantom_vector<T>(1);
        m_poly[0] = rhs;
        m_modulus = phantom_vector<T>();
        m_mod_bits = std::vector<int>();
        return *this;
    }

    mp_gf2n& set(const mp_gf2n& obj)
    {
        m_poly = obj.m_poly;
        m_modulus = obj.m_modulus;
        m_mod_bits = obj.m_mod_bits;
        return *this;
    }

    /// @}


    /// Destructor
    /// @{

    /// Default destructor
    virtual ~mp_gf2n()
    {
    }

    /// @}



    /// Basic control methods
    /// @{

    // Calculate the bit position of each asserted bit of the modulus polynomial
    static void compute_mod_bits(const phantom_vector<T>& modulus, std::vector<int>& mod_bits)
    {
        mod_bits = std::vector<int>();

        if (0 == modulus.size()) {
            return;
        }

        for (int i = static_cast<int>(modulus.size()) - 1; i >= 0; i--) {
            if (!modulus[i]) {
                continue;
            }

            T mask = LIMB_HIGHBIT;

            for (int j = std::numeric_limits<T>::digits - 1; j >= 0; j--) {
                if (modulus[i] & mask) {
                    mod_bits.push_back(std::numeric_limits<T>::digits * i + j);
                }
                mask >>= 1;
            }
        }
    }

    const std::vector<int>& get_mod_bits() const
    {
        return m_mod_bits;
    }

    /// Return a flag indicating that the mp_gf2n object is zero
    virtual bool is_zero() const
    {
        return 0 == m_poly.size();
    }

    /// Return a flag indicating that the mp_gf2n object is one
    virtual bool is_one() const
    {
        return 1 == m_poly.size() && 1 == m_poly[0];
    }

    // Return a flag indicating that the mp_gf2n is odd
    virtual bool is_odd() const
    {
        if (is_zero()) {
            return false;
        }
        return m_poly[0] & 1;
    }

    /// Return a flag indicating that the mp_gf2n object is negative
    virtual bool is_negative() const
    {
        return false;
    }

    /// Set the sign flag to the defined value
    virtual void set_sign(bool sign)
    {
    }

    // Memory pre-allocation and value set to zero
    virtual void zero_init(size_t n)
    {
        m_poly = phantom_vector<T>(n);
    }

    // Convert to a vector of bytes with selectable endianness (default: big-endian)
    virtual void get_bytes(phantom_vector<uint8_t>& bytes, bool little_endian = false) const
    {
        size_t num_bytes = std::numeric_limits<T>::digits >> 3;
        size_t n         = (this->sizeinbase(2) + 7) >> 3;

        if (this->is_zero()) {
            bytes.resize(1);
            bytes[0] = 0;
            return;
        }

        bytes.resize(n);

        T mask = static_cast<T>(num_bytes) - 1;
        T w = 0;
        for (size_t i=0; i < n; i++) {
            if (0 == (i & mask)) {
                w = m_poly[i >> (bits_log2<T>::value() - 3)];
            }

            bytes[i] = w & 0xff;
            w >>= 8;
        }

        if (little_endian) {
            std::reverse(bytes.begin(), bytes.end());
        }
    }

    // Set the polynomial using a vector of bytes with selectable endianness (default: big-endian)
    virtual void set_bytes(const phantom_vector<uint8_t>& bytes, bool little_endian = false)
    {
        m_poly.resize((8 * bytes.size() + std::numeric_limits<T>::digits - 1) >> bits_log2<T>::value());

        T mask = (1 << (bits_log2<T>::value() - 3)) - 1;
        T w = 0;
        if (little_endian) {
            for (size_t i=0; i < bytes.size(); i++) {
                w |= (static_cast<T>(bytes[bytes.size() - 1 - i])) << 8*(i & mask);
                if (mask == (i & mask)) {
                    m_poly[i >> (bits_log2<T>::value() - 3)] = w;
                    w = 0;
                }
            }
        }
        else {
            for (size_t i=0; i < bytes.size(); i++) {
                w |= (static_cast<T>(bytes[i])) << 8*(i & mask);
                if (mask == (i & mask)) {
                    m_poly[i >> (bits_log2<T>::value() - 3)] = w;
                    w = 0;
                }
            }
        }

        if (bytes.size() & mask) {
            m_poly[bytes.size() >> (bits_log2<T>::value() - 3)] = w;
        }

        size_t size = mpbase<T>::normalized_size(m_poly.data(), m_poly.size());
        m_poly.resize(size);
    }

    // Calculate the integer size in bits of the mpz object given a specific base
    virtual size_t sizeinbase(size_t base) const
    {
        return mpz_core<T>::sizeinbase(m_poly.data(), m_poly.size(), base);
    }

    /// Swap the mpz pbjects
    virtual void swap(mp<T>& in)  // NOLINT
    {
        m_poly.swap(in.get_limbs());
    }

    /// Return the number of limb words used by the mpz object
    virtual size_t get_limbsize() const
    {
        return m_poly.size();
    }

    // Return the vector of T limbs defining the polynomial
    virtual const phantom_vector<T>& get_limbs() const
    {
        return m_poly;
    }

    // Return the vector of T limbs defining the polynomial
    virtual phantom_vector<T>& get_limbs()
    {
        return m_poly;
    }

    // Return a string describing the polynomial in the selected base
    virtual std::string get_str(size_t base, bool uppercase = false) const
    {
        mpz<T> temp;
        temp.set_words(m_poly);
        return limbstring<T>::get_str(temp, base, uppercase);
    }

    // Return the limb at the selected index
    const T operator[](size_t index) const
    {
        return m_poly[index];
    }

    // Return a reference to the limb at the selected index
    T& operator[](size_t index)
    {
        return m_poly[index];
    }

    /// @}



    /// Comparative operations
    /// @{

    bool operator==(const mp_gf2n& rhs)
    {
        return 0 == this->cmp(rhs);
    }

    bool operator==(T rhs)
    {
        return 0 == this->cmp_ui(rhs);
    }

    bool operator==(S rhs)
    {
        return 0 == this->cmp_si(rhs);
    }

    bool operator==(double rhs)
    {
        return 0 == this->cmp_d(rhs);
    }

    bool operator!=(const mp_gf2n& rhs)
    {
        return 0 != this->cmp(rhs);
    }

    bool operator!=(T rhs)
    {
        return 0 != this->cmp_ui(rhs);
    }

    bool operator!=(S rhs)
    {
        return 0 != this->cmp_si(rhs);
    }

    bool operator!=(double rhs)
    {
        return 0 != this->cmp_d(rhs);
    }

    bool operator<=(const mp_gf2n& rhs)
    {
        return 1 != this->cmp(rhs);
    }

    bool operator<=(T rhs)
    {
        return 1 != this->cmp_ui(rhs);
    }

    bool operator<=(S rhs)
    {
        return 1 != this->cmp_si(rhs);
    }

    bool operator<=(double rhs)
    {
        return 1 != this->cmp_d(rhs);
    }

    bool operator<(const mp_gf2n& rhs)
    {
        return -1 == this->cmp(rhs);
    }

    bool operator<(T rhs)
    {
        return -1 == this->cmp_ui(rhs);
    }

    bool operator<(S rhs)
    {
        return -1 == this->cmp_si(rhs);
    }

    bool operator<(double rhs)
    {
        return -1 == this->cmp_d(rhs);
    }

    bool operator>=(const mp_gf2n& rhs)
    {
        return -1 != this->cmp(rhs);
    }

    bool operator>=(T rhs)
    {
        return -1 != this->cmp_ui(rhs);
    }

    bool operator>=(S rhs)
    {
        return -1 != this->cmp_si(rhs);
    }

    bool operator>=(double rhs)
    {
        return -1 != this->cmp_d(rhs);
    }

    bool operator>(const mp_gf2n& rhs)
    {
        return 1 == this->cmp(rhs);
    }

    bool operator>(T rhs)
    {
        return 1 == this->cmp_ui(rhs);
    }

    bool operator>(S rhs)
    {
        return 1 == this->cmp_si(rhs);
    }

    bool operator>(double rhs)
    {
        return 1 == this->cmp_d(rhs);
    }

    friend bool operator==(const mp_gf2n& lhs, const mp_gf2n& rhs)
    {
        return 0 == lhs.cmp(rhs);
    }

    friend bool operator==(const mp_gf2n& lhs, T rhs)
    {
        return 0 == lhs.cmp_ui(rhs);
    }

    friend bool operator==(const mp_gf2n& lhs, S rhs)
    {
        return 0 == lhs.cmp_si(rhs);
    }

    friend bool operator==(const mp_gf2n& lhs, double rhs)
    {
        return 0 == lhs.cmp_d(rhs);
    }

    friend bool operator!=(const mp_gf2n& lhs, const mp_gf2n& rhs)
    {
        return 0 != lhs.cmp(rhs);
    }

    friend bool operator!=(const mp_gf2n& lhs, T rhs)
    {
        return 0 != lhs.cmp_ui(rhs);
    }

    friend bool operator!=(const mp_gf2n& lhs, S rhs)
    {
        return 0 != lhs.cmp_si(rhs);
    }

    friend bool operator!=(const mp_gf2n& lhs, double rhs)
    {
        return 0 != lhs.cmp_d(rhs);
    }

    friend bool operator<=(const mp_gf2n& lhs, const mp_gf2n& rhs)
    {
        return 1 != lhs.cmp(rhs);
    }

    friend bool operator<=(const mp_gf2n& lhs, T rhs)
    {
        return 1 != lhs.cmp_ui(rhs);
    }

    friend bool operator<=(const mp_gf2n& lhs, S rhs)
    {
        return 1 != lhs.cmp_si(rhs);
    }

    friend bool operator<=(const mp_gf2n& lhs, double rhs)
    {
        return 1 != lhs.cmp_d(rhs);
    }

    friend bool operator<(const mp_gf2n& lhs, const mp_gf2n& rhs)
    {
        return -1 == lhs.cmp(rhs);
    }

    friend bool operator<(const mp_gf2n& lhs, T rhs)
    {
        return -1 == lhs.cmp_ui(rhs);
    }

    friend bool operator<(const mp_gf2n& lhs, S rhs)
    {
        return -1 == lhs.cmp_si(rhs);
    }

    friend bool operator<(const mp_gf2n& lhs, double rhs)
    {
        return -1 == lhs.cmp_d(rhs);
    }

    friend bool operator>=(const mp_gf2n& lhs, const mp_gf2n& rhs)
    {
        return -1 != lhs.cmp(rhs);
    }

    friend bool operator>=(const mp_gf2n& lhs, T rhs)
    {
        return -1 != lhs.cmp_ui(rhs);
    }

    friend bool operator>=(const mp_gf2n& lhs, S rhs)
    {
        return -1 != lhs.cmp_si(rhs);
    }

    friend bool operator>=(const mp_gf2n& lhs, double rhs)
    {
        return -1 != lhs.cmp_d(rhs);
    }

    friend bool operator>(const mp_gf2n& lhs, const mp_gf2n& rhs)
    {
        return 1 == lhs.cmp(rhs);
    }

    friend bool operator>(const mp_gf2n& lhs, T rhs)
    {
        return 1 == lhs.cmp_ui(rhs);
    }

    friend bool operator>(const mp_gf2n& lhs, S rhs)
    {
        return 1 == lhs.cmp_si(rhs);
    }

    friend bool operator>(const mp_gf2n& lhs, double rhs)
    {
        return 1 == lhs.cmp_d(rhs);
    }

    /// Compare two mp_gf2n objects (using references to base class objects)
    virtual int32_t cmp(const mp<T>& in) const
    {
        // Use the 'used' parameter to quickly compare multiple precision polynomials of
        // different lengths, otherwise if they are both positive numbers of equal length they are
        // simply compared. If both numbers are negative and equal length then they are compared as
        // asbsolute values with the result inverted to account for the sign change.
        int in1_used = static_cast<int>(m_poly.size());
        int in2_used = static_cast<int>(in.get_limbsize());
        if (in1_used < in2_used) {
            return -1;
        }
        else if (in1_used > in2_used) {
            return 1;
        }

        // Obtain a reference to the limb vector
        auto in_limbs = const_cast<phantom_vector<T>&>(in.get_limbs());

        // Compare the two multiple precision signed limb arrays
        if (in1_used >= 0) {
            return mpbase<T>::cmp(m_poly.data(), in_limbs.data(), in1_used);
        }
        else {
            return mpbase<T>::cmp(in_limbs.data(), m_poly.data(), -in1_used);
        }
    }

    /// Compare to a single word polynomial
    virtual int32_t cmp_ui(T in) const
    {
        if (0 == m_poly.size()) {
            // lhs is zero, so do a simple comparison of zero to rhs
            return (0 == in)? 0 : -1;
        }
        else if (m_poly.size() > 1) {
            // lhs is a multiple precision positive integer, so it is larger than
            return 1;
        }
        else {
            // Both the rhs and lhs are non-zero single precision positive integers
            return (m_poly[0] > in) - (m_poly[0] < in);
        }
    }

    /// Compare to a single word polynomial
    virtual int32_t cmp_si(S in) const
    {
        if (0 == m_poly.size()) {
            // lhs is zero, so do a simple comparison of zero to rhs
            return (0 == in)? 0 : (in < 0)? 1 : -1;
        }
        else if (1 < m_poly.size()) {
            // If this is a multiple-precision negative integer it must be less than rhs
            return -1;
        }
        else if (in >= 0) {
            // rhs and lhs are both non-negative, use the unsigned integer routine to compare
            return cmp_ui(in);
        }
        else {
            // rhs is negative and lhs is positive then the result must be greater than
            return 1;
        }
    }

    /// Compare two mp_gf2n objects in terms of the absolute magnitude
    virtual int32_t cmpabs(const mp<T>& in) const
    {
        // Compare the two limb arrays which are stored in an absolute format
        return mpbase<T>::cmp_n(m_poly.data(), m_poly.size(), in.get_limbs().data(), in.get_limbs().size());
    }

    /// @}



    /// Bit shifting operations
    /// @{

    mp_gf2n operator<<(int bits) const
    {
        mp_gf2n out;
        lshift(out.m_poly, this->m_poly, bits);
        return out;
    }

    mp_gf2n& operator<<(int bits)
    {
        phantom_vector<T> in = this->m_poly;
        lshift(this->m_poly, in, bits);
        return *this;
    }

    mp_gf2n& operator<<=(int bits)
    {
        phantom_vector<T> in = this->m_poly;
        lshift(this->m_poly, in, bits);
        return *this;
    }

    mp_gf2n operator>>(int bits) const
    {
        mp_gf2n out;
        rshift(out.m_poly, this->m_poly, bits);
        return out;
    }

    mp_gf2n& operator>>(int bits)
    {
        phantom_vector<T> in = this->m_poly;
        rshift(m_poly, in, bits);
        return *this;
    }

    mp_gf2n& operator>>=(int bits)
    {
        phantom_vector<T> in = this->m_poly;
        rshift(m_poly, in, bits);
        return *this;
    }

    /// Bitwise left shift of an mpz integer
    static void lshift(phantom_vector<T>& out, const phantom_vector<T>& in1, const int bits)
    {
        if (0 == bits) {
            out = in1;
            return;
        }

        size_t in_used = in1.size();
        if (0 == in_used) {
            out.resize(0);
            return;
        }

        // Determine the number of words and bits to shift
        size_t sh_words = bits >> bits_log2<T>::value();              // Divide by limb bits
        T      sh_bits  = bits & ((1 << bits_log2<T>::value()) - 1);  // Modulo 2 ^ limb bits

        // The output length will be incremented by (bits + limb bits - 1) / limb bits,
        // so resize the limbs array appropriately
        size_t out_used = in_used + sh_words;
        out.resize(out_used);

        if (sh_bits > 0) {
            // If sh_bits is non-zero bits must be shifted between limbs
            T cc = mpbase<T>::lshift(out.data() + sh_words, in1.data(), in_used, sh_bits);
            if (cc) {
                out.push_back(cc);
            }
        }
        else {
            // sh_bits is zero therefore a copy is sufficient to perform the shift
            mpbase<T>::copy(out.data() + sh_words, in1.data(), in_used);
        }

        // The least significant words of the output must be zeroed
        mpbase<T>::zero(out.data(), sh_words);

        out_used = mpbase<T>::normalized_size(out.data(), out.size());
        out.resize(out_used);

        return;
    }

    /// Bitwise right shift of an mpz integer
    static void rshift(phantom_vector<T>& out, const phantom_vector<T>& in1, const int bits)
    {
        if (0 == bits) {
            out = in1;
            return;
        }

        int in_used = static_cast<int>(in1.size());
        if (0 == in_used || (bits >= (in_used * std::numeric_limits<T>::digits))) {
            out.resize(0);
            return;
        }

        // Determine the number of words and bits to shift
        size_t sh_words = bits >> bits_log2<T>::value();              // Divide by limb bits
        T      sh_bits  = bits & ((1 << bits_log2<T>::value()) - 1);  // Modulo 2 ^ limb bits

        size_t out_used = in_used - sh_words;
        out.resize(out_used);

        if (sh_bits > 0) {
            // If sh_bits is non-zero bits must be shifted between limbs
            mpbase<T>::rshift(out.data(), in1.data() + sh_words, in_used - sh_words, sh_bits);
        }
        else {
            // sh_bits is zero therefore a copy is sufficient to perform the shift
            mpbase<T>::copy(out.data(), in1.data() + sh_words, in_used - sh_words);  // NOLINT
            mpbase<T>::zero(out.data() + in_used - sh_words, sh_words);
        }

        out_used = mpbase<T>::normalized_size(out.data(), out.size());
        out.resize(out_used);

        return;
    }

    /// @}



    /// Bitwise AND of the two mp_gf2n objects
    /// @{

    mp_gf2n operator&(const mp_gf2n& d) const
    {
        mp_gf2n out(this->m_modulus);
        out.bitwise_and(*this, d);
        return out;
    }

    T operator&(const T rhs) const
    {
        if (0 == this->get_limbsize()) {
            return T(0);
        }
        return this->get_limbs()[0] & rhs;
    }

    mp_gf2n& operator&=(const mp_gf2n& d)
    {
        mp_gf2n in = *this;
        this->bitwise_and(in, d);
        return *this;
    }

    void bitwise_and(const mp<T>& in1, const mp<T>& in2)
    {
        auto in1_int = static_cast<const mp_gf2n<T>&>(in1);
        auto in2_int = static_cast<const mp_gf2n<T>&>(in2);

        // If either argument is zero the result is zero
        auto in1_size = in1.m_poly.get_limbsize();
        auto in2_size = in2.m_poly.get_limbsize();
        if (0 == in1_size || 0 == in2_size) {
            m_poly = 0;
            return;
        }

        // Iterate over all shared limbs and perform a bitwise AND
        size_t min_size = (in1_size < in2_size)? in1_size : in2_size;
        m_poly.zero_init(min_size);
        for (size_t i=0; i < min_size; i++) {
            m_poly[i] = in1_int[i] & in2_int[i];
        }
        m_poly.m_sign  = false;
    }

    /// @}



    /// Exclusive-OR of the two mp_gf2n objects
    /// @{

    mp_gf2n operator^(const mp_gf2n& d) const
    {
        mp_gf2n out(this->m_modulus);
        bitwise_xor(out, *this, d);
        return out;
    }

    mp_gf2n operator+(const mp_gf2n& d) const
    {
        mp_gf2n out(this->m_modulus);
        bitwise_xor(out, *this, d);
        return out;
    }

    mp_gf2n operator-(const mp_gf2n& d) const
    {
        mp_gf2n out(this->m_modulus);
        bitwise_xor(out, *this, d);
        return out;
    }

    mp_gf2n& operator^=(const mp_gf2n& d)
    {
        mp_gf2n in(*this);
        bitwise_xor(*this, in, d);
        return *this;
    }

    mp_gf2n& operator+=(const mp_gf2n& d)
    {
        mp_gf2n in(*this);
        bitwise_xor(*this, in, d);
        return *this;
    }

    mp_gf2n& operator-=(const mp_gf2n& d)
    {
        mp_gf2n in(*this);
        bitwise_xor(*this, in, d);
        return *this;
    }

    friend mp_gf2n operator^(const mp_gf2n& lhs, const mp_gf2n& rhs)
    {
        mp_gf2n local(lhs.m_modulus);
        local.bitwise_xor(lhs, rhs);
        return local;
    }

    static void bitwise_xor(mp_gf2n<T>& out, const mp_gf2n<T>& in1, const mp_gf2n<T>& in2)
    {
        // If either argument is zero the result is the opposing argument
        auto in1_size = in1.m_poly.size();
        auto in2_size = in2.m_poly.size();
        if (0 == in1_size) {
            out = in2;
            return;
        }
        if (0 == in2_size) {
            out = in1;
            return;
        }

        size_t min_size = (in1_size < in2_size)? in1_size : in2_size;
        const auto& a = (in1_size < in2_size)? in2.get_limbs() : in1.get_limbs();
        const auto& b = (in1_size < in2_size)? in1.get_limbs() : in2.get_limbs();

        out.m_poly = phantom_vector<T>(a.begin(), a.end());

        // Iterate over all shared limbs and perform a bitwise XOR
        for (size_t i=0; i < min_size; i++) {
            out.m_poly[i] ^= b[i];
        }

        in1_size = mpbase<T>::normalized_size(out.m_poly.data(), out.m_poly.size());
        out.m_poly.resize(in1_size);
    }

    /// Add an mp_gf2n object and reduce
    mp_gf2n<T>& add(const mp_gf2n<T>& in2)
    {
        mp_gf2n in(*this);
        bitwise_xor(*this, in, in2);
        return *this;
    }

    /// Subtract an mp_gf2n object and reduce
    mp_gf2n<T>& sub(const mp_gf2n<T>& in2)
    {
        mp_gf2n in(*this);
        bitwise_xor(*this, in, in2);
        return *this;
    }

    /// @}


    /// Multiply two mp_gf2n objects
    /// @{

    mp_gf2n operator*(const mp_gf2n& d) const
    {
        mp_gf2n out(this->m_modulus);
        gf2n<T>::mod_mul_arr(out.m_poly, this->m_poly, d.m_poly, m_mod_bits);
        return out;
    }

    mp_gf2n operator*=(const mp_gf2n& d) const
    {
        mp_gf2n out(this->m_modulus);
        gf2n<T>::mod_mul_arr(out.m_poly, this->m_poly, d.m_poly, m_mod_bits);
        return out;
    }

    mp_gf2n& operator*(const mp_gf2n& d)
    {
        mp_gf2n in(*this);
        gf2n<T>::mod_mul_arr(this->m_poly, in.m_poly, d.m_poly, m_mod_bits);
        return *this;
    }

    mp_gf2n& operator*=(const mp_gf2n& d)
    {
        mp_gf2n in(*this);
        gf2n<T>::mod_mul_arr(this->m_poly, in.m_poly, d.m_poly, m_mod_bits);
        return *this;
    }

    mp_gf2n<T>& mul(const mp<T>& in2)
    {
        const mp_gf2n<T>& gf2n_in2 = static_cast<const mp_gf2n<T>>(in2);
        mp_gf2n in1(*this);
        gf2n<T>::mod_mul_arr(this->m_poly, in1.m_poly, gf2n_in2.m_poly, m_mod_bits);
        return *this;
    }

    mp_gf2n<T>& square()
    {
        mp_gf2n in1(*this);
        gf2n<T>::mod_sqr_arr(this->m_poly, in1.m_poly, m_mod_bits);
        return *this;
    }

    /// @}


    /// Division of an mp_gf2n object
    /// @{

    mp_gf2n operator/(const mp_gf2n& d) const
    {
        mp_gf2n out(this->m_modulus);
        div(out, *this, d);
        return out;
    }

    static void div(mp_gf2n<T>& out, const mp<T>& dividend, const mp<T>& divisor)
    {
        auto n_gf2n = static_cast<const mp_gf2n<T>&>(dividend);
        auto d_gf2n = static_cast<const mp_gf2n<T>&>(divisor);

        // Calculate the modular inverse of the divisor
        inv_mod(out, d_gf2n);

        // Multiply the dividend by 1/divisor
        out *= n_gf2n;
    }

    static void mod(mp_gf2n<T>& r, const mp_gf2n<T>& a, const std::vector<int>& mod_bits)
    {
        size_t a_size = a.get_limbsize();
        if (!(0 == a_size || (0 != a_size && 0 != a[a_size-1]))) {
            throw std::runtime_error("a is invalid");
        }

        if (0 == mod_bits[0]) {
            r = T(0);
            return;
        }

        size_t max_index = mod_bits[0] >> bits_log2<T>::value();

        r = a;
        r.m_poly.resize(max_index + 1);

        int n, d0, d1;
        size_t i;
        for (i = a_size - 1; i > max_index; ) {
            T zz = r[i];
            if (0 == r[i]) {
                i--;
                continue;
            }
            r[i] = T(0);

            std::vector<int>::const_iterator cit = mod_bits.cbegin();
            cit++;
            while (cit != mod_bits.cend()) {
                /* reducing component t^p[k] */
                n  = mod_bits[0] - *cit;
                d0 = n & ((1 << bits_log2<T>::value()) - 1);
                d1 = std::numeric_limits<T>::digits - d0;
                n >>= bits_log2<T>::value();
                r[i - n] ^= T(zz >> d0);
                if (d0) {
                    r[i - n - 1] ^= (zz << d1);
                }

                cit++;
            }

            /* reducing component t^0 */
            n  = max_index;
            d0 = mod_bits[0] & ((1 << bits_log2<T>::value()) - 1);
            d1 = std::numeric_limits<T>::digits - d0;
            r[i - n] ^= (zz >> d0);
            if (d0) {
                r[i - n - 1] ^= (zz << d1);
            }
        }

        /* final round of reduction */
        while (i == max_index) {

            d0 = mod_bits[0] & ((1 << bits_log2<T>::value()) - 1);
            T zz = r[max_index] >> d0;
            if (0 == zz) {
                break;
            }
            d1 = std::numeric_limits<T>::digits - d0;

            /* clear up the top d1 bits */
            if (d0) {
                r[max_index] = (r[max_index] << d1) >> d1;
            }
            else {
                r[max_index] = 0;
            }
            r[0] ^= zz;             /* reduction t^0 component */

            std::vector<int>::const_iterator cit = mod_bits.cbegin();
            cit++;

            while (cit != mod_bits.cend()) {
                T tmp_ulong;

                /* reducing component t^p[k] */
                n  = *cit >> bits_log2<T>::value();
                d0 = *cit & ((1 << bits_log2<T>::value()) - 1);
                d1 = std::numeric_limits<T>::digits - d0;
                r[n] ^= (zz << d0);
                if (d0 && (tmp_ulong = zz >> d1)) {
                    r[n + 1] ^= tmp_ulong;
                }

                cit++;
            }
        }
    }

    static bool invert(mp_gf2n& out, const mp_gf2n& in)
    {
        try {
            inv_mod(out, in);
            return true;
        }
        catch (const std::exception& e) {
            return false;
        }

    }

    static void inv_mod(mp_gf2n<T>& inv, const mp_gf2n<T>& a)
    {
        if (a.is_zero()) {
            throw std::runtime_error("a is zero");
        }

        mp_gf2n<T> b(T(1), a.m_modulus), c(a.m_modulus), u(a.m_modulus),
            v(a.m_modulus, a.m_modulus), m(a.m_modulus, a.m_modulus);

        gf2n<T>::mod_arr(u.m_poly, a.m_poly, a.get_mod_bits());

        mp_gf2n<T>* pb = &b;
        mp_gf2n<T>* pc = &c;
        mp_gf2n<T>* pu = &u;
        mp_gf2n<T>* pv = &v;

        while (1) {
            while (!pu->is_odd()) {
                if (pu->is_zero()) {
                    throw std::runtime_error("u is zero");
                }
                *pu >>= 1;

                if (pb->is_odd()) {
                    *pb += m;
                }
                *pb >>= 1;
            }

            if (1 == pu->get_limbsize() && 1 == (*pu)[0]) {
                break;
            }

            if (pu->sizeinbase(2) < pv->sizeinbase(2)) {
                mp_gf2n<T>* t;
                t = pu;
                pu = pv;
                pv = t;
                t = pb;
                pb = pc;
                pc = t;
            }

            *pu += *pv;
            *pb += *pc;
        }

        inv = *pb;
    }

    /// @}

};

}  // namespace core
}  // namespace phantom
