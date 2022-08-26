/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <algorithm>
#include <cstdint>
#include <cmath>
#include <iomanip>
#include <limits>
#include <string>
#include <vector>

#include "core/limbstring.hpp"
#include "crypto/csprng.hpp"
#include "core/mp.hpp"
#include "core/mpz_core.hpp"
#include "core/small_primes.hpp"
#include "core/template_helpers.hpp"


namespace phantom {
namespace core {

template<typename T>
class mpz;

template<typename T>
class mp_gf2n;

/** 
 * @brief Multiple Precision integer class
 * 
 * Arithmetic for multiple-precision integers
 */
template<typename T>
class mpz : public mp<T>
{
    static_assert(std::is_same<T, uint8_t>::value  ||
                  std::is_same<T, uint16_t>::value ||
                  std::is_same<T, uint32_t>::value ||
                  std::is_same<T, uint64_t>::value,
                  "number instantiated with unsupported type");

    using S = signed_type_t<T>;

    phantom_vector<T> m_limbs;
    phantom_vector<T> m_scratch;
    bool m_sign;

    friend class mp_gf2n<T>;


public:
    /// Constructors
    /// @{

    // Default constructor
    mpz();

    /// Copy constructor from base type
    mpz(const mp<T> &obj);  // NOLINT

    /// Copy constructor
    mpz(const mpz &obj);

    /// Constructor with initialization from a vector
    mpz(const phantom_vector<T> &vec, bool sign);

    /// Copy an object and return a reference
    mpz &set(const mpz &obj);

    /// A static clone method
    static mpz clone(const mpz &obj);

    /// Constructor with raw byte array initialization
    mpz(uint8_t *data, size_t n);

    /// Constructor that initializes from an unsigned integer
    mpz(T data);  // NOLINT

    /// Constructor that initializes from an signed integer
    mpz(S data);  // NOLINT

    /// Constructor that initializes from a double
    mpz(double data);  // NOLINT

    /// Constructor that initializes from a c-string
    mpz(const char *str, size_t base);

    /// @}


    /// Destructor
    /// @{

    /// Default destructor
    virtual ~mpz()
    {
    }

    /// @}


    /// Operator overloading
    /// @{

    operator double() const;
    operator float() const;
    operator uint8_t() const;
    operator uint16_t() const;
    operator uint32_t() const;
    operator uint64_t() const;
    operator int8_t() const;
    operator int16_t() const;
    operator int32_t() const;
    operator int64_t() const;

    const T operator[](size_t index) const;
    T &operator[](size_t index);
    mpz &operator+=(const mpz &rhs);
    mpz &operator+=(T rhs);
    mpz operator+(const mpz &rhs) const;
    mpz operator+(T rhs) const;
    mpz operator+(S rhs) const;
    mpz &operator++();
    mpz operator++(int);
    mpz &operator-=(const mpz &rhs);
    mpz &operator-=(T rhs);
    mpz operator-(const mpz &rhs) const;
    mpz operator-(T rhs) const;
    mpz operator-(S rhs) const;
    mpz &operator--();
    mpz operator--(int);
    mpz operator-() const;
    mpz operator*(const mpz &rhs) const;
    mpz operator*(T rhs) const;
    mpz operator*(S rhs) const;
    mpz operator*(double rhs) const;
    mpz operator/(const mpz &d) const;
    mpz operator/(T d) const;
    mpz operator%(const mpz &d) const;
    mpz operator%(T d) const;
    mpz operator&(const mpz &d) const;
    mpz &operator&=(const mpz &d);
    mpz operator|(const mpz &d) const;
    mpz &operator|=(const mpz &d);
    mpz operator^(const mpz &d) const;
    mpz &operator^=(const mpz &d);
    mpz operator<<(int bits) const;
    mpz &operator<<(int bits);
    mpz &operator<<=(int bits);
    mpz operator>>(int bits) const;
    mpz &operator>>(int bits);
    mpz &operator>>=(int bits);
    mpz &operator=(const mpz &rhs);
    mpz &operator=(T rhs);
    mpz &operator=(S rhs);
    mpz &operator=(double rhs);
    bool operator==(const mpz &rhs);
    bool operator==(T rhs);
    bool operator==(S rhs);
    bool operator==(double rhs);
    bool operator!=(const mpz &rhs);
    bool operator!=(T rhs);
    bool operator!=(S rhs);
    bool operator!=(double rhs);
    bool operator<=(const mpz &rhs);
    bool operator<=(T rhs);
    bool operator<=(S rhs);
    bool operator<=(double rhs);
    bool operator<(const mpz &rhs);
    bool operator<(T rhs);
    bool operator<(S rhs);
    bool operator<(double rhs);
    bool operator>=(const mpz &rhs);
    bool operator>=(T rhs);
    bool operator>=(S rhs);
    bool operator>=(double rhs);
    bool operator>(const mpz &rhs);
    bool operator>(T rhs);
    bool operator>(S rhs);
    bool operator>(double rhs);

    friend bool operator==(const mpz& lhs, const mpz& rhs)
    {
        return 0 == lhs.cmp(rhs);
    }

    friend bool operator==(const mpz& lhs, T rhs)
    {
        return 0 == lhs.cmp_ui(rhs);
    }

    friend bool operator==(const mpz& lhs, S rhs)
    {
        return 0 == lhs.cmp_si(rhs);
    }

    friend bool operator==(const mpz& lhs, double rhs)
    {
        return 0 == lhs.cmp_d(rhs);
    }

    friend bool operator!=(const mpz& lhs, const mpz& rhs)
    {
        return 0 != lhs.cmp(rhs);
    }

    friend bool operator!=(const mpz& lhs, T rhs)
    {
        return 0 != lhs.cmp_ui(rhs);
    }

    friend bool operator!=(const mpz& lhs, S rhs)
    {
        return 0 != lhs.cmp_si(rhs);
    }

    friend bool operator!=(const mpz& lhs, double rhs)
    {
        return 0 != lhs.cmp_d(rhs);
    }

    friend bool operator<=(const mpz& lhs, const mpz& rhs)
    {
        return 1 != lhs.cmp(rhs);
    }

    friend bool operator<=(const mpz& lhs, T rhs)
    {
        return 1 != lhs.cmp_ui(rhs);
    }

    friend bool operator<=(const mpz& lhs, S rhs)
    {
        return 1 != lhs.cmp_si(rhs);
    }

    friend bool operator<=(const mpz& lhs, double rhs)
    {
        return 1 != lhs.cmp_d(rhs);
    }

    friend bool operator<(const mpz& lhs, const mpz& rhs)
    {
        return -1 == lhs.cmp(rhs);
    }

    friend bool operator<(const mpz& lhs, T rhs)
    {
        return -1 == lhs.cmp_ui(rhs);
    }

    friend bool operator<(const mpz& lhs, S rhs)
    {
        return -1 == lhs.cmp_si(rhs);
    }

    friend bool operator<(const mpz& lhs, double rhs)
    {
        return -1 == lhs.cmp_d(rhs);
    }

    friend bool operator>=(const mpz& lhs, const mpz& rhs)
    {
        return -1 != lhs.cmp(rhs);
    }

    friend bool operator>=(const mpz& lhs, T rhs)
    {
        return -1 != lhs.cmp_ui(rhs);
    }

    friend bool operator>=(const mpz& lhs, S rhs)
    {
        return -1 != lhs.cmp_si(rhs);
    }

    friend bool operator>=(const mpz& lhs, double rhs)
    {
        return -1 != lhs.cmp_d(rhs);
    }

    friend bool operator>(const mpz& lhs, const mpz& rhs)
    {
        return 1 == lhs.cmp(rhs);
    }

    friend bool operator>(const mpz& lhs, T rhs)
    {
        return 1 == lhs.cmp_ui(rhs);
    }

    friend bool operator>(const mpz& lhs, S rhs)
    {
        return 1 == lhs.cmp_si(rhs);
    }

    friend bool operator>(const mpz& lhs, double rhs)
    {
        return 1 == lhs.cmp_d(rhs);
    }

    /// @}


    /// Basic control methods
    /// @{

    /// Return a flag indicating that the mpz object is zero
    virtual bool is_zero() const;

    /// Return a flag indicating that the mpz object is one
    virtual bool is_one() const;

    /// Return a flag indicating that the mpz object is negative
    virtual bool is_negative() const;

    /// Set the sign flag to the defined value
    virtual void set_sign(bool sign);

    // Memory pre-allocation and value set to zero
    virtual void zero_init(size_t n);

    /// Return a flag indicating if the defined bit is asserted
    bool tstbit(size_t bit_index) const;

    void setbit(size_t bit_index);

    void unsetbit(size_t bit_index);

    static size_t make_odd(mpz &r);

    T get_ui() const;

    S get_si() const;

    double get_d() const;

    virtual void get_bytes(phantom_vector<uint8_t> &bytes, bool little_endian = false) const;

    virtual void set_bytes(const phantom_vector<uint8_t> &bytes, bool little_endian = false);

    template<typename A>
    mpz<T>& from_radix_array(const phantom_vector<A>& x, T radix, bool little_endian)
    {
        mpz<T> r;
        *this = T(0);
        r = radix;

        if (little_endian) {
            size_t offset = little_endian ? x.size() - 1 : 0;
            for (size_t i=0; i < x.size(); i++) {
                *this = *this * r + T(x[offset - i]);
            }
        }
        else {
            for (size_t i=0; i < x.size(); i++) {
                *this = *this * r + T(x[i]);
            }
        }

        return *this;
    }

    template<typename A>
    void to_radix_array(phantom_vector<A>& y, T radix, bool little_endian)
    {
        size_t len = this->get_limbsize();

        mpz<T> r, xx, quo, rem;
        xx = *this;
        y = phantom_vector<A>();
        r = radix;

        for (size_t i=0; i < len; i++) {
            tdiv_qr(quo, rem, xx, r);
            if (rem.is_zero()) {
                y.push_back(T(0));
            }
            else {
                y.push_back(rem[0]);
            }
            xx = quo;
        }

        if (!little_endian) {
            std::reverse(y.begin(), y.end());
        }
    }

    void get_words(phantom_vector<T> &words) const;

    void set_words(const phantom_vector<T> &words);

    void set_words(const phantom_vector<T> &words, size_t n);

    virtual std::string get_str(size_t base, bool uppercase = false) const;

    virtual const phantom_vector<T> &get_limbs() const;

    virtual phantom_vector<T> &get_limbs();

    /// @}



    /// Comparative methods
    /// @{

    /// Compare two mpz objects (using references to base class objects)
    virtual int32_t cmp(const mp<T>& in) const
    {
        return mpz_core<T>::cmp(get_limbs().data(), is_negative(), get_limbs().size(),
            in.get_limbs().data(), in.is_negative(), in.get_limbs().size());
    }

    /// Compare to a double value (double is converted to integer and rounded towards zero)
    int32_t cmp_d(double in) const
    {
        return mpz_core<T>::cmp_d(get_limbs().data(), m_sign, get_limbs().size(), in);
    }

    /// Compare to an unsigned integer
    virtual int32_t cmp_ui(T in) const
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
    virtual int32_t cmp_si(S in) const
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
    virtual int32_t cmpabs(const mp<T>& in) const
    {
        // Compare the two limb arrays which are stored in an absolute format
        return mpz_core<T>::cmpabs(get_limbs().data(), get_limbsize(), in.get_limbs().data(), in.get_limbs().size());
    }

    /// Compare an mpz object and a double in terms of their absolute magnitudes
    virtual int32_t cmpabs_d(double in) const
    {
        return mpz_core<T>::cmpabs_d(get_limbs().data(), get_limbs().size(), in);
    }

    // Calculate the integer size in bits of the mpz object given a specific base
    virtual size_t sizeinbase(size_t base) const
    {
        return mpz_core<T>::sizeinbase(get_limbs().data(), get_limbsize(), base);
    }

    /// Swap the mpz pbjects
    virtual void swap(mp<T>& in)  // NOLINT
    {
        // Swap the limb vectors and the sign
        m_limbs.swap(const_cast<phantom_vector<T>&>(in.get_limbs()));
        bool in_sign = in.is_negative();
        bit_manipulation::swap<bool>(m_sign, in_sign);  // NOLINT
        in.set_sign(in_sign);
    }

    /// Return the number of limb words used by the mpz object
    virtual size_t get_limbsize() const
    {
        return m_limbs.size();
    }

    /// @}



    /// Logical methods
    /// @{

    /**
     * @brief Bitwise AND of the two mpz objects
     */
    void bitwise_and(const mpz<T>& in1, const mpz<T>& in2)
    {
        // If either argument is zero the result is zero
        auto in1_size = in1.get_limbsize();
        auto in2_size = in2.get_limbsize();
        if (0 == in1_size || 0 == in2_size) {
            m_limbs.resize(0);
            m_sign  = false;
            return;
        }

        // Iterate over all shared limbs and perform a bitwise AND
        size_t min_size = (in1_size < in2_size)? in1_size : in2_size;
        m_limbs.resize(min_size);
        for (size_t i=0; i < min_size; i++) {
            m_limbs[i] = in1[i] & in2[i];
        }
        m_sign  = false;
    }

    /**
     * @brief Bitwise OR of the two mpz objects
     */
    void bitwise_or(const mpz<T>& in1, const mpz<T>& in2)
    {
        // If either argument is zero the result is the opposing argument
        auto in1_size = in1.get_limbsize();
        auto in2_size = in2.get_limbsize();
        if (0 == in1_size) {
            *this = in2;
            return;
        }
        if (0 == in2_size) {
            *this = in1;
            return;
        }

        // Iterate over all shared limbs and perform a bitwise OR
        size_t min_size = (in1_size < in2_size)? in1_size : in2_size;
        m_limbs = phantom_vector<T>((in1_size < in2_size)? in2.m_limbs : in1.m_limbs);
        const mpz<T>& other = (in1_size < in2_size)? in1 : in2;
        for (size_t i=0; i < min_size; i++) {
            m_limbs[i] |= other[i];
        }
        m_sign = false;
    }

    /**
     * @brief Bitwise exclusive-OR of the two mpz objects
     */
    void bitwise_xor(const mpz<T>& in1, const mpz<T>& in2)
    {
        // If either argument is zero the result is the opposing argument
        auto in1_size = in1.get_limbsize();
        auto in2_size = in2.get_limbsize();
        if (0 == in1_size) {
            *this = in2;
            return;
        }
        if (0 == in2_size) {
            *this = in1;
            return;
        }

        // Iterate over all shared limbs and perform a bitwise OR
        size_t min_size = (in1_size < in2_size)? in1_size : in2_size;
        m_limbs = phantom_vector<T>((in1_size < in2_size)? in2.m_limbs : in1.m_limbs);
        const mpz<T>& other = (in1_size < in2_size)? in1 : in2;
        for (size_t i=0; i < min_size; i++) {
            m_limbs[i] ^= other[i];
        }
        m_sign  = false;

        in1_size = mpbase<T>::normalized_size(m_limbs.data(), m_limbs.size());
        m_limbs.resize(in1_size);
    }

    /**
     * @brief Bitwise left shift of an mpz integer
     */
    void lshift(const mpz<T>& in1, const int bits)
    {
        if (0 == bits) {
            *this = in1;
            return;
        }

        size_t in_used = in1.get_limbsize();
        if (0 == in_used) {
            m_limbs.resize(0);
            m_sign  = false;
            return;
        }

        // Determine the number of words and bits to shift
        size_t sh_words = bits >> bits_log2<T>::value();              // Divide by limb bits
        T      sh_bits  = bits & ((1 << bits_log2<T>::value()) - 1);  // Modulo 2 ^ limb bits

        // The output length will be incremented by (bits + limb bits - 1) / limb bits,
        // so resize the limbs array appropriately
        size_t out_used = in_used + sh_words;
        this->m_limbs.resize(out_used);

        if (sh_bits > 0) {
            // If sh_bits is non-zero bits must be shifted between limbs
            T cc = mpbase<T>::lshift(this->m_limbs.data() + sh_words, in1.m_limbs.data(), in_used, sh_bits);
            if (cc) {
                this->m_limbs.push_back(cc);
            }
        }
        else {
            // sh_bits is zero therefore a copy is sufficient to perform the shift
            mpbase<T>::copy(this->m_limbs.data() + sh_words, in1.m_limbs.data(), in_used);
        }

        // The least significant words of the output must be zeroed
        mpbase<T>::zero(this->m_limbs.data(), sh_words);

        // Set the sign with the same sign as the input
        this->m_sign = (is_negative()) ? true : false;

        out_used = mpbase<T>::normalized_size(this->m_limbs.data(), this->m_limbs.size());
        this->m_limbs.resize(out_used);

        return;
    }

    /**
     * @brief Bitwise right shift of an mpz integer
     */
    void rshift(const mpz<T>& in1, const int bits)
    {
        if (0 == bits) {
            *this = in1;
            return;
        }

        int in_used = in1.get_limbsize();
        if (0 == in_used || (bits >= (in_used * std::numeric_limits<T>::digits))) {
            m_limbs.resize(0);
            m_sign = false;
            return;
        }

        // Determine the number of words and bits to shift
        size_t sh_words = bits >> bits_log2<T>::value();              // Divide by limb bits
        T      sh_bits  = bits & ((1 << bits_log2<T>::value()) - 1);  // Modulo 2 ^ limb bits

        size_t out_used = in_used - sh_words;
        this->m_limbs.resize(out_used);

        if (sh_bits > 0) {
            // If sh_bits is non-zero bits must be shifted between limbs
            mpbase<T>::rshift(this->m_limbs.data(), in1.m_limbs.data() + sh_words, in_used - sh_words, sh_bits);
        }
        else {
            // sh_bits is zero therefore a copy is sufficient to perform the shift
            mpbase<T>::copy(this->m_limbs.data(), in1.m_limbs.data() + sh_words, in_used - sh_words);
            mpbase<T>::zero(this->m_limbs.data() + in_used - sh_words, sh_words);
        }

        // Set the sign with the same sign as the input
        this->m_sign = (in1.is_negative()) ? true : false;

        out_used = mpbase<T>::normalized_size(this->m_limbs.data(), this->m_limbs.size());
        this->m_limbs.resize(out_used);

        return;
    }

    /**
     * @brief Calculate the Hamming weight of the mpz object (i.e. number of asserted
     * bits in the absolute representation)
     */
    size_t hamming_weight() const
    {
        size_t used = get_limbsize();

        // Terminate early with zero bits if thempz integer is zero
        if (0 == used) {
            return 0;
        }

        // Accumulate the Hamming weight of all of the limb words
        size_t count = 0;
        for (size_t i=0; i < used; i++) {
            count += bit_manipulation::hamming_weight(m_limbs[i]);
        }

        return count;
    }

    enum miller_rabin_status_e {
        MILLER_RABIN_PROBABLY_PRIME = 0,
        MILLER_RABIN_COMPOSITE_WITH_FACTOR,
        MILLER_RABIN_COMPOSITE_NOT_POWER_OF_PRIME,
        MILLER_RABIN_ERROR
    };

    /**
     * @brief Miller-Rabin primality test
     * @param prng A reference to the CSPRNG to be used
     * @param p The mpz object to be tested
     * @param iterations The maximum number of test iterations to be used
     * @return miller_rabin_status_e Primality status of the mpz object tested
     */
    static miller_rabin_status_e prime_miller_rabin(csprng& prng, const mpz<T>& p, size_t iterations)
    {
        if (p.is_zero() || !(p[0] & 1)) {
            return MILLER_RABIN_ERROR;
        }

        mpz<T> g;
        mpz<T> p1;
        mpz<T> p3;
        mpz<T> x;
        mpz<T> m;
        mpz<T> z;
        mpz<T> b;
        p1 = p - T(1);
        p3 = p - T(3);

        if (p3.is_zero() || p3.is_negative()) {
            return MILLER_RABIN_ERROR;
        }

        // Calculate largest a such that p-1 is a multiple of 2^a
        int a = 1;
        while (!p1.tstbit(a)) {
            a++;
        }
        m.rshift(p1, a);

        mod_config<T> cfg;
        cfg.mod = p;
        cfg.mod_bits = p.sizeinbase(2);
        cfg.k = (p.sizeinbase(2) + std::numeric_limits<T>::digits - 1) >> bits_log2<T>::value();
        cfg.blog2 = std::numeric_limits<T>::digits;
        cfg.reduction = reduction_e::REDUCTION_BARRETT;

        mpz<T> temp_n;
        temp_n.setbit(cfg.blog2 * cfg.k * 2);
        mpz<T>::tdiv_q(cfg.mod_inv, temp_n, p);
        size_t out_used = mpbase<T>::normalized_size(cfg.mod_inv.m_limbs.data(), cfg.mod_inv.m_limbs.size());
        cfg.mod_inv.m_limbs.resize(out_used);

        phantom_vector<uint8_t> rand_b((cfg.mod_bits + 7) >> 3);

        for (size_t i=0; i < iterations; i++) {

            // Obtain a random string of bits b where 1 < b < p-1
            prng.get_mem(rand_b.data(), rand_b.size());
            b.set_bytes(rand_b);
            while (b >= p3) {
                b >>= 1;
            }
            b = b + T(2);

            // Calculate the GCD of b and p
            g = b.gcd(p);
            if (!g.is_one()) {
                return MILLER_RABIN_COMPOSITE_WITH_FACTOR;
            }

            // Calculate z = b^m mod p
            out_used = mpbase<T>::normalized_size(b.m_limbs.data(), b.m_limbs.size());
            b.m_limbs.resize(out_used);
            out_used = mpbase<T>::normalized_size(m.m_limbs.data(), m.m_limbs.size());
            m.m_limbs.resize(out_used);
            powm(z, b, m, cfg.mod);
            if (z.is_one() || z == p1) {
                continue;
            }

            bool is_composite = true;
            for (int j=1; j < a; j++) {
                z.square_mod(cfg);
                if (z == T(1)) {
                    return MILLER_RABIN_COMPOSITE_NOT_POWER_OF_PRIME;
                }
                if (z == p1) {
                    is_composite = false;
                    break;
                }
            }

            z.square_mod(cfg);
            if (z == T(1)) {
                return MILLER_RABIN_COMPOSITE_NOT_POWER_OF_PRIME;
            }

            if (is_composite) {
                return MILLER_RABIN_COMPOSITE_NOT_POWER_OF_PRIME;
            }
        }

        return MILLER_RABIN_PROBABLY_PRIME;
    }

    /**
     * @brief Check the primality of an mpz object with optional trial divisions
     * @param prng A reference to the CSPRNG to be used
     * @param p mpz object to be tested
     * @param bits Size in bits of the mpz number
     * @param trial_division The number of trial divisions to be performed initally
     * @return bool True if prime, false otherwise
     */
    static bool check_prime(csprng& prng, const mpz<T>& p, size_t bits, bool trial_division)
    {
        // Determine the number of Miller-Rabin checks (1 per 16 bits)
        size_t checks = (bits + 15) >> 4;
        if (checks < 64) checks = 64;

        // Not prime if 1, 0 or negative
        if (p <= T(1)) {
            return false;
        }

        // Not prime if even
        if (!(p[0] & 1)) {
            return p == T(2);
        }

        // If trial divisions are enabled a faster check for a remainder
        // is perfomed using a small group of the smallest prime numbers
        if (trial_division) {
            size_t num_trial_divisions = bits_log2<T>::value() == 8 ? (PHANTOM_NUM_FIRST_PRIMES_8BIT - 1) :
                                                                      (PHANTOM_NUM_FIRST_PRIMES - 1);
            mpz<T> r;
            for (size_t i=1; i < num_trial_divisions; i++) {
                T rem = div_r_ui(r, p, first_primes_list[i], mp_round_e::MP_ROUND_TRUNC);
                if (T(-1) == rem) {
                    return false;
                }
                if (0 == rem) {
                    return p == static_cast<T>(first_primes_list[i]);
                }
            }
        }

        return prime_miller_rabin(prng, p, checks) == MILLER_RABIN_PROBABLY_PRIME;
    }

    /// @}



    /// Additive methods
    /// @{

    /// Negate the mpz object
    mpz<T>& negate()
    {
        set_sign(!this->is_negative());
        return *this;
    }

    /// Calculate the absolute of the mpz object
    mpz abs() const
    {
        mpz out = *this;
        out.set_sign(false);
        return out;
    }

    /// Add the two mpz integers as absolute values
    int32_t abs_add(const mpz& in1, const mpz& in2)
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
    int32_t abs_sub(const mpz& in1, const mpz& in2)
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
    int32_t abs_add(const mpz& in1, T in2)
    {
        m_limbs.resize(in1.get_limbsize() + 1);
        int32_t used = mpz_core<T>::abs_add(m_limbs.data(), in1.m_limbs.data(), in1.get_limbsize(), in2);
        m_limbs.resize(used);
        return used;
    }

    /// Subtract an mpz integer and an unsigned integer as absolute values
    int32_t abs_sub(const mpz& in1, T in2)
    {
        int32_t used = in1.get_limbsize();
        m_limbs.resize((used < 1)? 1 : used);
        used = mpz_core<T>::abs_sub(m_limbs.data(), in1.get_limbs().data(), used, in2);
        m_limbs.resize((used < 0)? -used : used);
        return used;
    }

    /// Add an unsigned integer to an mpz object
    void add(const mpz<T>& in1, T in2)
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
    void sub(const mpz<T>& in1, T in2)
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
    mpz<T>& add(T in2)
    {
        this->add(*this, in2);
        return *this;
    }

    /// Subtract an unsigned integer from an mpz object
    mpz<T>& sub(T in2)
    {
        this->sub(*this, in2);
        return *this;
    }

    /// Add an mpz object to an mpz object
    void add(const mpz<T>& in1, const mpz<T>& in2)
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
    void sub(const mpz<T>& in1, const mpz<T>& in2)
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
    mpz<T>& add(const mpz<T>& in2)
    {
        this->add(*this, in2);
        return *this;
    }

    /// Subtract an mpz object from an mpz object
    mpz<T>& sub(const mpz<T>& in2)
    {
        this->sub(*this, in2);
        return *this;
    }

    /// Add an mpz object and reduce
    mpz<T>& add_mod(const mpz<T>& in2, const mod_config<T>& cfg)
    {
        this->add(*this, in2);
        this->mod_positive(cfg);
        return *this;
    }

    /// Subtract an mpz object and reduce
    mpz<T>& sub_mod(const mpz<T>& in2, const mod_config<T>& cfg)
    {
        this->sub(*this, in2);
        this->mod_positive(cfg);
        return *this;
    }

    /// @}



    /// Multiplicative methods
    /// @{

    /// Multiply an mpz object by 2*bits
    mpz<T>& mul_2exp(size_t bits)
    {
        if (0 == bits) {
            return *this;
        }

        size_t in_used = get_limbsize();
        if (0 == in_used) {
            m_limbs.resize(0);
            m_sign  = false;
            return *this;
        }

        // This multiply corresponds to a left shift by 'bits', so determine the number of
        // words and bits to shift
        size_t sh_words = bits >> bits_log2<T>::value();              // Divide by limb bits
        T      sh_bits  = bits & ((1 << bits_log2<T>::value()) - 1);  // Modulo 2 ^ limb bits

        // The output length will be incremented by (bits + limb bits - 1) / limb bits,
        // so resize the limbs array appropriately
        size_t out_used = in_used + sh_words + 1;
        m_scratch.resize(out_used);

        if (sh_bits > 0) {
            // If sh_bits is non-zero bits must be shifted between limbs
            T cc = mpbase<T>::lshift(m_scratch.data() + sh_words, m_limbs.data(), in_used, sh_bits);
            if (cc) {
                m_scratch[out_used - 1] = cc;
            }
        }
        else {
            // sh_bits is zero therefore a copy is sufficient to perform the shift
            mpbase<T>::copy(m_scratch.data() + sh_words, m_limbs.data(), in_used);
        }

        // The least significant words of the output must be zeroed
        mpbase<T>::zero(m_scratch.data(), sh_words);

        this->m_limbs.swap(m_scratch);
        out_used = mpbase<T>::normalized_size(m_limbs.data(), m_limbs.size());
        m_limbs.resize(out_used);

        // Set the sign with the same sign as the input
        this->m_sign = is_negative();

        return *this;
    }

    /// Multiply an mpz object by an unsigned integer
    static void mul_ui(mpz& out, const mpz& in1, T in2)
    {
        // If either operand is zero the result is zero
        size_t in1_used = in1.get_limbsize();
        if (0 == in1_used || 0 == in2) {
            out.m_limbs.resize(0);
            out.m_sign  = false;
            return;
        }

        // Resize the 'out' limbs, perform a multiply using mul_1() and
        // remember to assign the carry to the most significant limb
        out.m_limbs.resize(in1_used);
        T carry = mpbase<T>::mul_1(out.m_limbs.data(), in1.m_limbs.data(), in1_used, in2);
        if (carry) {
            out.m_limbs.push_back(carry);
        }

        // Set the appropriate sign
        out.m_sign = in1.is_negative();
    }

    /// Multiply an mpz object by a signed integer
    static void mul_si(mpz& out, const mpz& in1, S in2)
    {
        if (in2 < 0) {
            mul_ui(out, in1, -(static_cast<T>((in2) + 1) - 1));
            out.m_sign ^= true;
        }
        else {
            mul_ui(out, in1, in2);
        }
    }

    /// Multiply an mpz object by an mpz object
    static void mul(mpz& out, const mpz& in1, const mpz<T>& in2)
    {
        out.m_limbs.resize(in1.get_limbsize() + in2.get_limbsize());
        int used = mpz_core<T>::mul(out.m_limbs.data(), in1.get_limbs().data(), in1.get_limbsize(), in1.is_negative(),
            in2.get_limbs().data(), in2.get_limbsize(), in2.is_negative());
        out.set_sign(used < 0);
        out.m_limbs.resize((used < 0)? -used : used);
    }

    /// Multiply an mpz object by an mpz object
    mpz<T>& mul_mod(const mpz<T>& in2, const mod_config<T>& cfg)
    {
        if (REDUCTION_MONTGOMERY == cfg.reduction) {
            return mul_mont(in2, cfg);
        }
        else {
            mpz<T> out;
            mul(out, *this, in2);
            out.reduce(cfg);
            this->swap(out);
            return *this;
        }
    }

    /// Multiply an mpz object by an mpz object
    mpz<T>& mul_mod(const mpz<T>& in1, const mpz<T>& in2, const mod_config<T>& cfg)
    {
        mul(*this, in1, in2);
        this->reduce(cfg);
        return *this;
    }

    // Montgomery multiplication of an mpz integer with another
    mpz<T>& mul_mont(const mpz<T>& in2, const mod_config<T>& cfg)
    {
        if (m_scratch.size() < (cfg.k + 1)) {
            m_scratch.resize(cfg.k + 1);
        }
        int32_t used = mpz_core<T>::mul_mont(m_scratch.data(), this->m_limbs.data(), this->m_limbs.size(),
            in2.m_limbs.data(), in2.m_limbs.size(), cfg.mod.get_limbs().data(), cfg.k, cfg.mont_inv);
        this->m_limbs.swap(m_scratch);

        m_limbs.resize(used);

        return *this;
    }

    /// Calculate the square root of an mpz object
    /// NOTE: the square root of a negative number is indeterminate and a zero is returned
    mpz sqrt() const
    {
        // If <= 1 then return the input, this is incorrect for negative inputs
        // which are indeterminate
        if (this->cmp_ui(1) <= 0) {
            mpz a;
            return a;
        }

        // Set a=0 and b=2^ceil(log2(in))
        mpz a, b, tmp;
        b.setbit((this->sizeinbase(2) >> 1) + (this->hamming_weight() > 1));

        // Iteratively compute a=b, b=(a + (in/a))/2 until |b| >= |a|
        do {
            a.swap(b);
            tdiv_q(b, *this, a);
            tmp = b + a;
            tdiv_q_2exp(b, tmp, 1);
        } while (b.cmpabs(a) < 0);

        return b;
    }

    /**
     * @brief Legendre symbol calculation
     * @param a Number a to be 
     * @param b 
     * @return int Legendre symbol of 1, 0 or -1
     */
    static int legendre(const mpz<T>& a, const mpz<T>& b)
    {
        mpz<T> local_a = a;
        mpz<T> local_b = b;
        size_t asize = local_a.get_limbsize();
        T alow = asize? local_a[0] : 0;

        size_t bsize = local_b.get_limbsize();
        T blow = bsize? local_b[0] : 0;

        if (bsize == 0) {
            // (a/0) = [ a = 1 or a = -1 ]
            return asize == 1 && alow == 1;
        }

        if (asize == 0) {
            // (0/b) = [ b = 1 or b = - 1 ]
            return bsize == 1 && blow == 1;
        }

        if (((alow | blow) & 1) == 0) {
            // Common factor of 2 ==> (a/b) = 0
            return 0;
        }

        int result_bit1 = 0;
        if (local_b.is_negative()) {
            // (a/-1) = -1 if a < 0, +1 if a >= 0
            result_bit1 = local_a.is_negative() << 1;
        }

        int num_low_zero = 0;
        while (0 == local_b[num_low_zero]) {
            num_low_zero++;
        }
        local_b.get_limbs().erase(local_b.get_limbs().begin(), local_b.get_limbs().begin() + num_low_zero);
        blow = local_b[0];
        if ((std::numeric_limits<T>::digits & 1) == 1)
            result_bit1 ^= static_cast<int>((alow >> 1) ^ alow);
        size_t ctz = bit_manipulation::ctz(local_b[0]);
        blow >>= ctz;

        if (bsize > 1 && ctz > 0) {
            T b1 = local_b[1];
            blow |= b1 << (std::numeric_limits<T>::digits - ctz);
            if (bsize == 2 && (b1 >> ctz) == 0) {
                bsize = 1;
            }
        }

        if (local_a.is_negative()) {
            result_bit1 ^= static_cast<int>(blow);
        }

        num_low_zero = 0;
        while (0 == local_a[num_low_zero]) {
            num_low_zero++;
        }
        local_a.get_limbs().erase(local_a.get_limbs().begin(), local_a.get_limbs().begin() + num_low_zero);
        alow = local_a[0];
        if ((std::numeric_limits<T>::digits & 1) == 1)
            result_bit1 ^= static_cast<int>((blow >> 1) ^ blow);

        if (asize < bsize) {
            local_a.swap(local_b);
            blow ^= alow;
            alow ^= blow;
            blow ^= alow;
            asize ^= bsize;
            bsize ^= asize;
            asize ^= bsize;

            ctz = bit_manipulation::ctz(blow);
            blow >>= ctz;

            if (bsize > 1 && ctz > 0) {
                T b1 = local_b[1];
                blow |= b1 << (std::numeric_limits<T>::digits - ctz);
                if (bsize == 2 && (b1 >> ctz) == 0) {
                    bsize = 1;
                }
            }

            result_bit1 ^= static_cast<int>(alow & blow);
        }

        if (bsize == 1) {
            result_bit1 ^= static_cast<int>(ctz << 1) & static_cast<int>((alow >> 1) ^ alow);

            if (blow == 1) {
                return 1 - (static_cast<int>(result_bit1) & 2);
            }

            if (asize > 1) {
                if (std::numeric_limits<T>::digits & 1) {
                    alow = mpbase<T>::mod_1(local_a.get_limbs().data(), asize, blow);
                }
                else {
                    result_bit1 ^= static_cast<int>(blow);
                    alow = mpbase<T>::modexact_1_odd(local_a.get_limbs().data(), asize, blow);
                }
            }

            return mpbase<T>::basecase_jacobi(alow, blow, result_bit1);
        }

        phantom_vector<T> ap(bsize);
        phantom_vector<T> bp((asize >= 2*bsize)? asize - bsize + 1 : bsize);

        // If a > b then bp = a/b, ap = a%b, otherwise bp = 0, ap = a
        if (asize > bsize) {
            mpbase<T>::tdiv_qr(bp.data(), ap.data(), local_a.get_limbs().data(), asize,
                local_b.get_limbs().data(), bsize);
        }
        else {
            mpbase<T>::copy(ap.data(), local_a.get_limbs().data(), bsize);
        }

        // If b had trailing zeros then they are restored to bp
        if (ctz > 0) {
            result_bit1 ^= static_cast<int>((ctz) << 1) & static_cast<int>((alow >> 1) ^ alow);

            bp = (local_b >> static_cast<int>(ctz)).get_limbs();
            bsize -= (ap[bsize-1] | bp[bsize-1]) == 0;
        }
        else {
            mpbase<T>::copy(bp.data(), local_b.get_limbs().data(), bsize);
        }

        assert(blow == bp[0]);
        int res = mpbase<T>::jacobi_n(ap.data(), bp.data(), bsize,
            mpbase<T>::jacobi_init(ap[0], blow, (result_bit1>>1) & 1));

        return res;
    }

    /**
     * @brief Check if a is divisible by d
     * @param a Dividend
     * @param d Denominator
     * @return int 1 if there is a remainder, 0 otherwise
     */
    static int divisible_p(const mpz<T>& a, const mpz<T>& d)
    {
        size_t dsize = d.get_limbsize();
        size_t asize = a.get_limbsize();

        if (dsize == 0) {
            return (asize == 0);
        }

        return mpbase<T>::divisible_p(a.get_limbs().data(), asize, d.get_limbs().data(), dsize);
    }

    /**
     * @brief Tonelli-Shanks algorithm, find a square root of n modulo p
     * 
     * @param cfg A mod_config object defining the modulus p
     * @param r Square root
     * @param n Input integer
     * @return bool True if a square root was found, false otherwise
     */
    static bool tonelli_shanks(const mod_config<T>& cfg, mpz<T>& r, const mpz<T>& n)
    {
        mpz<T> q, z, c, t, n_inv, tmp, pso, x, b, g;
        size_t i, s, m;

        q.set(cfg.mod);
        q = q - T(1);

        s = 0;
        while (q.tstbit(s) == 0) s++;
        fdiv_q_2exp(pso, q, s);               // x = q / 2^s
        q = pso;

        // p = 3 (mod 4)
        if (s == 1) {
            q.set(cfg.mod);
            q = q + T(1);                     // q = p-1
            fdiv_q_2exp(g, q, 2);
            r.set(n).pow_mod(g, cfg);         // q = n ^ ((p 1) / 4) (mod p)
            return true;
        }

        z = T(2);                             // Search for a non-residue mod p
        while (legendre(z, cfg.mod) != -1)
            z = z + T(1);

        fdiv_q_2exp(tmp, q + T(1), 1);

        c.set(z).pow_mod(q, cfg);
        r.set(n).pow_mod(tmp, cfg);
        t.set(n).pow_mod(q, cfg);
        m = T(s);

        while (t.cmp_ui(1) != 0) {
            size_t i = 1;
            x.set(t).square_mod(cfg);
            while (x.cmp_ui(1) != 0 && i < m) {
                x.square_mod(cfg);
                i++;
            }
            b.set(c).pow_mod(1 << (m-i-1), cfg);

            c.set(b).square_mod(cfg);
            r.mul_mod(b, cfg);
            t.mul_mod(c, cfg);
            m = i;
        }

        return true;
    }

    /**
     * @brief Calculate the square root modulo p
     * NOTE: Throws a runtime_error exception if a msquare root was not found.
     * @param cfg A mod_config object describing the modulus p
     * @return mpz<T>& A reference to the square root
     */
    mpz<T>& sqrt_mod(const mod_config<T>& cfg)
    {
        mpz<T> q;
        if (!tonelli_shanks(cfg, q, *this)) {
            throw std::runtime_error("Modular square root NOT found");
        }
        this->swap(q);
        return *this;
    }

    /// Calculate the square of an mpz object
    mpz<T>& square()
    {
        m_scratch.resize(2 * this->get_limbsize());
        int used = mpz_core<T>::square(m_scratch.data(), this->get_limbs().data(), this->get_limbsize());
        m_scratch.resize(used);
        this->get_limbs().swap(m_scratch);
        this->set_sign(false);
        return *this;
    }

    /// Calculate the square of an mpz object modulo p
    mpz<T>& square_mod(const mod_config<T>& cfg, size_t w = 1)
    {
        do {
            if (REDUCTION_MONTGOMERY == cfg.reduction) {
                this->square_mont(cfg);
            }
            else {
                this->square().reduce(cfg);
            }
        } while (--w);

        return *this;
    }

    // Montgomery squaring of the mpz object
    mpz<T>& square_mont(const mod_config<T>& cfg)
    {
        if (0 == this->m_limbs.size()) {
            return *this;
        }

        m_scratch.resize(cfg.k + 1);
        int32_t used = mpz_core<T>::square_mont(m_scratch.data(), this->m_limbs.data(), this->m_limbs.size(),
            cfg.mod.get_limbs().data(), cfg.k, cfg.mont_inv);
        this->m_limbs.swap(m_scratch);

        used = mpbase<T>::normalized_size(m_limbs.data(), m_limbs.size());
        m_limbs.resize(used);

        return *this;
    }

    /// Calculate the mpz object raised to the power of e
    mpz<T>& pow(T e)
    {
        T bit          = (1ULL << (std::numeric_limits<T>::digits-1)) >> bit_manipulation::clz(e);
        mpz out;
        out.m_limbs.resize(1);
        out.m_limbs[0] = 1;
        out.m_sign     = false;

        // Square-and-multiply exponentiation by scanning the exponent
        // from right to left
        mpz temp;
        do {
            out.square();
            if (e & bit) {
                mul(temp, out, *this);
                out = temp;
            }
            bit >>= 1;
        } while (bit > 0);

        this->swap(out);

        return *this;
    }

    /// Calculate the mpz object raised to the power of e
    mpz<T>& pow_mod(T e, const mod_config<T>& cfg)
    {
        if (REDUCTION_MONTGOMERY == cfg.reduction) {
            return this->pow_mont(e, cfg);
        }
        else {
            T bit          = 1 << (std::numeric_limits<T>::digits - bit_manipulation::clz(e));
            mpz out;
            out.m_limbs.resize(1);
            out.m_limbs[0] = 1;
            out.m_sign     = false;

            // Square-and-multiply exponentiation by scanning the exponent
            // from right to left
            do {
                out.square_mod(cfg);
                if (e & bit) {
                    out.mul_mod(*this, cfg);
                }
                bit >>= 1;
            } while (bit > 0);

            this->swap(out);

            return *this;
        }
    }

    /// Montgomery exponentiation of an mpz integer raised to the power of another
    mpz<T>& pow_mont(T e, const mod_config<T>& cfg)
    {
        T bit          = 1 << (std::numeric_limits<T>::digits - bit_manipulation::clz(e));
        mpz out;
        out.m_limbs.resize(1);
        out.m_limbs[0] = 1;
        out.m_sign     = false;

        // Square-and-multiply exponentiation by scanning the exponent from right to left
        do {
            out.square_mont(cfg);
            if (e & bit) {
                out.mul_mont(*this, cfg);
            }
            bit >>= 1;
        } while (bit > 0);

        this->swap(out);

        return *this;
    }

    /// Modular exponentiation
    mpz<T>& pow_mod(const mpz<T>& e, const mod_config<T>& cfg)
    {
        if (REDUCTION_MONTGOMERY == cfg.reduction) {
            mpz<T> in = *this;
            powm(*this, in, e, cfg.mod);
            return *this;
        }
        else {
            T   bits = e.sizeinbase(2) - 1;
            mpz out  = *this;

            // Square-and-multiply exponentiation by scanning the exponent from right to left
            while (bits) {
                out.square_mod(cfg);
                if (e.tstbit(--bits)) {
                    out.mul_mod(*this, cfg);
                }
            }

            this->swap(out);

            return *this;
        }
    }

    /// Explicit modular exponentiation of mpz objects, r = b^e mod m
    static void powm(mpz<T>& r, const mpz<T>& b, const mpz<T>& e, const mpz<T>& m)
    {
        size_t n = m.get_limbsize();
        if (0 == n) {
            throw std::runtime_error("Modulus has length 0");
        }

        mpz<T> local_b, bp, rp;
        mpz<T> mp = m;
        mpz<T> ep = e;
        rp.get_limbs().resize(n);

        size_t es = ep.get_limbsize();
        if (ep.is_zero()) {
            // b^0 mod m,  b is anything and m is non-zero.
            // Result is 1 mod m, i.e., 1 or 0 depending on if m = 1.
            r = T(1);
            return;
        }
        if (ep.is_negative()) {
            local_b.get_limbs().resize(n + 1);

            if (!invert(local_b, b, m)) {
                throw std::runtime_error("Divide by zero");
            }
            ep.set_sign(false);
        }
        else {
            local_b = b;
        }
        size_t en = es;

        size_t rn;
        size_t bn = local_b.get_limbsize();
        if (0 == bn) {
            r.get_limbs().resize(0);
            return;
        }

        // Handle (b^1 mod m) early, since pow doesn't handle that case
        if (en == 1 && ep[0] == 1) {
            bp = local_b;
            if (bn >= n) {
                mpz<T> qp;
                qp.get_limbs().resize(bn - n + 1);
                tdiv_qr(qp, rp, bp, mp);
                rn = mpbase<T>::normalized_size(rp.m_limbs.data(), n);

                if (rn != 0 && local_b.is_negative()) {
                    mpbase<T>::sub(rp.get_limbs().data(), mp.get_limbs().data(), n, rp.get_limbs().data(), rn);
                    rn = mpbase<T>::normalized_size(rp.m_limbs.data(), n);
                    rp.m_limbs.resize(rn);
                }
            }
            else {
                if (local_b.is_negative()) {
                    mpbase<T>::sub(rp.get_limbs().data(), mp.get_limbs().data(), n, bp.get_limbs().data(), bn);
                    rn = mpbase<T>::normalized_size(rp.m_limbs.data(), n);
                    rp.m_limbs.resize(rn);
                }
                else {
                    mpbase<T>::copy(rp.get_limbs().data(), bp.get_limbs().data(), bn);
                    rn = bn;
                }
            }

            r = rp;
            return;
        }

        // Remove low zero limbs from M. This loop will terminate for correctly represented mpz numbers
        size_t ncnt = 0;
        while (0 == mp[ncnt]) {
            ncnt++;
        }
        mp.get_limbs().erase(mp.get_limbs().begin(), mp.get_limbs().begin() + ncnt);
        size_t nodd = n - ncnt;
        int cnt  = 0;
        if (mp[0] % 2 == 0) {
            mpz<T> newmp;
            newmp.get_limbs().resize(nodd);
            cnt = bit_manipulation::ctz(mp[0]);
            newmp.rshift(mp, cnt);
            nodd -= newmp[nodd - 1] == 0;
            mp.swap(newmp);
            ncnt++;
        }

        size_t itch;
        if (ncnt != 0) {
            // We will call both powm and powlo
            // rp needs n, powlo needs 4n, the x2 binvert may need more
            size_t n_largest_binvert = MAX(ncnt, nodd);
            size_t size_binvert = mpbase<T>::binvert_powm_scratch_size(n_largest_binvert);
            itch = 2 * n + MAX(size_binvert, 2 * n);
        }
        else {
            // We will call just powm
            size_t size_binvert = mpbase<T>::binvert_powm_scratch_size(nodd);
            itch = MAX(size_binvert, 2 * n);
        }

        // Temporary array of length itch
        phantom_vector<T> scratch(itch);

        bp = local_b;
        mpbase<T>::powm(rp.get_limbs().data(), bp.get_limbs().data(), bn, ep.get_limbs().data(), en,
            mp.get_limbs().data(), nodd, scratch.data());

        rn = n;

        if (ncnt != 0) {
            T* r2 = rp.get_limbs().data();
            T* xp, *yp, *odd_inv_2exp;
            size_t t;
            size_t bcnt;

            if (bn < ncnt) {
                phantom_vector<T> newbp(ncnt);
                mpbase<T>::copy(newbp.data(), bp.get_limbs().data(), bn);
                mpbase<T>::zero(newbp.data(), ncnt - bn);
                bp.get_limbs().swap(newbp);
            }

            if (bp[0] % 2 == 0) {
                if (en > 1) {
                    mpbase<T>::zero(r2, ncnt);
                    goto zero;
                }

                assert(en == 1);
                t = (ncnt - (cnt != 0)) * std::numeric_limits<T>::digits + cnt;

                // Count number of low zero bits in B, up to 3
                bcnt = (0x1213 >> ((bp[0] & 7) << 1)) & 0x3;
                // Note that ep[0] * bcnt might overflow, but that just results in a missed optimization
                if (ep[0] * bcnt >= t) {
                    mpbase<T>::zero(r2, ncnt);
                    goto zero;
                }
            }

            mpbase<T>::pow_low(r2, bp.get_limbs().data(), ep.get_limbs().data(), en, ncnt, scratch.data() + n + ncnt);

    zero:
            if (nodd < ncnt) {
                phantom_vector<T> newmp(ncnt);
                mpbase<T>::copy(newmp.data(), mp.get_limbs().data(), nodd);
                mpbase<T>::zero(newmp.data() + nodd, ncnt - nodd);
                mp.get_limbs().swap(newmp);
            }

            odd_inv_2exp = scratch.data() + 2 * n;
            mpbase<T>::binvert(odd_inv_2exp, mp.get_limbs().data(), ncnt, scratch.data() + 3 * n);

            mpbase<T>::sub(r2, r2, ncnt, rp.get_limbs().data(), nodd > ncnt ? ncnt : nodd);

            xp = scratch.data() + 3 * n;
            mpbase<T>::mul_low_n(xp, odd_inv_2exp, r2, ncnt);

            if (cnt != 0)
                xp[ncnt - 1] &= (T(1) << cnt) - 1;

            yp = scratch.data() + n;
            if (ncnt > nodd)
                mpbase<T>::mul(yp, xp, ncnt, mp.get_limbs().data(), nodd);
            else
                mpbase<T>::mul(yp, mp.get_limbs().data(), nodd, xp, ncnt);

            mpbase<T>::add(rp.get_limbs().data(), yp, n, rp.get_limbs().data(), nodd);

            assert(nodd + ncnt >= n);
            assert(nodd + ncnt <= n + 1);
        }

        rn = mpbase<T>::normalized_size(rp.get_limbs().data(), rn);

        if ((ep[0] & 1) && b.is_negative() && rn != 0) {
            mpbase<T>::sub(rp.get_limbs().data(), m.get_limbs().data(), n, rp.get_limbs().data(), rn);
            rn = mpbase<T>::normalized_size(rp.get_limbs().data(), n);
        }
        rp.get_limbs().resize(rn);

        r = rp;
    }


    /// Divide the numerator by 2^bits and return the quotient
    static T div_q_2exp(mpz& q, const mpz& n, T bits, mp_round_e mode)
    {
        bool rounding = false;

        // If the numerator is 0 then the quotient is zero
        size_t n_used = n.get_limbsize();
        if (0 == n_used) {
            q.m_limbs.resize(0);
            q.m_sign  = false;
            return 0;
        }

        // Determine the number of limb words in the dividend and the quotient
        size_t used   = bits >> bits_log2<T>::value();
        size_t q_used = (n_used <= used)? 0 : n_used - used;

        // Calculate the number of bits in the most significant limb of the dividend
        bits &= (1 << bits_log2<T>::value()) - 1;

        if (mode == ((n.is_negative())? mp_round_e::MP_ROUND_FLOOR : mp_round_e::MP_ROUND_CEIL)) {
            // Divisor is larger than numerator
            rounding  = q_used <= 0;

            // Normalised numerator is larger than 0 in length
            rounding |= 0 != mpbase<T>::normalized_size(n.m_limbs.data(), used);

            // Most significant word of numerator is non-zero
            rounding |= n.m_limbs[used] & ((1 << bits) - 1);
        }

        // If the quotient is less than or equal to zero then the quotient is zero
        if (q.m_sign) {
            q_used = 0;
        }

        // Otherwise we resize the quotient and shift the numerator by q_used limbs and bits
        q.zero_init(q_used);
        if (q_used > 0) {
            T *q_limbs = q.m_limbs.data();
            if (0 != bits) {
                // Shifting of bits within words is necessary, so use rshift() and decrement
                // the quotient length if the most significant limb is zero
                mpbase<T>::rshift(q_limbs, n.m_limbs.data() + used, q_used, bits);
                if (0 == q_limbs[q_used - 1]) {
                    q.m_limbs.pop_back();
                }
            }
            else {
                // bits == 0 so we are shifting by an exact number of limbs so simply copy
                mpbase<T>::copy(q_limbs, n.m_limbs.data() + used, q_used);
            }
        }

        // Set the final quotient result by rounding and negating as necessary
        if (rounding) {
            q.add(q, T(1));
        }
        if (n.m_sign) {
            q.negate();
        }

        // Resize the quotient to the appropriate size and sign
        used = mpbase<T>::normalized_size(q.m_limbs.data(), q.m_limbs.size());
        q.m_limbs.resize(used);

        return (q.get_limbsize() > 1) || (q.get_limbsize() == 1 && q.m_limbs[0]);
    }

    /// Divide the numerator by 2^bits and return the remainder
    static void div_r_2exp(mpz& r, const mpz& n, T bits, mp_round_e mode)
    {
        // If the numerator is 0 then we return a zero remainder
        size_t n_used = n.get_limbsize();
        if (0 == n_used || 0 == bits) {
            r.m_limbs.resize(0);
            r.m_sign  = false;
            return;
        }

        // Create an mpz object with pre-allocated memory and mask
        size_t r_used  = (bits + std::numeric_limits<T>::digits - 1) >> bits_log2<T>::value();
        r = mpz<T>();
        r.zero_init(r_used);
        T* r_limbs = r.m_limbs.data();
        T  mask    = std::numeric_limits<T>::max() >> (r_used * std::numeric_limits<T>::digits - bits);

        if (r_used > n_used) {
            // Negate the numerator if it is non-zero, otherwise copy it
            if (mode == ((n.is_negative())? mp_round_e::MP_ROUND_FLOOR : mp_round_e::MP_ROUND_CEIL)) {
                T carry = 1;
                size_t i;
                for (i=0; i < n_used; i++) {
                    T temp = ~n.m_limbs[i] + carry;
                    r_limbs[i] = temp;
                    carry = temp < carry;
                }

                // Sign extend the most significant limbs
                for (; i < r_used - 1; i++) {
                    r_limbs[i] = std::numeric_limits<T>::max();
                }
                r_limbs[r_used - 1] = mask;
                r.m_sign ^= true;
            }
            else {
                if (r != n) {
                    mpbase<T>::copy(r_limbs, n.m_limbs.data(), n_used);
                    r_used = n_used;
                }
            }
        }
        else {
            if (r != n) {
                mpbase<T>::copy(r_limbs, n.m_limbs.data(), r_used - 1);
            }

            // Zero the most significant bits of the most significant limb of the remainder
            r_limbs[r_used - 1] = n.m_limbs[r_used - 1] & mask;

            if (mode == ((n.get_limbsize() > 0)? mp_round_e::MP_ROUND_CEIL : mp_round_e::MP_ROUND_FLOOR)) {
                size_t i;
                for (i=0; i < r_used && 0 == r_limbs[i]; i++) {
                }

                if (i < r_used) {
                    r_limbs[i] = ~r_limbs[i] + 1;
                    while (++i < r_used) {
                        r_limbs[i] = ~r_limbs[i];
                    }
                    r_limbs[r_used-1] &= mask;
                    r.m_sign ^= true;
                }

            }
        }

        // Resize the remainder to the appropriate size and sign
        r_used   = mpbase<T>::normalized_size(r_limbs, r_used);
        r.m_limbs.resize(r_used);
        r.m_sign = n.m_sign;

        return;
    }

    /// Divide a numerator by a denominator and return the quotient
    static T div_q(mpz& q, const mpz& n, const mpz& d, mp_round_e mode)
    {
        size_t n_used = n.get_limbsize();
        size_t d_used = d.get_limbsize();

        // Check for divide by zero
        if (0 == d_used) {
            return 0;
        }

        // Check for a single precision divisor that is a power of 2
        if (1 == d_used && !(d.m_limbs[0] & (d.m_limbs[0] - 1))) {
            T ctz = bit_manipulation::ctz(d.m_limbs[0]);
            return div_q_2exp(q, n, ctz, mode);
        }

        // If the numerator is zero set the output quotient and remainder to zero
        // and return 0 to indicate a zero remainder
        if (0 == n_used) {
            q.m_limbs.resize(0);
            q.set_sign(false);
            return 0;
        }

        // Determine the sign of the quotient
        bool q_sign = d.is_negative() ^ n.is_negative();

        // If the numerator used length is less than the denominator then quickly
        // compute the quotient and remainder
        if (n_used < d_used) {
            if (mp_round_e::MP_ROUND_FLOOR == mode && q_sign) {
                // Round down required
                q = S(-1);
            }
            else if (mp_round_e::MP_ROUND_CEIL == mode && !q_sign) {
                // Round up required
                q = T(1);
            }
            else {
                // Normal truncation
                q = mpz();
            }

            // Return a non-zero remainder
            return 1;
        }
        else {
            // Initialise the temporary remainder and commonly used variables
            mpz temp_r = n;
            T* n_limbs = temp_r.m_limbs.data();
            const T* d_limbs = d.m_limbs.data();
            size_t q_used  = n_used - d_used + 1;

            // Create a pointer to the quotient data
            mpz temp_q;
            temp_q.zero_init(q_used);
            T* q_limbs = temp_q.m_limbs.data();

            // Obtain the quotient - numerator variable is destroyed!
            mpbase<T>::div_qr(q_limbs, n_limbs, n_used, d_limbs, d_used);

            // Compensate for the most significant limb being zero and set the size
            // of the output quotient and the remainder
            temp_q.m_sign = q_sign;
            size_t r_used = mpbase<T>::normalized_size(n_limbs, d_used);
            temp_r.m_limbs.resize(r_used);
            temp_r.m_sign = n.m_sign;

            // Rounding
            if (0 != r_used) {
                if (mp_round_e::MP_ROUND_FLOOR == mode && q_sign) {
                    // Round down required
                    temp_q = temp_q - T(1);
                }
                else if (mp_round_e::MP_ROUND_CEIL == mode && !q_sign) {
                    // Round up required
                    temp_q = temp_q + T(1);
                }
            }

            temp_q.swap(q);
            if (1 == q_used && 0 == q.m_limbs[0]) {
                q.m_limbs.resize(0);
            }

            return 0 != r_used;
        }
    }

    /// Divide a numerator by a denominator and return the remainder
    static T div_r(mpz<T>& r, const mpz<T>& n, const mpz<T>& d, mp_round_e mode)
    {
        size_t n_used = n.get_limbsize();
        size_t d_used = d.get_limbsize();
        size_t r_used;

        // Check for divide by zero
        if (0 == d_used) {
            return 0;
        }

        // Check for a single precision divisor that is a power of 2
        if (1 == d_used && !(d.m_limbs[0] & (d.m_limbs[0] - 1))) {
            T retval = 0;
            T ctz    = bit_manipulation::ctz(d.m_limbs[0]);
            div_r_2exp(r, n, ctz, mode);
            return r.get_limbsize() > 0;
        }

        // If the numerator is zero set the output quotient and remainder to zero
        // and return 0 to indicate a zero remainder
        if (0 == n_used) {
            r.m_limbs.resize(0);
            return 0;
        }

        // Allocate memory for the quotient if necessary
        bool q_sign = d.m_sign ^ n.m_sign;

        // If the numerator used length is less than the denominator then quickly
        // compute the quotient and remainder
        if (n_used < d_used) {
            if (mp_round_e::MP_ROUND_FLOOR == mode && q_sign) {
                // Round down required
                r.add(n, d);  // n and d have opposing signs
            }
            else if (mp_round_e::MP_ROUND_CEIL == mode && !q_sign) {
                // Round up required
                r.sub(n, d);  // n and d have the same sign
            }
            else {
                // Normal truncation
                r = n;
            }

            // Return a non-zero remainder
            return 1;
        }
        else {
            // Initialise the temporary remainder and commonly used variables
            mpz<T> temp_r = n;
            T* n_limbs = temp_r.m_limbs.data();
            const T* d_limbs = d.m_limbs.data();
            size_t q_used  = n_used - d_used + 1;

            // Obtain the quotient
            mpbase<T>::div_qr(nullptr, n_limbs, n_used, d_limbs, d_used);

            // Compensate for the most significant limb being zero and set the size
            // of the output quotient and the remainder
            size_t r_used = mpbase<T>::normalized_size(n_limbs, d_used);
            temp_r.m_limbs.resize(r_used);

            // Rounding
            if (0 != r_used) {
                if (mp_round_e::MP_ROUND_FLOOR == mode && q_sign) {
                    // Round down required
                    temp_r = temp_r + d;
                }
                else if (mp_round_e::MP_ROUND_CEIL == mode && !q_sign) {
                    // Round up required
                    temp_r = temp_r - d;
                }
            }

            temp_r.swap(r);

            // Remove significant words that are equal to zero
            r_used = r.m_limbs.size();
            while (r_used) {
                if (r.m_limbs[--r_used]) {
                    r_used++;
                    break;
                }
            }
            r.m_limbs.resize(r_used);

            if (1 == r_used && 0 == r.m_limbs[0]) {
                r.m_limbs.resize(0);
            }

            return 0 != r_used;
        }
    }

    /// Divide a numerator by a denominator and return the quotient and remainder
    static T div_qr(mpz& q, mpz& r, const mpz& n, const mpz& d, mp_round_e mode)
    {
        size_t n_used = n.get_limbsize();
        size_t d_used = d.get_limbsize();
        size_t r_used;

        // Check for divide by zero
        if (0 == d_used) {
            return 0;
        }

        // Check for a single precision divisor that is a power of 2
        if (1 == d_used && !(d.m_limbs[0] & (d.m_limbs[0] - 1))) {
            T retval = 0;
            T ctz    = bit_manipulation::ctz(d.m_limbs[0]);
            retval = div_q_2exp(q, n, ctz, mode);
            div_r_2exp(r, n, ctz, mode);
            return retval;
        }

        // If the numerator is zero set the output quotient and remainder to zero
        // and return 0 to indicate a zero remainder
        if (0 == n_used) {
            q.m_limbs.resize(0);
            r.m_limbs.resize(0);
            return 0;
        }

        // Allocate memory for the quotient if necessary
        bool q_sign = d.m_sign ^ n.m_sign;

        // If the numerator used length is less than the denominator then quickly
        // compute the quotient and remainder
        if (n_used < d_used) {
            if (mp_round_e::MP_ROUND_FLOOR == mode && q_sign) {
                // Round down required
                r = const_cast<mpz<T>&>(n) + const_cast<mpz<T>&>(d);   // n and d have opposing signs
                q = S(-1);
            }
            else if (mp_round_e::MP_ROUND_CEIL == mode && !q_sign) {
                // Round up required
                r = const_cast<mpz<T>&>(n) - const_cast<mpz<T>&>(d);   // n and d have the same sign
                q = T(1);
            }
            else {
                // Normal truncation
                r = n;
                q = T(0);
            }

            // Return a non-zero remainder
            return 1;
        }
        else {
            // Initialise the temporary remainder and commonly used variables
            mpz temp_r = n;
            T* n_limbs = temp_r.m_limbs.data();
            T* d_limbs = const_cast<mpz<T>&>(d).m_limbs.data();
            size_t q_used = n_used - d_used + 1;

            // Create a pointer to the quotient data
            mpz temp_q = mpz<T>();
            temp_q.zero_init(q_used);
            T* q_limbs = temp_q.m_limbs.data();

            // Obtain the quotient
            mpbase<T>::div_qr(q_limbs, n_limbs, n_used, d_limbs, d_used);

            // Compensate for the most significant limb being zero and set the size
            // of the output quotient and the remainder
            temp_q.m_sign = q_sign;
            size_t r_used = mpbase<T>::normalized_size(n_limbs, d_used);
            temp_r.m_limbs.resize(r_used);
            temp_r.m_sign = n.m_sign;

            // Rounding
            if (0 != r_used) {
                if (mp_round_e::MP_ROUND_FLOOR == mode && q_sign) {
                    // Round down required
                    temp_r = temp_r + d;
                    temp_q = temp_q - T(1);
                }
                else if (mp_round_e::MP_ROUND_CEIL == mode && !q_sign) {
                    // Round up required
                    temp_r = temp_r - d;
                    temp_q = temp_q + T(1);
                }
            }

            temp_q.swap(q);
            temp_r.swap(r);
            if (1 == q_used && 0 == q.m_limbs[0]) {
                q.m_limbs.resize(0);
            }
            if (1 == r_used && 0 == r.m_limbs[0]) {
                r.m_limbs.resize(0);
            }

            return 0 != r_used;
        }
    }

    /// Divide a numerator by a unsigned integer denominator and return the quotient and remainder
    static T div_qr_ui(mpz& q, mpz& r, const mpz& n, T d, mp_round_e mode)
    {
        // If the numerator is zero set the output quotient and remainder to zero
        // and return 0
        size_t n_used = n.get_limbsize();
        if (0 == n_used) {
            q.m_limbs.resize(0);
            q.m_sign = false;
            r.m_limbs.resize(0);
            r.m_sign = false;
            return 0;
        }

        // Allocate memory for the quotient if necessary
        size_t q_used = n.get_limbsize();
        q.m_limbs.resize(q_used);
        T* q_limbs = q.m_limbs.data();

        // Obtain the result of q / d
        const T* n_limbs = n.m_limbs.data();
        T  r_lsw   = mpbase<T>::div_qr_1(q_limbs, n_limbs, q_used, d);
        size_t r_used = r_lsw > 0;
        bool   r_sign = n.m_sign;

        // If q/d is non-zero then apply rounding
        if (r_lsw > 0) {
            if ((mp_round_e::MP_ROUND_FLOOR == mode && n.m_sign) ||
                (mp_round_e::MP_ROUND_CEIL  == mode && !n.m_sign)) {
                mpbase<T>::add_1(q_limbs, q_limbs, q_used, 1);
                r_lsw   = d - r_lsw;
                r_sign ^= true;
            }
        }

        // If a remainder is to be output then (re)allocate memory and configure
        // the LSW and length for a single output word
        r.m_sign     = r_sign;
        r.m_limbs.resize(r_used);
        if (r_used) {
            r.m_limbs[0] = r_lsw;
        }

        // a quotient is to be output then update the used length
        q.m_limbs.resize(q_used - (0 == q_limbs[q_used-1]));
        q.m_sign     = n.m_sign;

        return r_lsw;
    }

    /// Divide a numerator by a unsigned integer denominator and return the remainder
    static T div_ui(const mpz& n, T d, mp_round_e mode)
    {
        // If the numerator is zero set the output quotient and remainder to zero
        // and return 0
        size_t n_used = n.get_limbsize();
        if (0 == n_used) {
            return 0;
        }

        // Allocate memory for the quotient if necessary
        size_t q_used  = n_used;
        T*     q_limbs = nullptr;

        // Obtain the result of q / d
        const T* n_limbs = n.m_limbs.data();
        T  r_lsw   = mpbase<T>::div_qr_1(q_limbs, n_limbs, q_used, d);
        size_t r_used = r_lsw > 0;
        bool   r_sign = n.m_sign;

        // If q/d is non-zero then apply rounding
        if (r_lsw > 0) {
            if ((mp_round_e::MP_ROUND_FLOOR == mode && n.m_sign) ||
                (mp_round_e::MP_ROUND_CEIL  == mode && !n.m_sign)) {
                r_lsw   = d - r_lsw;
                r_sign ^= true;
            }
        }

        return r_lsw;
    }

    /// Divide a numerator by a unsigned integer denominator and return the
    /// remainder as an unsigned integer and the quotient as an mpz object
    static T div_q_ui(mpz& q, const mpz& n, T d, mp_round_e mode)
    {
        // If the numerator is zero set the output quotient and remainder to zero
        // and return 0
        size_t n_used = n.get_limbsize();
        if (0 == n_used) {
            q.m_limbs.resize(0);
            q.m_sign  = false;
            return 0;
        }

        // Allocate memory for the quotient if necessary
        size_t q_used = n_used;
        q.m_limbs.resize(q_used);
        T* q_limbs   = q.m_limbs.data();

        // Obtain the result of q / d
        T* n_limbs = const_cast<T*>(n.m_limbs.data());
        T  r_lsw   = mpbase<T>::div_qr_1(q_limbs, n_limbs, q_used, d);
        size_t r_used = r_lsw > 0;
        bool   r_sign = n.m_sign;

        // If q/d is non-zero then apply rounding
        if (r_lsw > 0) {
            if ((mp_round_e::MP_ROUND_FLOOR == mode && n.m_sign) ||
                (mp_round_e::MP_ROUND_CEIL  == mode && !n.m_sign)) {
                mpbase<T>::add_1(q_limbs, q_limbs, q_used, 1);
                r_lsw = d - r_lsw;
            }
        }

        // a quotient is to be output then update the used length
        q_used = mpbase<T>::normalized_size(q.m_limbs.data(), q_used);
        q.m_limbs.resize(q_used);
        q.m_sign = n.m_sign;

        return r_lsw;
    }

    /// Divide a numerator by a unsigned integer denominator and return the
    /// remainder as an unsigned integer and an mpz object
    static T div_r_ui(mpz& r, const mpz& n, T d, mp_round_e mode)
    {
        // If the numerator is zero set the output quotient and remainder to zero
        // and return 0
        size_t n_used = n.get_limbsize();
        if (0 == n_used) {
            r.m_limbs.resize(0);
            r.m_sign  = false;
            return 0;
        }

        // Allocate memory for the quotient if necessary
        size_t q_used = n.get_limbsize();

        // Obtain the result of q / d
        T* n_limbs = const_cast<T*>(n.m_limbs.data());
        T  r_lsw   = mpbase<T>::div_qr_1(nullptr, n_limbs, q_used, d);
        size_t r_used = r_lsw > 0;
        bool   r_sign = n.m_sign;

        // If q/d is non-zero then apply rounding
        if (r_lsw > 0) {
            if ((mp_round_e::MP_ROUND_FLOOR == mode && n.m_sign) ||
                (mp_round_e::MP_ROUND_CEIL  == mode && !n.m_sign)) {
                r_lsw   = d - r_lsw;
                r_sign ^= true;
            }
        }

        // If a remainder is to be output then (re)allocate memory and configure
        // the LSW and length for a single output word
        r.m_sign     = r_sign;
        r.m_limbs.resize(r_used);
        if (r_used) {
            r.m_limbs[0] = r_lsw;
        }

        return r_lsw;
    }

    static T fdiv_qr(mpz& q, mpz& r, const mpz& n, const mpz& d)
    {
        return div_qr(q, r, n, d, mp_round_e::MP_ROUND_FLOOR);
    }

    static T tdiv_qr(mpz& q, mpz& r, const mpz& n, const mpz& d)
    {
        return div_qr(q, r, n, d, mp_round_e::MP_ROUND_TRUNC);
    }

    static T fdiv_q(mpz& q, const mpz& n, const mpz& d)
    {
        return div_q(q, n, d, mp_round_e::MP_ROUND_FLOOR);
    }

    static T tdiv_q(mpz& q, const mpz& n, const mpz& d)
    {
        return div_q(q, n, d, mp_round_e::MP_ROUND_TRUNC);
    }

    static T fdiv_r(mpz& r, const mpz& n, const mpz& d)
    {
        return div_r(r, n, d, mp_round_e::MP_ROUND_FLOOR);
    }

    static T tdiv_r(mpz& r, const mpz& n, const mpz& d)
    {
        return div_r(r, n, d, mp_round_e::MP_ROUND_TRUNC);
    }

    static T fdiv_qr_ui(mpz& q, mpz& r, const mpz& n, T d)
    {
        return div_qr_ui(q, r, n, d, mp_round_e::MP_ROUND_FLOOR);
    }

    static T fdiv_q_ui(mpz& q, const mpz& n, T d)
    {
        return div_q_ui(q, n, d, mp_round_e::MP_ROUND_FLOOR);
    }

    static T fdiv_r_ui(mpz& r, const mpz& n, T d)
    {
        return div_r_ui(r, n, d, mp_round_e::MP_ROUND_FLOOR);
    }

    static T tdiv_qr_ui(mpz& q, mpz& r, const mpz& n, T d)
    {
        return div_qr_ui(q, r, n, d, mp_round_e::MP_ROUND_TRUNC);
    }

    static T tdiv_q_ui(mpz& q, const mpz& n, T d)
    {
        return div_q_ui(q, n, d, mp_round_e::MP_ROUND_TRUNC);
    }

    static T tdiv_r_ui(mpz& r, const mpz& n, T d)
    {
        return div_r_ui(r, n, d, mp_round_e::MP_ROUND_TRUNC);
    }

    static T tdiv_q_2exp(mpz& q, const mpz& n, T b)
    {
        return div_q_2exp(q, n, b, mp_round_e::MP_ROUND_TRUNC);   // TRUNC(n/(2^b))
    }

    static T fdiv_q_2exp(mpz& q, const mpz& n, T b)
    {
        return div_q_2exp(q, n, b, mp_round_e::MP_ROUND_FLOOR);   // FLOOR(n/(2^b))
    }

    static T cdiv_ui(const mpz& n, T d)
    {
        return div_ui(n, d, mp_round_e::MP_ROUND_CEIL);
    }

    static T fdiv_ui(const mpz& n, T d)
    {
        return div_ui(n, d, mp_round_e::MP_ROUND_FLOOR);
    }

    static T tdiv_ui(const mpz& n, T d)
    {
        return div_ui(n, d, mp_round_e::MP_ROUND_TRUNC);
    }

    static void divexact(mpz& q, const mpz& n, const mpz& d)
    {
        div_q(q, n, d, mp_round_e::MP_ROUND_TRUNC);
    }

    static void divexact_ui(mpz& q, const mpz& n, T d)
    {
        div_q_ui(q, n, d, mp_round_e::MP_ROUND_TRUNC);
    }

    /**
     * @brief Greatest Common Divisor
     * @param rhs mpz object to compare with
     * @return mpz<T> GCD
     */
    mpz<T> gcd(const mpz<T>& rhs) const
    {
        mpz g;

        // If either input is zero then the GCD is the absolute value of the other input
        if (0 == this->get_limbsize()) {
            g = rhs.abs();
            return g;
        }
        if (0 == rhs.get_limbsize()) {
            g = this->abs();
            return g;
        }

        // Normalise the absolute input variables and store in temporary storage
        mpz tu = this->abs();
        size_t uz = make_odd(tu);
        mpz tv = rhs.abs();
        size_t vz = make_odd(tv);

        // Obtain the minimum normalisation bit shift
        size_t gz = (uz < vz)? uz : vz;

        // Ensure that normalised u is the largest input for the following
        // division to return a non-zero result
        if (tu.get_limbsize() < tv.get_limbsize()) {
            tu.swap(tv);
        }

        // Obtain the remainder of N(|u|)/N(|v))
        mpz r;
        tdiv_r(r, tu, tv);
        if (0 == r.get_limbsize()){
            // If the remainder is zero then the GCD is N(|v|), pre-scaled by gz
            g.swap(tv);
        }
        else {
            // Iteratively update the remainder until it is zero or
            // the denominator is single-precision
            while (1) {
                make_odd(r);
                int32_t c = r.cmp(tv);
                if (0 == c) {
                    g.swap(r);
                    break;
                }
                if (c < 0) {
                    r.swap(tv);
                }

                if (1 == tv.get_limbsize()) {
                    T vl = tv[0];
                    T ul = tdiv_ui(r, vl);
                    g = number<T>::ugcd(ul, vl);
                    break;
                }
                r.sub(r, tv);
            }
        }

        // Scale the GCD result by gz normalization bits
        r = g.mul_2exp(gz);

        return r;
    }

    /**
     * @brief Extended GCD, i.e. su + tv = gcd(s,t)
     * @param out GCD
     * @param s Output parameter s
     * @param t Output parameter t
     * @param u Input parameter u (will be modified)
     * @param v Input parameter v (will be modified)
     */
    static void gcdext(mpz& out, mpz& s, mpz& t, mpz& u, mpz& v)
    {
        if (0 == u.get_limbsize()) {
            // GCD = 0.u + sgn(v).v
            int32_t sign = v.cmp_ui(0);
            out = v.abs();
            s = T(0);
            t = S(sign);
            return;
        }

        if (0 == v.get_limbsize()) {
            // GCD = sgn(u).u + 0.v
            int32_t sign = u.cmp_ui(0);
            out = u.abs();
            s = S(sign);
            t = T(0);
            return;
        }

        // Normalise the absolute input variables and store in temporary storage
        mpz tu = u.abs();
        size_t uz = make_odd(tu);
        mpz tv = v.abs();
        size_t vz = make_odd(tv);
        size_t gz = (uz < vz)? uz : vz;
        uz -= gz;
        vz -= gz;

        // Cofactors corresponding to odd gcd
        bool swap = false;
        if (tu.get_limbsize() < tv.get_limbsize()) {
            swap = true;
            tu.swap(tv);

            mpz temp = u;
            u = v;
            v = temp;
            temp = s;
            s = t;
            t = temp;
            size_t temp2 = uz;
            uz = vz;
            vz = temp2;
        }

        // u = t0.tu + t1.tv, v = s0.tu + s1.tv
        //
        // tu = q.tv + tu', tu and tv are scaled by uz and vz bits respectively
        //   => u = 2^uz (tu' + q.tv) and v = 2^vz tv
        //
        // So we must initialise the variables as follows:
        //   t0 = 2^uz, t1 = 2^uz.q, s0 = 0, s1 = 2^vz
        mpz s0, s1, t0, t1, temp;
        t0.setbit(uz);
        temp = tu;
        tdiv_qr(t1, tu, temp, tv);
        t1 = t1.mul_2exp(uz);
        s1.setbit(vz);
        size_t power = uz + vz;

        if (tu.get_limbsize() > 0) {
            size_t shift = make_odd(tu);
            t0 = t0.mul_2exp(shift);
            s0 = s0.mul_2exp(shift);
            power += shift;

            while (1) {
                int32_t c = tu.cmp(tv);
                if (0 == c) {
                    break;
                }

                if (c < 0) {
                    tv.sub(tv, tu);
                    t0.add(t1, t0);
                    s0.add(s1, s0);

                    shift = make_odd(tv);
                    t1 = t1.mul_2exp(shift);
                    s1 = s1.mul_2exp(shift);
                }
                else {
                    tu.sub(tu, tv);
                    t1.add(t0, t1);
                    s1.add(s0, s1);

                    shift = make_odd(tu);
                    t0 = t0.mul_2exp(shift);
                    s0 = s0.mul_2exp(shift);
                }

                power += shift;
            }
        }

        // Now tv = odd part of gcd, and -s0 and t0 are corresponding cofactors
        tv = tv.mul_2exp(gz);
        s0.negate();

        // 2^p g = s0 u + t0 v. Eliminate one factor of two at a time. To
        // adjust cofactors, we need u/g and v/g
        temp = v;
        divexact(s1, temp, tv);
        s1 = s1.abs();
        temp = u;
        divexact(t1, temp, tv);
        t1 = t1.abs();

        while (power-- > 0) {
            // s0 u + t0 v = (s0 - v/g) u - (t0 + u/g) v
            if ((s0.get_limbsize()? 1 & s0[0] : 0) || (t0.get_limbsize()? 1 & t0[0] : 0)) {
                s0.sub(s0, s1);
                t0.add(t0, t1);
            }
            temp = s0;
            divexact_ui(s0, temp, 2);
            temp = t0;
            divexact_ui(t0, temp, 2);
        }

        // Arrange so that |s| < |u| / 2g
        s1.add(s0, s1);
        if (s0.cmpabs(s1) > 0) {
            s0.swap(s1);
            t0.sub(t0, t1);
        }
        if (u.is_negative()) {
            s0.negate();
        }
        if (v.is_negative()) {
            t0.negate();
        }

        out.swap(tv);
        s.swap(s0);
        t.swap(t0);
        if (swap) {
            s.swap(t);
        }
    }

    /**
     * @brief Calculate the modular multiplicative inverse using the Extended Euclidean algorithm
     * @param mod The modulus to be used
     * @return mpz& Modular multiplicative inverse
     */
    mpz& invert(const mpz& mod)
    {
        if (!invert(*this, *this, mod)) {
            throw std::runtime_error("Inversion is not possible");
        }
        return *this;
    }

    /**
     * @brief Calculate the modular multiplicative inverse using the Extended Euclidean algorithm
     * @param out Modular multiplicative inverse 
     * @param in Value to be inverted
     * @param mod The modulus to be used
     * @return bool True if invertible, false otherwise
     */
    static bool invert(mpz& out, const mpz& in, const mpz& mod)
    {
        // If we try to invert zero or the modulus is 0 the result is indeterminate
        if (0 == in.get_limbsize() || 0 == mod.get_limbsize()) {
            return false;
        }

        // Calculate XGCD(in, mod), the GCD must be 1 for an inverse to exist
        mpz gcd, dummy, in_copy(in), mod_copy(mod);
        gcdext(gcd, out, dummy, in_copy, mod_copy);

        // If an inverse exists we use the Bezout coefficient to calculate it
        if (1 == gcd.get_limbsize() && 1 == gcd.get_ui()) {
            // i.e. ax + my = gcd(a,m) = 1
            //   => ax + my = 1
            //      ax - 1 = (-y)m
            //      ax = 1 mod m, where x is the modular multiplicative inverse of a

            // If the inverse is negative the absolute value of the modulus is added
            if (out.is_negative()) {
                if (mod.is_negative()) {
                    out.sub(mod);
                }
                else {
                    out.add(mod);
                }
            }

            return true;
        }

        return false;
    }

    /**
     * @brief Barrett reduction
     * @param cfg A mod_config object describing the modulus
     * @return mpz<T>& A reference to the reduced mpz object
     */
    mpz<T>& barrett(const mod_config<T>& cfg)
    {
        if (m_sign) {
            size_t a_bits = this->sizeinbase(2);
            size_t m_bits = cfg.mod_bits;
            size_t bits   = (a_bits <= m_bits)? 0 : a_bits - m_bits;
            if (bits) {
                mpz<T> a(cfg.mod);
                a.mul_2exp(bits + 1);
                add(*this, a);
            }
            else {
                this->mod_positive(cfg);
            }
        }
        assert(!m_sign);

        // q1 = floor(in / b^(k-1))    i.e. right shift (k-1) words
        // q2 = q1 * mu
        // q3 = floor(q2 / b^(k+1))    i.e. right shift (k+1) words, or truncate the (k+1) least significant words of q2
        // r1 = in mod b^(k+1)          i.e. mask of the least significant (k+1) words
        // r2 = (q3 * m) mod b^(k+1)   i.e. mask of the least significant (k+1) words
        // r  = r1 - r2
        // if (r < 0)
        //   r += b^(k+1)
        // while (r >= m)
        //   r -= m
        mpz<T> q1;
        mpz<T> q2;
        mpz<T> q3;
        q1 = *this;
        q1 >>= T(cfg.blog2*(cfg.k-1));
        q2 = q1 * cfg.mod_inv;
        q2 >>= T(cfg.blog2*(cfg.k+1));
        q3 = q2 * cfg.mod;

        q1 = this->mod_2exp(cfg.blog2*(cfg.k+1));
        q3.mod_2exp(cfg.blog2*(cfg.k+1));
        *this = q1 - q3;

        if (this->is_negative()) {
            mpz<T> temp;
            temp.setbit(cfg.blog2*(cfg.k+1));
            this->add(*this, temp);
        }
        assert(!this->is_negative());

        // Scale
        while (*this >= cfg.mod) {
            mpz<T> temp = cfg.mod;
            size_t a_bits = this->sizeinbase(2);
            size_t m_bits = cfg.mod_bits;
            size_t bits   = (a_bits <= m_bits)? 0 : a_bits - m_bits - 1;
            if (bits) {
                temp.lshift(cfg.mod, bits);
            }

            *this = *this - temp;
        }
        assert(!this->is_negative());

        size_t used = mpbase<T>::normalized_size(this->m_limbs.data(), this->m_limbs.size());
        this->m_limbs.resize(used);

        return *this;
    }

    /**
     * @brief Modular reduction using optimized division
     * @param cfg A mod_config object describing the modulus
     * @return mpz<T>& A reference to the reduced mpz object
     */
    mpz<T>& mod(const mod_config<T>& cfg)
    {
        mpz<T> n = *this;
        div_r(*this, n, cfg.mod, cfg.mod.is_negative()? mp_round_e::MP_ROUND_CEIL : mp_round_e::MP_ROUND_FLOOR);
        return *this;
    }

    /**
     * @brief Modular reduction using simple addition/subtraction of the modulus
     * This should be used carefully to avoid exhaustive computation.
     * @param cfg A mod_config object describing the modulus
     * @return mpz<T>& A reference to the reduced mpz object
     */
    mpz<T>& mod_positive(const mod_config<T>& cfg)
    {
        while (this->is_negative()) {
            this->add(*this, cfg.mod);
        }
        while (*this >= cfg.mod) {
            this->sub(*this, cfg.mod);
        }
        return *this;
    }

    /**
     * @brief Modular reduction with a modulus equal to 2^bits
     * @param bits The number of bits in the modulus
     * @return mpz<T>& A reference to the reduced mpz object
     */
    mpz<T>& mod_2exp(size_t bits)
    {
        size_t in_used = get_limbsize();
        if (0 == in_used || 0 == bits) {
            m_limbs.resize(0);
            m_sign = false;
            return *this;
        }

        // This multiply corresponds to a left shift by 'bits', so determine the number of
        // words and bits to shift
        size_t mask_words = bits >> bits_log2<T>::value();              // Divide by limb bits
        T      mask_bits  = bits & ((1 << bits_log2<T>::value()) - 1);  // Modulo 2 ^ limb bits

        if ((mask_words + (0 != mask_bits)) <= m_limbs.size()) {
            m_limbs.resize(mask_words + (0 != mask_bits));
            if (mask_bits) {
                m_limbs[mask_words] &= (1 << mask_bits) - 1;
            }
        }

        size_t used = mpbase<T>::normalized_size(m_limbs.data(), m_limbs.size());
        m_limbs.resize(used);
        m_sign = false;

        return *this;
    }

    /**
     * @brief Reduction using the configured reduction method
     * @param cfg A mod_config object describing the modulus
     * @return mpz<T>& A reference to the reduced mpz object
     */
    mpz<T>& reduce(const mod_config<T>& cfg)
    {
        if (cfg.reduction == REDUCTION_CUSTOM) {
            return cfg.cst->reduce(*this, cfg);
        }
        else {
            if (m_sign) {
                size_t a_bits   = this->sizeinbase(2);
                size_t mod_bits = cfg.mod_bits;
                size_t bits     = (a_bits <= mod_bits)? 0 : a_bits - mod_bits;
                if (bits) {
                    mpz<T> a(cfg.mod);
                    a.mul_2exp(bits + 1);
                    *this = *this + a;
                    a_bits = this->sizeinbase(2);
                }
                else {
                    this->mod_positive(cfg);
                }
                assert(!m_sign);
            }

            assert(!m_sign);
            if (*this < cfg.mod) {
                return *this;
            }
            else {
                switch (cfg.reduction)
                {
                    case REDUCTION_BARRETT:
                    {
                        return this->barrett(cfg);
                    } break;

                    case REDUCTION_MONTGOMERY:
                    {
                        return this->reduce_mont(cfg);
                    } break;

                    case REDUCTION_NAIVE:
                    {
                        return this->mod(cfg);
                    } break;

                    default: {}
                }
            }
        }

        return *this;
    }

    /**
     * @brief Montgomery reduction of an mpz integer
     * @param cfg A mod_config object describing the modulus
     * @return mpz<T>& A reference to the reduced mpz object
     */
    mpz<T>& reduce_mont(const mod_config<T>& cfg)
    {
        m_scratch.resize(2 * cfg.k);
        int32_t used = mpz_core<T>::reduce_mont(m_scratch.data(), this->m_limbs.data(), this->m_limbs.size(),
            cfg.mod.get_limbs().data(), cfg.k, cfg.mont_inv);
        this->m_limbs.swap(m_scratch);

        m_limbs.resize(used);
        m_sign = false;

        return *this;
    }


    /// @}
};

// Explicit specialization of get_bytes() for uint8_t
template <>
void mpz<uint8_t>::get_bytes(phantom_vector<uint8_t> &bytes, bool little_endian) const;


// Forward declaration of common sizes
extern template class mpz<uint8_t>;
extern template class mpz<uint16_t>;
extern template class mpz<uint32_t>;
#if defined(IS_64BIT)
extern template class mpz<uint64_t>;
#endif


}  // namespace core
}  // namespace phantom
