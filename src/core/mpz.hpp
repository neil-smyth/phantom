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


enum miller_rabin_status_e {
        MILLER_RABIN_PROBABLY_PRIME = 0,
        MILLER_RABIN_COMPOSITE_WITH_FACTOR,
        MILLER_RABIN_COMPOSITE_NOT_POWER_OF_PRIME,
        MILLER_RABIN_ERROR
    };

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
    bool is_zero() const override;

    /// Return a flag indicating that the mpz object is one
    bool is_one() const override;

    /// Return a flag indicating that the mpz object is negative
    bool is_negative() const override;

    /// Set the sign flag to the defined value
    void set_sign(bool sign) override;

    // Memory pre-allocation and value set to zero
    void zero_init(size_t n) override;

    /// Return a flag indicating if the defined bit is asserted
    bool tstbit(size_t bit_index) const;

    void setbit(size_t bit_index);

    void unsetbit(size_t bit_index);

    static size_t make_odd(mpz &r);

    T get_ui() const;

    S get_si() const;

    double get_d() const;

    void get_bytes(phantom_vector<uint8_t> &bytes, bool little_endian = false) const override;

    void set_bytes(const phantom_vector<uint8_t> &bytes, bool little_endian = false) override;

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

    std::string get_str(size_t base, bool uppercase = false) const override;

    const phantom_vector<T> &get_limbs() const override;

    phantom_vector<T> &get_limbs() override;

    /// @}



    /// Comparative methods
    /// @{

    /// Compare two mpz objects (using references to base class objects)
    virtual int32_t cmp(const mp<T>& in) const;

    /// Compare to a double value (double is converted to integer and rounded towards zero)
    int32_t cmp_d(double in) const;

    /// Compare to an unsigned integer
    virtual int32_t cmp_ui(T in) const;

    /// Compare to a signed integer
    virtual int32_t cmp_si(S in) const;

    /// Compare two mpz objects in terms of the absolute magnitude
    virtual int32_t cmpabs(const mp<T>& in) const;

    /// Compare an mpz object and a double in terms of their absolute magnitudes
    virtual int32_t cmpabs_d(double in) const;

    // Calculate the integer size in bits of the mpz object given a specific base
    virtual size_t sizeinbase(size_t base) const;

    /// Swap the mpz pbjects
    virtual void swap(mp<T>& in);  // NOLINT;

    /// Return the number of limb words used by the mpz object
    virtual size_t get_limbsize() const;

    /// @}



    /// Logical methods
    /// @{

    /**
     * @brief Bitwise AND of the two mpz objects
     */
    void bitwise_and(const mpz<T>& in1, const mpz<T>& in2);

    /**
     * @brief Bitwise OR of the two mpz objects
     */
    void bitwise_or(const mpz<T>& in1, const mpz<T>& in2);

    /**
     * @brief Bitwise exclusive-OR of the two mpz objects
     */
    void bitwise_xor(const mpz<T>& in1, const mpz<T>& in2);

    /**
     * @brief Bitwise left shift of an mpz integer
     */
    void lshift(const mpz<T>& in1, const int bits);

    /**
     * @brief Bitwise right shift of an mpz integer
     */
    void rshift(const mpz<T>& in1, const int bits);

    /**
     * @brief Calculate the Hamming weight of the mpz object (i.e. number of asserted
     * bits in the absolute representation)
     */
    size_t hamming_weight() const;

    /**
     * @brief Miller-Rabin primality test
     * @param prng A reference to the CSPRNG to be used
     * @param p The mpz object to be tested
     * @param iterations The maximum number of test iterations to be used
     * @return miller_rabin_status_e Primality status of the mpz object tested
     */
    static miller_rabin_status_e prime_miller_rabin(csprng& prng, const mpz<T>& p, size_t iterations);

    /**
     * @brief Check the primality of an mpz object with optional trial divisions
     * @param prng A reference to the CSPRNG to be used
     * @param p mpz object to be tested
     * @param bits Size in bits of the mpz number
     * @param trial_division The number of trial divisions to be performed initally
     * @return bool True if prime, false otherwise
     */
    static bool check_prime(csprng& prng, const mpz<T>& p, size_t bits, bool trial_division);

    /// @}



    /// Additive methods
    /// @{

    /// Negate the mpz object
    mpz<T>& negate();

    /// Calculate the absolute of the mpz object
    mpz abs() const;

    /// Add the two mpz integers as absolute values
    int32_t abs_add(const mpz& in1, const mpz& in2);

    /// Subtract the two mpz integers as absolute values
    int32_t abs_sub(const mpz& in1, const mpz& in2);

    /// Add an mpz integer and an unsigned integer as absolute values
    int32_t abs_add(const mpz& in1, T in2);

    /// Subtract an mpz integer and an unsigned integer as absolute values
    int32_t abs_sub(const mpz& in1, T in2);

    /// Add an unsigned integer to an mpz object
    void add(const mpz<T>& in1, T in2);

    /// Subtract an unsigned integer from an mpz object
    void sub(const mpz<T>& in1, T in2);

    /// Add an unsigned integer to an mpz object
    mpz<T>& add(T in2);

    /// Subtract an unsigned integer from an mpz object
    mpz<T>& sub(T in2);

    /// Add an mpz object to an mpz object
    void add(const mpz<T>& in1, const mpz<T>& in2);

    /// Subtract an mpz object from an mpz object
    void sub(const mpz<T>& in1, const mpz<T>& in2);

    /// Add an mpz object to an mpz object
    mpz<T>& add(const mpz<T>& in2);

    /// Subtract an mpz object from an mpz object
    mpz<T>& sub(const mpz<T>& in2);

    /// Add an mpz object and reduce
    mpz<T>& add_mod(const mpz<T>& in2, const mod_config<T>& cfg);

    /// Subtract an mpz object and reduce
    mpz<T>& sub_mod(const mpz<T>& in2, const mod_config<T>& cfg);

    /// @}



    /// Multiplicative methods
    /// @{

    /// Multiply an mpz object by 2*bits
    mpz<T>& mul_2exp(size_t bits);

    /// Multiply an mpz object by an unsigned integer
    static void mul_ui(mpz& out, const mpz& in1, T in2);

    /// Multiply an mpz object by a signed integer
    static void mul_si(mpz& out, const mpz& in1, S in2);

    /// Multiply an mpz object by an mpz object
    static void mul(mpz& out, const mpz& in1, const mpz<T>& in2);

    /// Multiply an mpz object by an mpz object
    mpz<T>& mul_mod(const mpz<T>& in2, const mod_config<T>& cfg);

    /// Multiply an mpz object by an mpz object
    mpz<T>& mul_mod(const mpz<T>& in1, const mpz<T>& in2, const mod_config<T>& cfg);

    // Montgomery multiplication of an mpz integer with another
    mpz<T>& mul_mont(const mpz<T>& in2, const mod_config<T>& cfg);

    /// Calculate the square root of an mpz object
    /// NOTE: the square root of a negative number is indeterminate and a zero is returned
    mpz sqrt() const;

    /**
     * @brief Legendre symbol calculation
     * @param a Number a to be 
     * @param b 
     * @return int Legendre symbol of 1, 0 or -1
     */
    static int legendre(const mpz<T>& a, const mpz<T>& b);

    /**
     * @brief Check if a is divisible by d
     * @param a Dividend
     * @param d Denominator
     * @return int 1 if there is a remainder, 0 otherwise
     */
    static int divisible_p(const mpz<T>& a, const mpz<T>& d);

    /**
     * @brief Tonelli-Shanks algorithm, find a square root of n modulo p
     * 
     * @param cfg A mod_config object defining the modulus p
     * @param r Square root
     * @param n Input integer
     * @return bool True if a square root was found, false otherwise
     */
    static bool tonelli_shanks(const mod_config<T>& cfg, mpz<T>& r, const mpz<T>& n);

    /**
     * @brief Calculate the square root modulo p
     * NOTE: Throws a runtime_error exception if a msquare root was not found.
     * @param cfg A mod_config object describing the modulus p
     * @return mpz<T>& A reference to the square root
     */
    mpz<T>& sqrt_mod(const mod_config<T>& cfg);

    /// Calculate the square of an mpz object
    mpz<T>& square();

    /// Calculate the square of an mpz object modulo p
    mpz<T>& square_mod(const mod_config<T>& cfg, size_t w = 1);

    // Montgomery squaring of the mpz object
    mpz<T>& square_mont(const mod_config<T>& cfg);

    /// Calculate the mpz object raised to the power of e
    mpz<T>& pow(T e);

    /// Calculate the mpz object raised to the power of e
    mpz<T>& pow_mod(T e, const mod_config<T>& cfg);

    /// Montgomery exponentiation of an mpz integer raised to the power of another
    mpz<T>& pow_mont(T e, const mod_config<T>& cfg);

    /// Modular exponentiation
    mpz<T>& pow_mod(const mpz<T>& e, const mod_config<T>& cfg);

    /// Explicit modular exponentiation of mpz objects, r = b^e mod m
    static void powm(mpz<T>& r, const mpz<T>& b, const mpz<T>& e, const mpz<T>& m);

    /// Divide the numerator by 2^bits and return the quotient
    static T div_q_2exp(mpz& q, const mpz& n, T bits, mp_round_e mode);

    /// Divide the numerator by 2^bits and return the remainder
    static void div_r_2exp(mpz& r, const mpz& n, T bits, mp_round_e mode);

    /// Divide a numerator by a denominator and return the quotient
    static T div_q(mpz& q, const mpz& n, const mpz& d, mp_round_e mode);

    /// Divide a numerator by a denominator and return the remainder
    static T div_r(mpz<T>& r, const mpz<T>& n, const mpz<T>& d, mp_round_e mode);

    /// Divide a numerator by a denominator and return the quotient and remainder
    static T div_qr(mpz& q, mpz& r, const mpz& n, const mpz& d, mp_round_e mode);

    /// Divide a numerator by a unsigned integer denominator and return the quotient and remainder
    static T div_qr_ui(mpz& q, mpz& r, const mpz& n, T d, mp_round_e mode);

    /// Divide a numerator by a unsigned integer denominator and return the remainder
    static T div_ui(const mpz& n, T d, mp_round_e mode);

    /// Divide a numerator by a unsigned integer denominator and return the
    /// remainder as an unsigned integer and the quotient as an mpz object
    static T div_q_ui(mpz& q, const mpz& n, T d, mp_round_e mode);

    /// Divide a numerator by a unsigned integer denominator and return the
    /// remainder as an unsigned integer and an mpz object
    static T div_r_ui(mpz& r, const mpz& n, T d, mp_round_e mode);

    /// Division with flooring to obtain quotient and remainder
    static T fdiv_qr(mpz& q, mpz& r, const mpz& n, const mpz& d);

    /// Division with truncation to obtain quotient and remainder
    static T tdiv_qr(mpz& q, mpz& r, const mpz& n, const mpz& d);

    /// Division with flooring to obtain quotient
    static T fdiv_q(mpz& q, const mpz& n, const mpz& d);

    /// Division with truncation to obtain quotient
    static T tdiv_q(mpz& q, const mpz& n, const mpz& d);

    /// Division with flooring to obtain remainder
    static T fdiv_r(mpz& r, const mpz& n, const mpz& d);

    /// Division with truncation to obtain remainder
    static T tdiv_r(mpz& r, const mpz& n, const mpz& d);

    /// Division by single-word with flooring to obtain quotient and remainder
    static T fdiv_qr_ui(mpz& q, mpz& r, const mpz& n, T d);

    /// Division by single-word with flooring to obtain quotient
    static T fdiv_q_ui(mpz& q, const mpz& n, T d);

    /// Division by single-word with flooring to obtain remainder
    static T fdiv_r_ui(mpz& r, const mpz& n, T d);

    /// Division by single-word with truncation to obtain quotient and remainder
    static T tdiv_qr_ui(mpz& q, mpz& r, const mpz& n, T d);

    /// Division by single-word with truncation to obtain quotient
    static T tdiv_q_ui(mpz& q, const mpz& n, T d);

    /// Division by single-word with truncation to obtain remainder
    static T tdiv_r_ui(mpz& r, const mpz& n, T d);

    /// Division 2^b with flooring to obtain quotient
    static T fdiv_q_2exp(mpz& q, const mpz& n, T b);

    /// Division 2^b with truncation to obtain quotient
    static T tdiv_q_2exp(mpz& q, const mpz& n, T b);

    /// Division (ceiling) of mpz numerator with single-word denominator
    static T cdiv_ui(const mpz& n, T d);

    /// Division (floor) of mpz numerator with single-word denominator
    static T fdiv_ui(const mpz& n, T d);

    /// Division (truncation) of mpz numerator with single-word denominator
    static T tdiv_ui(const mpz& n, T d);

    /**
     * @brief Greatest Common Divisor
     * @param rhs mpz object to compare with
     * @return mpz<T> GCD
     */
    mpz<T> gcd(const mpz<T>& rhs) const;

    /**
     * @brief Extended GCD, i.e. su + tv = gcd(s,t)
     * @param out GCD
     * @param s Output parameter s
     * @param t Output parameter t
     * @param u Input parameter u (will be modified)
     * @param v Input parameter v (will be modified)
     */
    static void gcdext(mpz& out, mpz& s, mpz& t, mpz& u, mpz& v);

    /**
     * @brief Calculate the modular multiplicative inverse using the Extended Euclidean algorithm
     * @param mod The modulus to be used
     * @return mpz& Modular multiplicative inverse
     */
    mpz& invert(const mpz& mod);

    /**
     * @brief Calculate the modular multiplicative inverse using the Extended Euclidean algorithm
     * @param out Modular multiplicative inverse 
     * @param in Value to be inverted
     * @param mod The modulus to be used
     * @return bool True if invertible, false otherwise
     */
    static bool invert(mpz& out, const mpz& in, const mpz& mod);

    /**
     * @brief Barrett reduction
     * @param cfg A mod_config object describing the modulus
     * @return mpz<T>& A reference to the reduced mpz object
     */
    mpz<T>& barrett(const mod_config<T>& cfg);

    /**
     * @brief Modular reduction using optimized division
     * @param cfg A mod_config object describing the modulus
     * @return mpz<T>& A reference to the reduced mpz object
     */
    mpz<T>& mod(const mod_config<T>& cfg);

    /**
     * @brief Modular reduction using simple addition/subtraction of the modulus
     * This should be used carefully to avoid exhaustive computation.
     * @param cfg A mod_config object describing the modulus
     * @return mpz<T>& A reference to the reduced mpz object
     */
    mpz<T>& mod_positive(const mod_config<T>& cfg);

    /**
     * @brief Modular reduction with a modulus equal to 2^bits
     * @param bits The number of bits in the modulus
     * @return mpz<T>& A reference to the reduced mpz object
     */
    mpz<T>& mod_2exp(size_t bits);

    /**
     * @brief Reduction using the configured reduction method
     * @param cfg A mod_config object describing the modulus
     * @return mpz<T>& A reference to the reduced mpz object
     */
    mpz<T>& reduce(const mod_config<T>& cfg);

    /**
     * @brief Montgomery reduction of an mpz integer
     * @param cfg A mod_config object describing the modulus
     * @return mpz<T>& A reference to the reduced mpz object
     */
    mpz<T>& reduce_mont(const mod_config<T>& cfg);


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
