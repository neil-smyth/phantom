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


template<typename T>
void mpz<T>::bitwise_and(const mpz<T>& in1, const mpz<T>& in2)
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

template<typename T>
void mpz<T>::bitwise_or(const mpz<T>& in1, const mpz<T>& in2)
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

template<typename T>
void mpz<T>::bitwise_xor(const mpz<T>& in1, const mpz<T>& in2)
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

template<typename T>
void mpz<T>::lshift(const mpz<T>& in1, const int bits)
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

template<typename T>
void mpz<T>::rshift(const mpz<T>& in1, const int bits)
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

template<typename T>
size_t mpz<T>::hamming_weight() const
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

template<typename T>
miller_rabin_status_e mpz<T>::prime_miller_rabin(csprng& prng, const mpz<T>& p, size_t iterations)
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

template<typename T>
bool mpz<T>::check_prime(csprng& prng, const mpz<T>& p, size_t bits, bool trial_division)
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


// Forward declaration of common sizes
template class mpz<uint8_t>;
template class mpz<uint16_t>;
template class mpz<uint32_t>;
#if defined(IS_64BIT)
template class mpz<uint64_t>;
#endif

}  // namespace core
}  // namespace phantom
