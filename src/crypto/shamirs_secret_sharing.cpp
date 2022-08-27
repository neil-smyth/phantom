/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "crypto/shamirs_secret_sharing.hpp"
#include <assert.h>
#include <fstream>
#include <string>
#include "core/gf256.hpp"

namespace phantom {


shamirs_secret_sharing::shamirs_secret_sharing(const std::shared_ptr<csprng>& prng)
{
    if (nullptr == prng.get()) {
        throw std::runtime_error("std::shared_ptr object contains a null pointer");
    }
    m_prng = prng;
}

shamirs_secret_sharing::~shamirs_secret_sharing()
{
}

// Create key shares of the given key for a quorum of n users and k key shares
// required to reconstruct the key
int32_t shamirs_secret_sharing::create(phantom_vector<phantom_vector<uint8_t>>& shares,
    const uint8_t* key, size_t n, size_t k)
{
    assert(n != 0);
    assert(k != 0);
    assert(k <= n);

    if (shares.size() != n) {
        return EXIT_FAILURE;
    }
    if (nullptr == key) {
        return EXIT_FAILURE;
    }

    // Allocate memory for k word-sized polynomials and 4 word-sized variables
    phantom_vector<uint32_t> vec((k + 4) * 8);
    uint32_t* poly = vec.data();
    uint32_t* x    = poly + k * 8;
    uint32_t* y    = x + 8;
    uint32_t* xpow = y + 8;
    uint32_t* tmp  = xpow + 8;

    // Initialize the polynomial with the key
    bitslice(poly, key);

    // Fill the rest of the polynomial with random data
    m_prng->get_mem(reinterpret_cast<uint8_t*>(poly + 8), (k-1)*8);

    // Create a share for each user
    for (size_t i=0; i < n; i++) {
        shares[i] = phantom_vector<uint8_t>(shard_length);

        // Zeroth byte is the user index, value is contained in 1...n
        uint8_t unbitsliced_x = i + 1;
        shares[i][0] = unbitsliced_x;
        bitslice_single(x, unbitsliced_x);

        // Calculate y and copy to the output share as words
        memset(y, 0, sizeof(uint32_t[key_words]));
        memset(xpow, 0, sizeof(uint32_t[key_words]));
        xpow[0] = ~0;
        core::gf256<uint32_t>::add(y, poly);
        for (size_t j=1; j < k; j++) {
            core::gf256<uint32_t>::mul(xpow, xpow, x);
            core::gf256<uint32_t>::mul(tmp, xpow, poly + 8*j);
            core::gf256<uint32_t>::add(y, tmp);
        }
        unbitslice(&shares[i][1], y);
    }

    return EXIT_SUCCESS;
}

// Restore the k key shares and write the result to key.
int32_t shamirs_secret_sharing::combine(uint8_t key[key_bytes],
    const phantom_vector<phantom_vector<uint8_t>> &shares, size_t k)
{
    if (0 == k) {
        return EXIT_FAILURE;
    }

    phantom_vector<phantom_vector<uint32_t>> xs(k, phantom_vector<uint32_t>(key_words));
    phantom_vector<phantom_vector<uint32_t>> ys(k, phantom_vector<uint32_t>(key_words));

    phantom_vector<uint32_t> scratch(4 * key_words);
    uint32_t *num = scratch.data();
    uint32_t *denom = num + key_words;
    uint32_t *tmp = denom + key_words;
    uint32_t *secret = tmp + key_words;  // Will be initialized to zero

    // Collect the x and y values
    for (size_t i=0; i < k; i++) {
        bitslice_single(xs[i].data(), shares[i][0]);
        bitslice(ys[i].data(), &shares[i][1]);
    }

    // Use Lagrange basis polynomials to calculate the secret coefficient
    for (size_t i=0; i < k; i++) {
        memset(num, 0, sizeof(uint32_t) * key_words);
        memset(denom, 0, sizeof(uint32_t) * key_words);
        num[0] = ~0;
        denom[0] = ~0;
        for (size_t j=0; j < k; j++) {
            if (i == j) continue;
            core::gf256<uint32_t>::mul(num, num, xs[j].data());
            for (size_t t=0; t < key_words; t++) {
                tmp[t] = xs[i][t];
            }
            core::gf256<uint32_t>::add(tmp, xs[j].data());
            core::gf256<uint32_t>::mul(denom, denom, tmp);
        }
        core::gf256<uint32_t>::inv(tmp, denom);       // inverted denominator
        core::gf256<uint32_t>::mul(num, num, tmp);    // basis polynomial
        core::gf256<uint32_t>::mul(num, num, ys[i].data());  // scaled coefficient
        core::gf256<uint32_t>::add(secret, num);
    }
    unbitslice(key, secret);

    return EXIT_SUCCESS;
}

// Bitslice an array of bytes to an array of words
void shamirs_secret_sharing::bitslice(uint32_t r[key_words],
                                      const uint8_t x[key_bytes])
{
    memset(r, 0, key_bytes);
    for (size_t i=0; i < key_bytes; i++) {
        uint32_t cur = static_cast<uint32_t>(x[i]);
        for (size_t j=0; j < key_words; j++) {
            r[j] |= ((cur >> j) & 1) << i;
        }
    }
}

// Unbitslice an array of words to an array of bytes
void shamirs_secret_sharing::unbitslice(uint8_t r[key_bytes],
                                        const uint32_t x[key_words])
{
    memset(r, 0, key_bytes);
    for (size_t i=0; i < key_words; i++) {
        uint32_t cur = static_cast<uint32_t>(x[i]);
        for (size_t j=0; j < key_bytes; j++) {
            r[j] |= ((cur >> j) & 1) << i;
        }
    }
}

// Copy an input byte to an output bitsliced word (all zeros or all ones)
void shamirs_secret_sharing::bitslice_single(uint32_t r[8], const uint8_t x)
{
    r[0] = (static_cast<int32_t>((x &   1) << 31)) >> 31;
    r[1] = (static_cast<int32_t>((x &   2) << 30)) >> 31;
    r[2] = (static_cast<int32_t>((x &   4) << 29)) >> 31;
    r[3] = (static_cast<int32_t>((x &   8) << 28)) >> 31;
    r[4] = (static_cast<int32_t>((x &  16) << 27)) >> 31;
    r[5] = (static_cast<int32_t>((x &  32) << 26)) >> 31;
    r[6] = (static_cast<int32_t>((x &  64) << 25)) >> 31;
    r[7] = (static_cast<int32_t>((x & 128) << 24)) >> 31;
}

}  // namespace phantom
