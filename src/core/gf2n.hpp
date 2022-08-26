/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
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
#include <vector>

#include "core/mpbase.hpp"
#include "core/mp.hpp"
#include "core/mpz.hpp"
#include "core/template_helpers.hpp"


namespace phantom {
namespace core {

/** 
 * @brief Template class for Galois Field arithmetic
 * 
 * GF(2^n) finite field arithmetic methods with various types
 */
template<typename T>
class gf2n
{
    static_assert(std::is_same<T, uint8_t>::value  ||
                  std::is_same<T, uint16_t>::value ||
                  std::is_same<T, uint32_t>::value ||
                  std::is_same<T, uint64_t>::value,
                  "number instantiated with unsupported type");

    using S = signed_type_t<T>;

public:
    static bool mod_arr(phantom_vector<T>& r, const phantom_vector<T>& a, const std::vector<int>& p)
    {
        int j = 0;
        int n, dN, d0, d1;
        T zz, *z;

        if (p[0] == 0) {
            // reduction mod 1 => return 0
            r.resize(0);
            return true;
        }

        // Reduction occurs in-place in r, so copy the contents of a into r if required
        if (a != r) {
            size_t used = mpbase<T>::normalized_size(a.data(), a.size());
            r.resize(used);

            for (size_t j = 0; j < used; j++) {
                r[j] = a[j];
            }
        }
        z = r.data();

        // start reduction
        dN = p[0] >> bits_log2<T>::value();
        for (j = r.size() - 1; j > dN;) {
            zz = z[j];
            if (0 == z[j]) {
                j--;
                continue;
            }
            z[j] = 0;

            for (int k = 1; p[k] != 0; k++) {
                // reducing component t^p[k]
                n = p[0] - p[k];
                d0 = n & (std::numeric_limits<T>::digits - 1);
                d1 = (std::numeric_limits<T>::digits) - d0;
                n >>= bits_log2<T>::value();
                z[j - n] ^= (zz >> d0);
                if (d0) {
                    z[j - n - 1] ^= (zz << d1);
                }
            }

            // reducing component t^0
            n = dN;
            d0 = p[0] & (std::numeric_limits<T>::digits - 1);
            d1 = (std::numeric_limits<T>::digits) - d0;
            z[j - n] ^= (zz >> d0);
            if (d0) {
                z[j - n - 1] ^= (zz << d1);
            }
        }

        // final round of reduction
        while (j == dN) {

            d0 = p[0] & (std::numeric_limits<T>::digits - 1);
            zz = z[dN] >> d0;
            if (0 == zz) {
                break;
            }
            d1 = (std::numeric_limits<T>::digits) - d0;

            // clear up the top d1 bits
            if (d0) {
                z[dN] = T(z[dN] << d1) >> d1;
            }
            else {
                z[dN] = 0;
            }
            z[0] ^= zz;             // reduction t^0 component

            for (int k = 1; p[k] != 0; k++) {
                T tmp_ulong;

                // reducing component t^p[k]
                n = p[k] >> bits_log2<T>::value();
                d0 = p[k] & (std::numeric_limits<T>::digits - 1);
                d1 = (std::numeric_limits<T>::digits) - d0;
                z[n] ^= (zz << d0);
                if (d0 && (tmp_ulong = zz >> d1))
                    z[n + 1] ^= tmp_ulong;
            }

        }

        size_t used = mpbase<T>::normalized_size(r.data(), r.size());
        r.resize(used);
        return true;
    }

    static bool mod_mul_arr(phantom_vector<T>& r, const phantom_vector<T>& a,
        const phantom_vector<T>& b, const std::vector<int>& p)
    {
        size_t zlen;
        phantom_vector<T> s;
        T x1, x0, y1, y0, zz[4];

        if (a == b) {
            return mod_sqr_arr(r, a, p);
        }

        zlen = a.size() + b.size() + 4;
        s.resize(zlen);

        for (size_t i=0; i < zlen; i++) {
            s[i] = 0;
        }

        for (size_t j=0; j < b.size(); j+=2) {
            y0 = b[j];
            y1 = ((j + 1) == b.size()) ? 0 : b[j + 1];
            for (size_t i=0; i < a.size(); i+=2) {
                x0 = a[i];
                x1 = ((i + 1) == a.size()) ? 0 : a[i + 1];
                mul_2x2(zz, x1, x0, y1, y0);
                for (size_t k=0; k < 4; k++)
                    s[i + j + k] ^= zz[k];
            }
        }

        size_t used = mpbase<T>::normalized_size(s.data(), s.size());
        s.resize(used);

        return mod_arr(r, s, p);
    }

    static bool mod_sqr_arr(phantom_vector<T>& r, const phantom_vector<T>& a, const std::vector<int>& p)
    {
        phantom_vector<T> s;

        size_t zlen = a.size() * 2;
        s.resize(zlen);

        for (size_t i=0; i < a.size(); i++) {
            s[2*i + 1] = square_1(a[i]);
            s[2*i    ] = square_0(a[i]);
        }

        return mod_arr(r, s, p);
    }

private:
    static void mul_2x2(T *r, const T a1, const T a0, const T b1, const T b0)
    {
        T m1, m0;

        // r[3] = h1, r[2] = h0; r[1] = l1; r[0] = l0
        mul_1x1(r + 3, r + 2, a1, b1);
        mul_1x1(r + 1, r, a0, b0);
        mul_1x1(&m1, &m0, a0 ^ a1, b0 ^ b1);

        // Correction on m1 ^= l1 ^ h1; m0 ^= l0 ^ h0
        r[2] ^= m1 ^ r[1] ^ r[3];             // h0 ^= m1 ^ l1 ^ h1
        r[1] = r[3] ^ r[2] ^ r[0] ^ m1 ^ m0;  // l1 ^= l0 ^ h0 ^ m0
    }

    static void mul_1x1(uint8_t* r1, uint8_t* r0, const uint8_t a, const uint8_t b);
    static void mul_1x1(uint16_t* r1, uint16_t* r0, const uint16_t a, const uint16_t b);
    static void mul_1x1(uint32_t* r1, uint32_t* r0, const uint32_t a, const uint32_t b);
    static void mul_1x1(uint64_t* r1, uint64_t* r0, const uint64_t a, const uint64_t b);

    static T square_1(T w);
    static T square_0(T w);
};

}  // namespace core
}  // namespace phantom
