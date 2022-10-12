/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "schemes/kem/kyber/kyber_ntt.hpp"

#include <stdint.h>

#include "./phantom_types.hpp"
#include "core/poly.hpp"
#include "schemes/kem/kyber/kyber_reduce.hpp"


#define KYBER_N     256

namespace phantom {


const int16_t kyber_ntt::zetas[128] = {
  -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
   -171,   622,  1577,   182,   962, -1202, -1474,  1468,
    573, -1325,   264,   383,  -829,  1458, -1602,  -130,
   -681,  1017,   732,   608, -1542,   411,  -205, -1571,
   1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
    516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
   -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
   -398,   961, -1508,  -725,   448, -1065,   677, -1275,
  -1103,   430,   555,   843, -1251,   871,  1550,   105,
    422,   587,   177,  -235,  -291,  -460,  1574,  1653,
   -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
  -1590,   644,  -872,   349,   418,   329,  -156,   -75,
    817,  1097,   603,   610,  1322, -1285, -1465,   384,
  -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
  -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
   -108,  -308,   996,   991,   958, -1460,  1522,  1628
};


void kyber_ntt::ntt(int16_t *r, uint16_t q, uint16_t mont_inv)
{
  unsigned int len, start, j, k;
  int16_t t, zeta;

  k = 1;
  for (len = KYBER_N/2; len >= 2; len >>= 1) {
    for (start = 0; start < KYBER_N; start = j + len) {
      zeta = zetas[k++];
      for (j = start; j < start + len; j++) {
        t = kyber_reduce::mont_mul(zeta, r[j + len], q, mont_inv);
        r[j + len] = r[j] - t;
        r[j] = r[j] + t;
      }
    }
  }
}

void kyber_ntt::invntt(int16_t *r, uint16_t q, uint16_t mont_inv)
{
  unsigned int start, len, j, k;
  int16_t t, zeta;
  const int16_t f = 1441;  // mont^2 / 128

  k = KYBER_N/2 - 1;
  for (len = 2; len <= KYBER_N/2; len <<= 1) {
    for (start = 0; start < KYBER_N; start = j + len) {
      zeta = zetas[k--];
      for (j = start; j < start + len; j++) {
        t = r[j];
        r[j] = kyber_reduce::barrett(t + r[j + len], q);
        r[j + len] = r[j + len] - t;
        r[j + len] = kyber_reduce::mont_mul(zeta, r[j + len], q, mont_inv);
      }
    }
  }

  for (j = 0; j < KYBER_N; j++) {
      r[j] = kyber_reduce::mont_mul(r[j], f, q, mont_inv);
  }
}

void kyber_ntt::fwd_ntt(int16_t *r, const size_t k, const size_t n, uint16_t q, uint16_t mont_inv)
{
    for (size_t i = 0; i < k; i++) {
        ntt(r + i * n, q, mont_inv);
    }
    kyber_reduce::poly_barrett(r, KYBER_N, k, q);
}

void kyber_ntt::invntt_tomont(int16_t *r, const size_t k, const size_t n, uint16_t q, uint16_t mont_inv)
{
    for (size_t i = 0; i < k; i++) {
        invntt(r + i * n, q, mont_inv);
    }
}

void kyber_ntt::tomont(int16_t *r, const size_t k, const size_t n, uint16_t q, uint16_t mont_inv)
{
    const int16_t f = (1ULL << 32) % q;

    for (size_t i = 0; i < k; i++) {
        for (size_t j = 0; j < n; j++) {
            r[j + i*n] = kyber_reduce::montgomery((int32_t)r[j + i*n]*f, q, mont_inv);
        }
    }
}

void kyber_ntt::basemul(int16_t r[2], const int16_t a[2], const int16_t b[2],
  int16_t zeta, uint16_t q, uint16_t mont_inv)
{
    r[0]  = kyber_reduce::mont_mul(a[1], b[1], q, mont_inv);
    r[0]  = kyber_reduce::mont_mul(r[0], zeta, q, mont_inv);
    r[0] += kyber_reduce::mont_mul(a[0], b[0], q, mont_inv);
    r[1]  = kyber_reduce::mont_mul(a[0], b[1], q, mont_inv);
    r[1] += kyber_reduce::mont_mul(a[1], b[0], q, mont_inv);
}

void kyber_ntt::mul_montgomery(int16_t *r, const int16_t *a, const int16_t *b, uint16_t q, uint16_t mont_inv)
{
    for (size_t i = 0; i < KYBER_N/4; i++) {
        basemul(r + 4*i, a + 4*i, b + 4*i, zetas[64+i], q, mont_inv);
        basemul(r + 4*i+2, a + 4*i+2, b + 4*i+2, -zetas[64+i], q, mont_inv);
    }
}

void kyber_ntt::mul_acc_mont(int16_t *r, size_t k, size_t k2, const int16_t *a, const int16_t *b, const size_t n,
    uint16_t q, uint16_t mont_inv)
{
    phantom_vector<int16_t> temp(n);

    for (size_t i = 0; i < k2; i++) {
        mul_montgomery(r + n*i, a + n*k*i, b, q, mont_inv);
        for (size_t j = 1; j < k; j++) {
            mul_montgomery(temp.data(), a + n*k*i + n*j, b + n*j, q, mont_inv);
            core::poly<int16_t>::add(r + n*i, n, r + n*i, temp.data());
        }
    }
}


}  // namespace phantom
