/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "crypto/keccak.hpp"
#include <byteswap.h>
#include "./phantom_memory.hpp"


namespace phantom {
namespace crypto {

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))


alignas(DEFAULT_MEM_ALIGNMENT) const uint64_t keccak::keccakf_rndc[24] = {
    UINT64_C(0x0000000000000001),
    UINT64_C(0x0000000000008082),
    UINT64_C(0x800000000000808a),
    UINT64_C(0x8000000080008000),
    UINT64_C(0x000000000000808b),
    UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081),
    UINT64_C(0x8000000000008009),
    UINT64_C(0x000000000000008a),
    UINT64_C(0x0000000000000088),
    UINT64_C(0x0000000080008009),
    UINT64_C(0x000000008000000a),
    UINT64_C(0x000000008000808b),
    UINT64_C(0x800000000000008b),
    UINT64_C(0x8000000000008089),
    UINT64_C(0x8000000000008003),
    UINT64_C(0x8000000000008002),
    UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800a),
    UINT64_C(0x800000008000000a),
    UINT64_C(0x8000000080008081),
    UINT64_C(0x8000000000008080),
    UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008008)
};

alignas(DEFAULT_MEM_ALIGNMENT) const size_t keccak::keccakf_rotc[24] = {
    1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
    27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
};

alignas(DEFAULT_MEM_ALIGNMENT) const size_t keccak::keccakf_piln[24] = {
    10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
};

alignas(DEFAULT_MEM_ALIGNMENT) const size_t keccak::i4mod5[5] = {4, 0, 1, 2, 3};
alignas(DEFAULT_MEM_ALIGNMENT) const size_t keccak::i2mod5[5] = {2, 3, 4, 0, 1};
alignas(DEFAULT_MEM_ALIGNMENT) const size_t keccak::i1mod5[5] = {1, 2, 3, 4, 0};


// update the state with given number of rounds

void keccak::core(uint64_t* _RESTRICT_ st, size_t rounds)
{
    // variables
    size_t i, j, r;
    alignas(DEFAULT_MEM_ALIGNMENT) uint64_t bc[5];

#if PLATFORM_BYTE_ORDER == IS_BIG_ENDIAN
    // endianess conversion. this is redundant on little-endian targets
#if defined(KECCAKF_ROLLED)
    for (i = 0; i < 25; i++) {
        st[i] = ((st[i] & UINT64_C(0xFF00000000000000)) >> 56) |
                ((st[i] & UINT64_C(0x00FF000000000000)) >> 40) |
                ((st[i] & UINT64_C(0x0000FF0000000000)) >> 24) |
                ((st[i] & UINT64_C(0x000000FF00000000)) >>  8) |
                ((st[i] & UINT64_C(0x00000000FF000000)) <<  8) |
                ((st[i] & UINT64_C(0x0000000000FF0000)) << 24) |
                ((st[i] & UINT64_C(0x000000000000FF00)) << 40) |
                ((st[i] & UINT64_C(0x00000000000000FF)) << 56);
    }
#else
    st[ 0] = bswap_64(st[ 0]);
    st[ 1] = bswap_64(st[ 1]);
    st[ 2] = bswap_64(st[ 2]);
    st[ 3] = bswap_64(st[ 3]);
    st[ 4] = bswap_64(st[ 4]);
    st[ 5] = bswap_64(st[ 5]);
    st[ 6] = bswap_64(st[ 6]);
    st[ 7] = bswap_64(st[ 7]);
    st[ 8] = bswap_64(st[ 8]);
    st[ 9] = bswap_64(st[ 9]);
    st[10] = bswap_64(st[10]);
    st[11] = bswap_64(st[11]);
    st[12] = bswap_64(st[12]);
    st[13] = bswap_64(st[13]);
    st[14] = bswap_64(st[14]);
    st[15] = bswap_64(st[15]);
    st[16] = bswap_64(st[16]);
    st[17] = bswap_64(st[17]);
    st[18] = bswap_64(st[18]);
    st[19] = bswap_64(st[19]);
    st[20] = bswap_64(st[20]);
    st[21] = bswap_64(st[21]);
    st[22] = bswap_64(st[22]);
    st[23] = bswap_64(st[23]);
    st[24] = bswap_64(st[24]);
#endif
#endif

#if defined(KECCAKF_ROLLED)
    for (r = 0; r < rounds; r++) {

        // Theta
        for (i = 0; i < 5; i++) {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }

        for (i = 0; i < 5; i++) {
            t = bc[i4mod5[i]] ^ ROTL64(bc[i1mod5[i]], 1);
            for (j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }

        // Rho Pi
        t = st[1];
        for (i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        //  Chi
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++) {
                bc[i] = st[j + i];
            }
            for (i = 0; i < 5; i++) {
                st[j + i] ^= (~bc[i1mod5[i]]) & bc[i2mod5[i]];
            }
        }

        //  Iota
        st[0] ^= keccakf_rndc[r];
    }
#else
    for (r = 0; r < rounds; r++) {

        // Theta
        const uint64_t c0 = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
        const uint64_t c1 = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
        const uint64_t c2 = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
        const uint64_t c3 = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
        const uint64_t c4 = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

        const uint64_t t0 = c4 ^ ROTL64(c1, 1);
        st[ 0] ^= t0;
        st[ 5] ^= t0;
        st[10] ^= t0;
        st[15] ^= t0;
        st[20] ^= t0;
        const uint64_t t1 = c0 ^ ROTL64(c2, 1);
        st[ 1] ^= t1;
        st[ 6] ^= t1;
        st[11] ^= t1;
        st[16] ^= t1;
        st[21] ^= t1;
        const uint64_t t2 = c1 ^ ROTL64(c3, 1);
        st[ 2] ^= t2;
        st[ 7] ^= t2;
        st[12] ^= t2;
        st[17] ^= t2;
        st[22] ^= t2;
        const uint64_t t3 = c2 ^ ROTL64(c4, 1);
        st[ 3] ^= t3;
        st[ 8] ^= t3;
        st[13] ^= t3;
        st[18] ^= t3;
        st[23] ^= t3;
        const uint64_t t4 = c3 ^ ROTL64(c0, 1);
        st[ 4] ^= t4;
        st[ 9] ^= t4;
        st[14] ^= t4;
        st[19] ^= t4;
        st[24] ^= t4;

        // Rho Pi
        bc[0] = st[10]; st[10] = ROTL64(st[1],  1);
        bc[1] = st[ 7]; st[ 7] = ROTL64(bc[0],  3);
        bc[0] = st[11]; st[11] = ROTL64(bc[1],  6);
        bc[1] = st[17]; st[17] = ROTL64(bc[0], 10);
        bc[0] = st[18]; st[18] = ROTL64(bc[1], 15);
        bc[1] = st[ 3]; st[ 3] = ROTL64(bc[0], 21);
        bc[0] = st[ 5]; st[ 5] = ROTL64(bc[1], 28);
        bc[1] = st[16]; st[16] = ROTL64(bc[0], 36);
        bc[0] = st[ 8]; st[ 8] = ROTL64(bc[1], 45);
        bc[1] = st[21]; st[21] = ROTL64(bc[0], 55);
        bc[0] = st[24]; st[24] = ROTL64(bc[1],  2);
        bc[1] = st[ 4]; st[ 4] = ROTL64(bc[0], 14);
        bc[0] = st[15]; st[15] = ROTL64(bc[1], 27);
        bc[1] = st[23]; st[23] = ROTL64(bc[0], 41);
        bc[0] = st[19]; st[19] = ROTL64(bc[1], 56);
        bc[1] = st[13]; st[13] = ROTL64(bc[0],  8);
        bc[0] = st[12]; st[12] = ROTL64(bc[1], 25);
        bc[1] = st[ 2]; st[ 2] = ROTL64(bc[0], 43);
        bc[0] = st[20]; st[20] = ROTL64(bc[1], 62);
        bc[1] = st[14]; st[14] = ROTL64(bc[0], 18);
        bc[0] = st[22]; st[22] = ROTL64(bc[1], 39);
        bc[1] = st[ 9]; st[ 9] = ROTL64(bc[0], 61);
        bc[0] = st[ 6]; st[ 6] = ROTL64(bc[1], 20);
        bc[1] = st[ 1]; st[ 1] = ROTL64(bc[0], 44);

        //  Chi
        bc[0] = st[0];
        bc[1] = st[1];
        bc[2] = st[2];
        bc[3] = st[3];
        bc[4] = st[4];
        st[0] ^= (~bc[1]) & bc[2];
        st[1] ^= (~bc[2]) & bc[3];
        st[2] ^= (~bc[3]) & bc[4];
        st[3] ^= (~bc[4]) & bc[0];
        st[4] ^= (~bc[0]) & bc[1];
        bc[0] = st[5];
        bc[1] = st[6];
        bc[2] = st[7];
        bc[3] = st[8];
        bc[4] = st[9];
        st[5] ^= (~bc[1]) & bc[2];
        st[6] ^= (~bc[2]) & bc[3];
        st[7] ^= (~bc[3]) & bc[4];
        st[8] ^= (~bc[4]) & bc[0];
        st[9] ^= (~bc[0]) & bc[1];
        bc[0] = st[10];
        bc[1] = st[11];
        bc[2] = st[12];
        bc[3] = st[13];
        bc[4] = st[14];
        st[10] ^= (~bc[1]) & bc[2];
        st[11] ^= (~bc[2]) & bc[3];
        st[12] ^= (~bc[3]) & bc[4];
        st[13] ^= (~bc[4]) & bc[0];
        st[14] ^= (~bc[0]) & bc[1];
        bc[0] = st[15];
        bc[1] = st[16];
        bc[2] = st[17];
        bc[3] = st[18];
        bc[4] = st[19];
        st[15] ^= (~bc[1]) & bc[2];
        st[16] ^= (~bc[2]) & bc[3];
        st[17] ^= (~bc[3]) & bc[4];
        st[18] ^= (~bc[4]) & bc[0];
        st[19] ^= (~bc[0]) & bc[1];
        bc[0] = st[20];
        bc[1] = st[21];
        bc[2] = st[22];
        bc[3] = st[23];
        bc[4] = st[24];
        st[20] ^= (~bc[1]) & bc[2];
        st[21] ^= (~bc[2]) & bc[3];
        st[22] ^= (~bc[3]) & bc[4];
        st[23] ^= (~bc[4]) & bc[0];
        st[24] ^= (~bc[0]) & bc[1];

        //  Iota
        st[0] ^= keccakf_rndc[r];
    }
#endif

#if PLATFORM_BYTE_ORDER == IS_BIG_ENDIAN
    // endianess conversion. this is redundant on little-endian targets
#if defined(KECCAKF_ROLLED)
    for (i = 0; i < 25; i++) {
        st[i] = ((st[i] & UINT64_C(0xFF00000000000000)) >> 56) |
                ((st[i] & UINT64_C(0x00FF000000000000)) >> 40) |
                ((st[i] & UINT64_C(0x0000FF0000000000)) >> 24) |
                ((st[i] & UINT64_C(0x000000FF00000000)) >>  8) |
                ((st[i] & UINT64_C(0x00000000FF000000)) <<  8) |
                ((st[i] & UINT64_C(0x0000000000FF0000)) << 24) |
                ((st[i] & UINT64_C(0x000000000000FF00)) << 40) |
                ((st[i] & UINT64_C(0x00000000000000FF)) << 56);
    }
#else
    st[ 0] = bswap_64(st[ 0]);
    st[ 1] = bswap_64(st[ 1]);
    st[ 2] = bswap_64(st[ 2]);
    st[ 3] = bswap_64(st[ 3]);
    st[ 4] = bswap_64(st[ 4]);
    st[ 5] = bswap_64(st[ 5]);
    st[ 6] = bswap_64(st[ 6]);
    st[ 7] = bswap_64(st[ 7]);
    st[ 8] = bswap_64(st[ 8]);
    st[ 9] = bswap_64(st[ 9]);
    st[10] = bswap_64(st[10]);
    st[11] = bswap_64(st[11]);
    st[12] = bswap_64(st[12]);
    st[13] = bswap_64(st[13]);
    st[14] = bswap_64(st[14]);
    st[15] = bswap_64(st[15]);
    st[16] = bswap_64(st[16]);
    st[17] = bswap_64(st[17]);
    st[18] = bswap_64(st[18]);
    st[19] = bswap_64(st[19]);
    st[20] = bswap_64(st[20]);
    st[21] = bswap_64(st[21]);
    st[22] = bswap_64(st[22]);
    st[23] = bswap_64(st[23]);
    st[24] = bswap_64(st[24]);
#endif
#endif
}

}  // namespace crypto
}  // namespace phantom
