/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include "crypto/sha2.hpp"
#include "crypto/hash.hpp"


#if defined(__x86_64__)

#if __has_include("cpuid.h")
#include <cpuid.h>
#endif

#include <stdint.h>
#include <x86intrin.h>

#endif

#if defined(__clang__)
// Ensure that we enable support for SHA-NI
#pragma clang attribute push(__attribute__((target("sse4.1,sha"))), apply_to = function)
#elif defined(__GNUG__)
// Ensure that we enable support for SHA-NI
#pragma GCC target("sse4.1")
#pragma GCC target("sha")
#endif


namespace phantom {
namespace crypto {


class sha2_core_ni
{
private:
#if defined(__x86_64__)
    /**
     * @brief Updates the state variables A, B, C, ..., H for 4 rounds
     */
    static void update_state(int round, __m128i &msg, __m128i &ABEF, __m128i &CDGH)
    {
        const __m128i *k_round_vec = reinterpret_cast<const __m128i*>(&k256[round]);
        msg  = _mm_add_epi32(msg, *k_round_vec);        // Add the K constants to the working buffer
        CDGH = _mm_sha256rnds2_epu32(CDGH, ABEF, msg);  // 2 rounds using SHA-NI
        msg  = _mm_shuffle_epi32(msg, 0x0E);            // Move words 2, 3 to positions 0, 1
        ABEF = _mm_sha256rnds2_epu32(ABEF, CDGH, msg);  // 2 rounds using SHA-NI
    }

    /**
     * @brief Helper method for rounds 16 - 51 to update the message schedule
     */
    static void update_message(__m128i msg_0, __m128i &msg_1, __m128i &msg_3, __m128i &temp)
    {
        temp  = _mm_alignr_epi8(msg_0, msg_3, 4);
        msg_1 = _mm_add_epi32(msg_1, temp);
        msg_1 = _mm_sha256msg2_epu32(msg_1, msg_0);
        msg_3 = _mm_sha256msg1_epu32(msg_3, msg_0);
    }
#endif

public:
    /**
     * @brief  Method indicates if SHA-NI is available
     */
    static bool has_sha_ni()
    {
#if defined(__x86_64__) && __has_include("cpuid.h")
        // Only 64-bit Intel and AMD CPU's support SHA-NI
        static int32_t test = -1;
        if (test < 0) {
            uint32_t a, b, c, d;
            if (!__get_cpuid(1, &a, &b, &c, &d)) {
                test = 0;
            }
            else {
                if (a < 7) {
                    test = 0;
                }
                else {
                    __get_cpuid_count(7, 0, &a, &b, &c, &d);
                    test = b & (1 << 29);
                }
            }
        }
        return test != 0;
#else
        return false;
#endif
    }

    /**
     * @brief SHA2 coreimplementationusing SHA NI intrinsics
     */
    static void core(sha2_ctx<uint32_t>* ctx)
    {
#if defined(__x86_64__)
        // Load the state and reorder
        __m128i DCBA = _mm_loadu_si128(reinterpret_cast<__m128i*>(&ctx->hash[0]));  // (D, C, B, A)
        __m128i HGFE = _mm_loadu_si128(reinterpret_cast<__m128i*>(&ctx->hash[4]));  // (H, G, F, E)
        __m128i FEBA = _mm_unpacklo_epi64(DCBA, HGFE);                              // (F, E, B, A)
        __m128i HGDC = _mm_unpackhi_epi64(DCBA, HGFE);                              // (H, G, D, C)
        __m128i ABEF = _mm_shuffle_epi32(FEBA, 0x1B);                               // (A, B, E, F)
        __m128i CDGH = _mm_shuffle_epi32(HGDC, 0x1B);                               // (C, D, G, H)

        // Create a pointer to the working buffer
        __m128i *data = reinterpret_cast<__m128i*>(ctx->wbuf);

        // Save the current state for update later
        __m128i ABEF_start = ABEF;
        __m128i CDGH_start = CDGH;

        // Temporary state
        __m128i tmp;

        // Accumulators for each round
        __m128i msg_0, msg_1, msg_2, msg_3;

        // Rounds 0 - 3
        tmp   = _mm_loadu_si128(data);                  // Load 4 32-bit words
        msg_0 = tmp;                                    // msg_0 = ( W_3 = M3, W_2 = M_2, W_1 = M_1, W_0 = M_0 )
        update_state(0, tmp, ABEF, CDGH);

        // Rounds 4 - 7
        tmp   = _mm_loadu_si128(data + 1);              // Load next 4 32-bit words
        msg_1 = tmp;                                    // msg_1 = ( W_7 = M_7, W_6 = M_6, W_5 = M_5, W_4 = M_4 )
        update_state(4, tmp, ABEF, CDGH);
        msg_0 = _mm_sha256msg1_epu32(msg_0, msg_1);     // msg_0 = ( X_19, X_18, X_17, X_16 ) =
                                                        // ( W_3 + \sigma_0(W_4), ..., W_0 + \sigma_0(W_1) )

        // Rounds 8 - 11
        tmp   = _mm_loadu_si128(data + 2);              // Load next 4 32-bit words
        msg_2 = tmp;                                    // msg_2 = ( W_11 = M_11, W_10 = M_10, W_9 = M_9, W_8 = M_8 )
        update_state(8, tmp, ABEF, CDGH);
        msg_1 = _mm_sha256msg1_epu32(msg_1, msg_2);     // msg_1 = ( X_23, X_22, X_21, X_20 )

        // Rounds 12 - 15
        tmp   = _mm_loadu_si128(data + 3);              // Load next 4 32-bit words
        msg_3 = tmp;                                    // msg_3 = ( W_15 = M_15, W_14 = M_14, W_13 = M_13, W_12 = M_12 )
        update_state(12, tmp, ABEF, CDGH);

        // Update msg_0 using msg_2 before it's modified
        tmp   = _mm_alignr_epi8(msg_3, msg_2, 4);       // tmp   = ( W_12, W_11, W_10, W_9 )
        msg_0 = _mm_add_epi32(msg_0, tmp);              // msg_0 = msg_0 + ( W_12, W_11, W_10, W_9 )
        msg_0 = _mm_sha256msg2_epu32(msg_0, msg_3);     // msg_0 = ( X_19 + W_12 + \sigma_1(W_17)], ..., X_16 + W_9 + \sigma_1(W_14)] )
        msg_2 = _mm_sha256msg1_epu32(msg_2, msg_3);     // msg_2 = ( X_27, X_26, X_25, X_24 )

        // Rounds 16 - 19
        tmp   = msg_0;
        update_state(16, tmp, ABEF, CDGH);
        update_message(msg_0, msg_1, msg_3, tmp);

        // Rounds 20 - 23
        tmp   = msg_1;
        update_state(20, tmp, ABEF, CDGH);
        update_message(msg_1, msg_2, msg_0, tmp);

        // Rounds 24 - 27
        tmp   = msg_2;
        update_state(24, tmp, ABEF, CDGH);
        update_message(msg_2, msg_3, msg_1, tmp);

        // Rounds 28 - 31
        tmp   = msg_3;
        update_state(28, tmp, ABEF, CDGH);
        update_message(msg_3, msg_0, msg_2, tmp);

        // Rounds 32 - 35
        tmp   = msg_0;
        update_state(32, tmp, ABEF, CDGH);
        update_message(msg_0, msg_1, msg_3, tmp);

        // Rounds 36 - 39
        tmp   = msg_1;
        update_state(36, tmp, ABEF, CDGH);
        update_message(msg_1, msg_2, msg_0, tmp);

        // Rounds 40 - 43
        tmp   = msg_2;
        update_state(40, tmp, ABEF, CDGH);
        update_message(msg_2, msg_3, msg_1, tmp);

        // Rounds 44 - 47
        tmp   = msg_3;
        update_state(44, tmp, ABEF, CDGH);
        update_message(msg_3, msg_0, msg_2, tmp);

        // Rounds 48 - 51
        tmp   = msg_0;
        update_state(48, tmp, ABEF, CDGH);
        update_message(msg_0, msg_1, msg_3, tmp);

        // Rounds 52 - 55
        tmp   = msg_1;                                  // ( W_55, W_54, W_53, W_52 )
        update_state(52, tmp, ABEF, CDGH);
        tmp   = _mm_alignr_epi8(msg_1, msg_0, 4);       // tmp = ( W_52, W_51, W_50, W_49 )
        msg_2 = _mm_add_epi32(msg_2, tmp);              // msg_2 = msg_2 + ( W_52, W_51, W_50, W_49 )
        msg_2 = _mm_sha256msg2_epu32( msg_2, msg_1);    // Calculate ( W_59, W_58, W_57, W_56 )

        // Rounds 56 - 59
        tmp   = msg_2;                                  // ( W_59, W_58, W_57, W_56 )
        update_state(56, tmp, ABEF, CDGH);
        tmp   = _mm_alignr_epi8(msg_2, msg_1, 4);       // tmp = ( W_56, W_55, W_54, W_53 )
        msg_3 = _mm_add_epi32(msg_3, tmp);              // msg_3 = msg_3 + ( W_56, W_55, W_54, W_53 )
        msg_3 = _mm_sha256msg2_epu32(msg_3, msg_2);     // Calculate ( W_63, W_62, W_61, W_60 )

        // Rounds 60 - 63
        update_state(60, msg_3, ABEF, CDGH);

        // Update the existing state by addition
        ABEF = _mm_add_epi32(ABEF, ABEF_start);
        CDGH = _mm_add_epi32(CDGH, CDGH_start);

        // Unpack the state registers and store them
        FEBA = _mm_shuffle_epi32(ABEF, 0x1B);
        HGDC = _mm_shuffle_epi32(CDGH, 0x1B);
        DCBA = _mm_unpacklo_epi64(FEBA, HGDC);                              // (D, C, B, A)
        HGFE = _mm_unpackhi_epi64(FEBA, HGDC);                              // (H, G, F, E)
        _mm_storeu_si128(reinterpret_cast<__m128i*>(&ctx->hash[0]), DCBA);  // (D, C, B, A)
        _mm_storeu_si128(reinterpret_cast<__m128i*>(&ctx->hash[4]), HGFE);  // (H, G, F, E)
#endif
    }
};


}  // namespace crypto
}  // namespace phantom
