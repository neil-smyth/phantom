/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <algorithm>
#include <cmath>
#include <memory>
#include "./phantom.hpp"
#include "crypto/aes.hpp"
#include "core/mpz.hpp"
#include "./phantom_memory.hpp"


namespace phantom {
namespace crypto {

/**
 * @ingroup symmetric
 * @brief A struct to store the FPE FF3 context
 */
struct fpe_ff3_ctx : public fpe_ctx
{
    phantom_vector<uint8_t>      tweak;
    std::unique_ptr<aes_encrypt> aes_enc;
};

/**
 * @ingroup symmetric
 * @brief AES FF3-1 Format Preserving Encryption template class
 * 
 * @tparam T Underlying data type
 */
template<typename T>
class aes_fpe_ff3_1
{
public:
    static std::unique_ptr<fpe_ctx> create_ctx(const phantom_vector<uint8_t>& user_key,
                                               aes_keylen_e keylen,
                                               const phantom_vector<uint8_t>& tweak)
    {
        if (tweak.size() != 7) {
            return nullptr;
        }

        switch (keylen)
        {
        case AES_128: if (16 != user_key.size()) {
                          return nullptr;
                      } break;
        case AES_192: if (24 != user_key.size()) {
                          return nullptr;
                      } break;
        case AES_256: if (32 != user_key.size()) {
                          return nullptr;
                      } break;
        default:      return nullptr;
        }

        auto ctx     = std::unique_ptr<fpe_ctx>(new fpe_ff3_ctx());
        fpe_ff3_ctx* myctx = reinterpret_cast<fpe_ff3_ctx*>(ctx.get());

        myctx->tweak   = phantom_vector<uint8_t>(8);
        myctx->tweak[0] = tweak[0];
        myctx->tweak[1] = tweak[1];
        myctx->tweak[2] = tweak[2];
        myctx->tweak[3] = tweak[3] & 0xffff0000;
        myctx->tweak[4] = tweak[4];
        myctx->tweak[5] = tweak[5];
        myctx->tweak[6] = tweak[6];
        myctx->tweak[7] = tweak[3] << 4;
        myctx->aes_enc = std::unique_ptr<aes_encrypt>(aes_encrypt::make(keylen));
        myctx->aes_enc->set_key(user_key.data(), keylen);
        return ctx;
    }

    static void encrypt(const std::unique_ptr<fpe_ctx>& ctx,
                        const T radix,
                        const phantom_vector<T>& in,
                        phantom_vector<T>& out)
    {
        fpe_ctx* myfpectx = ctx.get();
        if (nullptr == myfpectx) {
            throw std::runtime_error("fpe_ctx is NULL");
        }
        fpe_ff3_ctx& myctx = reinterpret_cast<fpe_ff3_ctx&>(*myfpectx);

        core::mpz<T> bnum, y, anum;
        T inlen = in.size();
        if (0 == inlen) {
            out = phantom_vector<T>();
            return;
        }

        T u = inlen >> 1;
        T v = inlen - u;
        phantom_vector<T> outA(in.begin(), in.begin() + u);
        phantom_vector<T> outB(in.begin() + u, in.end());
        T *B = outB.data();

        int ceil_vlog2, b, tweaklen;
        setup(myctx, v, &ceil_vlog2, &b, &tweaklen, radix);

        phantom_vector<uint8_t> S(16);
        phantom_vector<uint8_t> P(16);
        phantom_vector<uint8_t> vecBytes;

        for (size_t i = 0; i < ff3_rounds; i++) {

            // i If odd m = v and W = Tr, if even m = u and W = Tl
            size_t m = (i & 1)? v: u;

            // ii Calculate P
            int offset = (i & 1)? 4 : 0;
            P[0] = myctx.tweak[offset    ];
            P[1] = myctx.tweak[offset + 1];
            P[2] = myctx.tweak[offset + 2];
            P[3] = myctx.tweak[offset + 3] ^ i;
            bnum.from_radix_array(outB, radix, false);
            bnum.get_bytes(vecBytes, false);
            int ptmp = 12 - vecBytes.size();
            memset(P.data() + 4, 0x00, ptmp);
            std::copy(vecBytes.begin(), vecBytes.end(), P.begin() + 4 + ptmp);

            // iii Compute S as P encrypted with byte reversal
            myctx.aes_enc->encrypt(S.data(), P.data());

            // iv y = NUM(S)
            y.set_bytes(S, true);

            // vi c = (NUM_radix (REV(A)) + y) mod radix ^ m
            anum.from_radix_array(outA, radix, false);

            // Swap A and B
            outA.swap(outB);
            B = outB.data();

            // anum = (anum + y) mod qpow_uv
            core::mpz<T> q, r, n;
            n = anum + y;
            for (size_t k=m; k-->0; ) {
                B[k] = core::mpz<T>::fdiv_qr_ui(q, r, n, radix);
                n.swap(q);
            }
        }

        out = phantom_vector<T>(outA.begin(), outA.end());
        out.insert(out.end(), outB.begin(), outB.end());
    }

    static void decrypt(const std::unique_ptr<fpe_ctx>& ctx,
                        const T radix,
                        const phantom_vector<T>& in,
                        phantom_vector<T>& out)
    {
        fpe_ctx* myfpectx = ctx.get();
        if (nullptr == myfpectx) {
            throw std::runtime_error("fpe_ctx is NULL");
        }
        fpe_ff3_ctx& myctx = reinterpret_cast<fpe_ff3_ctx&>(*myfpectx);

        core::mpz<T> bnum, y, c, anum;
        T inlen = in.size();

        if (0 == inlen) {
            out = phantom_vector<T>();
            return;
        }

        T u = inlen >> 1;
        T v = inlen - u;
        phantom_vector<T> outA(in.begin(), in.begin() + u);
        phantom_vector<T> outB(in.begin() + u, in.end());
        T *A = outA.data();

        int ceil_vlog2, b, tweaklen;
        setup(myctx, v, &ceil_vlog2, &b, &tweaklen, radix);

        phantom_vector<uint8_t> S(16);
        phantom_vector<uint8_t> P(16);
        phantom_vector<uint8_t> vecBytes;

        for (int i = ff3_rounds - 1; i >= 0; i--) {

            // i If odd m = v and W = Tr, if even m = u and W = Tl
            int m = (i & 1)? v: u;

            // ii Calculate P
            int offset = (i & 1)? 4 : 0;
            P[0] = myctx.tweak[offset    ];
            P[1] = myctx.tweak[offset + 1];
            P[2] = myctx.tweak[offset + 2];
            P[3] = myctx.tweak[offset + 3] ^ i;
            anum.from_radix_array(outA, radix, false);
            anum.get_bytes(vecBytes, false);
            int ptmp = 12 - vecBytes.size();
            memset(P.data() + 4, 0x00, ptmp);
            std::copy(vecBytes.begin(), vecBytes.end(), P.begin() + 4 + ptmp);

            // iii Compute S as P encrypted with byte reversal
            myctx.aes_enc->encrypt(S.data(), P.data());

            // iv y = NUM(S)
            y.set_bytes(S, true);

            // vi c = (NUM_radix (REV(B)) + y) mod radix ^ m
            bnum.from_radix_array(outB, radix, false);

            // Swap A and B
            outA.swap(outB);
            A = outA.data();

            // anum = (anum + y) mod qpow_uv
            core::mpz<T> q, r, n;
            n = bnum - y;
            for (size_t k=m; k-->0; ) {
                A[k] = core::mpz<T>::fdiv_qr_ui(q, r, n, radix);
                n.swap(q);
            }
        }

        out = phantom_vector<T>(outA.begin(), outA.end());
        out.insert(out.end(), outB.begin(), outB.end());
    }

private:
    inline static int ceil2(int x, int bit)
    {
        return (x >> bit) + ((x & ((1 << bit) - 1)) > 0);
    }

    inline static void setup(const fpe_ff3_ctx& ctx,
                             const int v,
                             int* ceil_vlog2,
                             int* b,
                             int* tweaklen,
        const T radix)
    {
        *ceil_vlog2 = v * core::bit_manipulation::log2_ceil(radix);
        *b          = ceil2(*ceil_vlog2, 3);

        *tweaklen   = ctx.tweak.size();
    }

    static const size_t ff3_rounds = 8;
};

}  // namespace crypto
}  // namespace phantom
