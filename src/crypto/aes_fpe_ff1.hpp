/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
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
 * @brief A struct to store the FPE FF1 context
 */
struct fpe_ff1_ctx : public fpe_ctx
{
    phantom_vector<uint8_t>      tweak;
    std::unique_ptr<aes_encrypt> aes_enc;
};

/**
 * @ingroup symmetric
 * @brief AES FF1 Format Preserving Encryption template class
 * 
 * @tparam T Underlying data type
 */
template<typename T>
class aes_fpe_ff1
{
public:
    static std::unique_ptr<fpe_ctx> create_ctx(const phantom_vector<uint8_t>& user_key,
                                               aes_keylen_e keylen,
                                               const phantom_vector<uint8_t>& tweak)
    {
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

        auto ctx     = std::unique_ptr<fpe_ctx>(new fpe_ff1_ctx());
        fpe_ff1_ctx* myctx = reinterpret_cast<fpe_ff1_ctx*>(ctx.get());

        myctx->tweak   = phantom_vector<uint8_t>(tweak.begin(), tweak.end());
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
        fpe_ff1_ctx& myctx = reinterpret_cast<fpe_ff1_ctx&>(*myfpectx);

        core::mpz<T> bnum, y, c, anum, qpow_u, qpow_v;
        T inlen = in.size();

        T u = inlen >> 1;
        T v = inlen - u;
        phantom_vector<T> outA(in.begin(), in.begin() + u);
        phantom_vector<T> outB(in.begin() + u, in.end());
        T *B = outB.data();
        pow_uv(qpow_u, qpow_v, radix, u, v);

        int ceil_vlog2, b, d, tweaklen, pad, Qlen;
        setup(myctx, v, &ceil_vlog2, &b, &d, &tweaklen, radix, &pad, &Qlen);

        phantom_vector<uint8_t> Q(Qlen);
        phantom_vector<uint8_t> P(16);
        computeP(P, radix, tweaklen, inlen, ceil_vlog2, u);

        std::copy(myctx.tweak.begin(), myctx.tweak.end(), Q.begin());
        memset(Q.data() + tweaklen, 0x00, pad);
        assert(tweaklen + pad - 1 <= Qlen);

        phantom_vector<uint8_t> R(16);
        int cnt = ceil2(d, 4) - 1;
        int Slen = 16 + cnt * 16;
        phantom_vector<uint8_t> S(Slen);
        phantom_vector<uint8_t> vecBytes;
        for (size_t i = 0; i < ff1_rounds; i++) {

            // v
            size_t m = (i & 1) ? v : u;

            // i
            Q[tweaklen + pad] = i & 0xff;
            bnum.from_radix_array(outB, radix, false);
            bnum.get_bytes(vecBytes, true);
            memset(Q.data() + Qlen - b, 0x00, b);
            int qtmp = Qlen - vecBytes.size();
            std::copy(vecBytes.begin(), vecBytes.end(), Q.begin() + qtmp);

            // ii PRF(P || Q), P is always 16 bytes long
            PRF(myctx, R, P, Q);

            // iii
            computeS(myctx, S, cnt, Slen, R);

            // iv
            S.resize(d);
            y.set_bytes(S, true);
            S.resize(Slen);

            // vi
            // (num(A, radix, m) + y) % qpow(radix, m);
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
        fpe_ff1_ctx& myctx = reinterpret_cast<fpe_ff1_ctx&>(*myfpectx);

        core::mpz<T> bnum, y, c, anum, qpow_u, qpow_v;
        T inlen = in.size();

        T u = inlen >> 1;
        T v = inlen - u;
        phantom_vector<T> outA(in.begin(), in.begin() + u);
        phantom_vector<T> outB(in.begin() + u, in.end());
        T *A = outA.data();
        pow_uv(qpow_u, qpow_v, radix, u, v);

        int ceil_vlog2, b, d, tweaklen, pad, Qlen;
        setup(myctx, v, &ceil_vlog2, &b, &d, &tweaklen, radix, &pad, &Qlen);

        phantom_vector<uint8_t> Q(Qlen);
        phantom_vector<uint8_t> P(16);
        computeP(P, radix, tweaklen, inlen, ceil_vlog2, u);

        std::copy(myctx.tweak.begin(), myctx.tweak.end(), Q.begin());
        memset(Q.data() + tweaklen, 0x00, pad);
        assert(tweaklen + pad - 1 <= Qlen);

        phantom_vector<uint8_t> R(16);
        int cnt = ceil2(d, 4) - 1;
        int Slen = 16 + cnt * 16;
        phantom_vector<uint8_t> S(Slen);
        phantom_vector<uint8_t> vecBytes;
        for (int i = ff1_rounds - 1; i >= 0; i--) {

            // v
            int m = (i & 1)? v: u;

            // i
            Q[tweaklen + pad] = i & 0xff;
            anum.from_radix_array(outA, radix, false);
            anum.get_bytes(vecBytes, true);
            memset(Q.data() + Qlen - b, 0x00, b);
            int qtmp = Qlen - vecBytes.size();
            std::copy(vecBytes.begin(), vecBytes.end(), Q.begin() + qtmp);

            // ii PRF(P || Q), P is always 16 bytes long
            PRF(myctx, R, P, Q);

            // iii
            computeS(myctx, S, cnt, Slen, R);

            // iv
            S.resize(d);
            y.set_bytes(S, true);
            S.resize(Slen);

            bnum.from_radix_array(outB, radix, false);

            // Swap A and B
            outA.swap(outB);
            A = outA.data();

            // bnum = (bnum - y) mod qpow_uv
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

    inline static void setup(const fpe_ff1_ctx& ctx,
                             const int v,
                             int* ceil_vlog2,
                             int* b,
                             int* d,
                             int* tweaklen,
                             const T radix,
                             int* pad,
                             int* Qlen)
    {
        *ceil_vlog2 = v * core::bit_manipulation::log2_ceil(radix);
        *b          = ceil2(*ceil_vlog2, 3);
        *d          = 4 * ceil2(*b, 2) + 4;

        *tweaklen   = ctx.tweak.size();
        *pad        = (((-*tweaklen - *b - 1) & 15) + 16) & 15;
        *Qlen       = *tweaklen + *pad + 1 + *b;
    }

    inline static void computeP(phantom_vector<uint8_t>& P,
                                T radix,
                                int tweaklen,
                                int inlen,
                                int ceil_vlog2,
                                int u)
    {
        P[0]  = 0x1;
        P[1]  = 0x2;
        P[2]  = 0x1;
        P[7]  = u & 255;
#if PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN
        ceil_vlog2 = (radix << 8) | 10;
        P[3]  = (ceil_vlog2 >> 24) & 0xff;
        P[4]  = (ceil_vlog2 >> 16) & 0xff;
        P[5]  = (ceil_vlog2 >>  8) & 0xff;
        P[6]  = (ceil_vlog2 >>  0) & 0xff;
        P[8]  = (inlen >> 24) & 0xff;
        P[9]  = (inlen >> 16) & 0xff;
        P[10] = (inlen >>  8) & 0xff;
        P[11] = (inlen >>  0) & 0xff;
        P[12] = (tweaklen >> 24) & 0xff;
        P[13] = (tweaklen >> 16) & 0xff;
        P[14] = (tweaklen >>  8) & 0xff;
        P[15] = (tweaklen >>  0) & 0xff;
#else
        *(reinterpret_cast<uint32_t *>(P.data() +  3)) = (radix << 8) | 10;
        *(reinterpret_cast<uint32_t *>(P.data() +  8)) = inlen;
        *(reinterpret_cast<uint32_t *>(P.data() + 12)) = tweaklen;
#endif
    }

    inline static void computeS(fpe_ff1_ctx& ctx, phantom_vector<uint8_t>& S,
        int cnt, int Slen, phantom_vector<uint8_t>& R)
    {
        phantom_vector<uint8_t> tmp(16);
        assert(Slen >= 16);
        assert(16 + 16 * cnt == Slen);

        std::copy(R.begin(), R.begin() + 16, S.begin());

        for (int j=1; j <= cnt; j++) {
            std::copy(R.begin(), R.begin() + 16, tmp.begin());

#if PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN
            tmp[15] ^= (j >>  0) & 0xff;
            tmp[14] ^= (j >>  8) & 0xff;
            tmp[13] ^= (j >> 16) & 0xff;
            tmp[12] ^= (j >> 24) & 0xff;
#else
            *(reinterpret_cast<uint32_t *>(tmp) + 3) ^= j;
#endif

            ctx.aes_enc->encrypt(S.data() + 16 * j, tmp.data());
        }
    }

    inline static void PRF(fpe_ff1_ctx& ctx, phantom_vector<uint8_t>& R,
        phantom_vector<uint8_t>& P, phantom_vector<uint8_t>& Q)
    {
        ctx.aes_enc->encrypt(R.data(), P.data());

        int count = Q.size() >> 4;
        uint8_t *Qi = Q.data();

        phantom_vector<uint8_t> Ri(16);
        for (int cc=0; cc < count; cc++) {
            for (int j=0; j < 16; j++) {
                Ri[j] = Qi[j] ^ R[j];
            }
            ctx.aes_enc->encrypt(R.data(), Ri.data());
            Qi += 16;
        }
    }

    inline static void pow_uv(core::mpz<T>& pow_u, core::mpz<T>& pow_v, T radix, int u, int v)
    {
        core::mpz<T> base, e;

        base = radix;
        if (u > v) {
            e = T(v);
            pow_v = base;
            pow_v = base.pow(e);       // pow_v = radix ^ e
            pow_u = pow_v * base;      // pow_u = radix ^ (e+1)
        }
        else {
            e = T(u);
            pow_u = base;
            pow_u = base.pow(e);       // pow_u = radix ^ e

            if (u == v) {
                pow_v = pow_u;         // pow_v = radix ^ e
            }
            else {  // u < v
                pow_v = pow_u * base;  // pow_v = radix ^ (e+1)
            }
        }
    }

    static const size_t ff1_rounds = 10;
};

}  // namespace crypto
}  // namespace phantom
