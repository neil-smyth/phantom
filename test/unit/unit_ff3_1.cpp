/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include <iostream>
#include <memory>
#include "./lest.hpp"
#include "crypto/aes_fpe_ff3_1.hpp"
#include "./phantom.hpp"

namespace phantom {
using namespace crypto;  // NOLINT

bool double_equals(double a, double b, double epsilon = 0.002)
{
    return std::abs(a - b) < epsilon;
}

const lest::test specification[] =
{
    CASE("FPE FF3 Encrypt create_ctx")
    {
        phantom_vector<uint8_t> bad_user_key;
        phantom_vector<uint8_t> user_key = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        phantom_vector<uint8_t> tweak(7);
        phantom_vector<uint8_t> badtweak(8);

        aes_fpe_ff3_1<int> uut;
        std::unique_ptr<fpe_ctx> ctx;
        ctx = aes_fpe_ff3_1<uint16_t>::create_ctx(user_key, aes_keylen_e::AES_128, badtweak);
        EXPECT(nullptr == ctx.get());
        ctx = aes_fpe_ff3_1<uint16_t>::create_ctx(user_key, static_cast<aes_keylen_e>(0xffff), tweak);
        EXPECT(nullptr == ctx.get());
        ctx = aes_fpe_ff3_1<uint16_t>::create_ctx(bad_user_key, aes_keylen_e::AES_128, tweak);
        EXPECT(nullptr == ctx.get());
        ctx = aes_fpe_ff3_1<uint16_t>::create_ctx(user_key, aes_keylen_e::AES_128, tweak);
        EXPECT(nullptr != ctx.get());
    },
    CASE("FPE FF3 encrypt/decrypt sanity check")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        phantom_vector<uint8_t> tweak(7);

        std::unique_ptr<fpe_ctx> ctx = aes_fpe_ff3_1<uint16_t>::create_ctx(user_key, aes_keylen_e::AES_128, tweak);
        EXPECT(nullptr != ctx.get());

        phantom_vector<uint16_t> ct, rt, pt = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

        for (uint8_t radix=10; radix < 20; radix++) {
            aes_fpe_ff3_1<uint16_t>::encrypt(ctx, radix, pt, ct);
            EXPECT(pt.size() == ct.size());

            aes_fpe_ff3_1<uint16_t>::decrypt(ctx, radix, ct, rt);
            EXPECT(pt.size() == rt.size());

            for (size_t i=0; i < rt.size(); i++) {
                EXPECT(pt[i] == rt[i]);
            }
        }
    },
    CASE("FPE FF3 encrypt with radix 10")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        phantom_vector<uint8_t> tweak(7);

        std::unique_ptr<fpe_ctx> ctx = aes_fpe_ff3_1<uint16_t>::create_ctx(user_key, aes_keylen_e::AES_128, tweak);
        EXPECT(nullptr != ctx.get());

        phantom_vector<uint16_t> ct, rt, badpt, pt = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

        std::unique_ptr<fpe_ctx> badctx = std::unique_ptr<fpe_ctx>(nullptr);
        EXPECT_THROWS_AS(aes_fpe_ff3_1<uint16_t>::encrypt(badctx, 10, pt, ct), std::runtime_error);

        aes_fpe_ff3_1<uint16_t>::encrypt(ctx, 10, badpt, ct);
        EXPECT(0 == ct.size());

        aes_fpe_ff3_1<uint16_t>::encrypt(ctx, 10, pt, ct);
        EXPECT(pt.size() == ct.size());
    },
    CASE("FPE FF3 decrypt with radix 10")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        phantom_vector<uint8_t> tweak(7);

        std::unique_ptr<fpe_ctx> ctx = aes_fpe_ff3_1<uint16_t>::create_ctx(user_key, aes_keylen_e::AES_128, tweak);
        EXPECT(nullptr != ctx.get());

        phantom_vector<uint16_t> rt, badct, ct = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

        std::unique_ptr<fpe_ctx> badctx = std::unique_ptr<fpe_ctx>(nullptr);
        EXPECT_THROWS_AS(aes_fpe_ff3_1<uint16_t>::decrypt(badctx, 10, ct, rt), std::runtime_error);

        aes_fpe_ff3_1<uint16_t>::decrypt(ctx, 10, badct, rt);
        EXPECT(0 == rt.size());

        aes_fpe_ff3_1<uint16_t>::decrypt(ctx, 10, ct, rt);
        EXPECT(ct.size() == rt.size());
    },
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

