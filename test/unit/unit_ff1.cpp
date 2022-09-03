/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include <iostream>
#include <memory>
#include "./lest.hpp"
#include "crypto/aes_fpe_ff1.hpp"
#include "./phantom.hpp"

namespace phantom {
using namespace crypto;  // NOLINT

bool double_equals(double a, double b, double epsilon = 0.002)
{
    return std::abs(a - b) < epsilon;
}

const lest::test specification[] =
{
    CASE("FPE FF1 Encrypt create_ctx")
    {
        phantom_vector<uint8_t> bad_user_key;
        phantom_vector<uint8_t> user_key = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        phantom_vector<uint8_t> tweak(16);

        std::unique_ptr<fpe_ctx> ctx;
        ctx = aes_fpe_ff1<uint16_t>::create_ctx(user_key, static_cast<aes_keylen_e>(0xffff), tweak);
        EXPECT(nullptr == ctx.get());
        ctx = aes_fpe_ff1<uint16_t>::create_ctx(bad_user_key, aes_keylen_e::AES_128, tweak);
        EXPECT(nullptr == ctx.get());
        ctx = aes_fpe_ff1<uint16_t>::create_ctx(user_key, aes_keylen_e::AES_128, tweak);
        EXPECT(nullptr != ctx.get());
    },
    CASE("FPE FF1 encrypt/decrypt sanity check")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        phantom_vector<uint8_t> tweak;

        std::unique_ptr<fpe_ctx> ctx = aes_fpe_ff1<uint16_t>::create_ctx(user_key, aes_keylen_e::AES_128, tweak);
        EXPECT(nullptr != ctx.get());

        phantom_vector<uint16_t> ct, rt, pt = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

        for (uint8_t radix=10; radix < 20; radix++) {
            aes_fpe_ff1<uint16_t>::encrypt(ctx, radix, pt, ct);
            EXPECT(pt.size() == ct.size());

            aes_fpe_ff1<uint16_t>::decrypt(ctx, radix, ct, rt);
            EXPECT(pt.size() == rt.size());

            for (size_t i=0; i < rt.size(); i++) {
                EXPECT(pt[i] == rt[i]);
            }
        }
    },
    CASE("FPE FF1 encrypt with radix 10")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        phantom_vector<uint8_t> tweak;

        std::unique_ptr<fpe_ctx> ctx = aes_fpe_ff1<uint16_t>::create_ctx(user_key, aes_keylen_e::AES_128, tweak);
        EXPECT(nullptr != ctx.get());

        phantom_vector<uint16_t> ct, rt, badpt, pt = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

        std::unique_ptr<fpe_ctx> badctx = std::unique_ptr<fpe_ctx>(nullptr);
        EXPECT_THROWS_AS(aes_fpe_ff1<uint16_t>::encrypt(badctx, 10, pt, ct), std::runtime_error);

        aes_fpe_ff1<uint16_t>::encrypt(ctx, 10, badpt, ct);
        EXPECT(0U == ct.size());

        aes_fpe_ff1<uint16_t>::encrypt(ctx, 10, pt, ct);
        EXPECT(pt.size() == ct.size());
    },
    CASE("FPE FF1 decrypt with radix 10")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        phantom_vector<uint8_t> tweak;

        std::unique_ptr<fpe_ctx> ctx = aes_fpe_ff1<uint16_t>::create_ctx(user_key, aes_keylen_e::AES_128, tweak);
        EXPECT(nullptr != ctx.get());

        phantom_vector<uint16_t> rt, badct, ct = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

        std::unique_ptr<fpe_ctx> badctx = std::unique_ptr<fpe_ctx>(nullptr);
        EXPECT_THROWS_AS(aes_fpe_ff1<uint16_t>::decrypt(badctx, 10, ct, rt), std::runtime_error);

        aes_fpe_ff1<uint16_t>::decrypt(ctx, 10, badct, rt);
        EXPECT(0U == rt.size());

        aes_fpe_ff1<uint16_t>::decrypt(ctx, 10, ct, rt);
        EXPECT(ct.size() == rt.size());
    },
    CASE("FPE FF1 Encrypt sample #1")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        phantom_vector<uint8_t> tweak;

        std::unique_ptr<fpe_ctx> ctx = aes_fpe_ff1<uint16_t>::create_ctx(user_key, aes_keylen_e::AES_128, tweak);

        phantom_vector<uint16_t> ct, rt, pt = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        aes_fpe_ff1<uint16_t>::encrypt(ctx, 10, pt, ct);
        EXPECT(nullptr != ctx.get());

        aes_fpe_ff1<uint16_t>::decrypt(ctx, 10, ct, rt);

        for (size_t i=0; i < rt.size(); i++) {
            EXPECT(pt[i] == rt[i]);
        }
    },
    CASE("FPE FF1 Encrypt sample #2")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        phantom_vector<uint8_t> tweak = {
            0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30
        };

        std::unique_ptr<fpe_ctx> ctx = aes_fpe_ff1<uint16_t>::create_ctx(user_key, aes_keylen_e::AES_128, tweak);

        phantom_vector<uint16_t> ct, rt, pt = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        aes_fpe_ff1<uint16_t>::encrypt(ctx, 10, pt, ct);
        EXPECT(nullptr != ctx.get());

        aes_fpe_ff1<uint16_t>::decrypt(ctx, 10, ct, rt);

        for (size_t i=0; i < rt.size(); i++) {
            EXPECT(pt[i] == rt[i]);
        }
    },
    CASE("FPE FF1 Encrypt sample #3")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        phantom_vector<uint8_t> tweak = {
            0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37
        };

        std::unique_ptr<fpe_ctx> ctx = aes_fpe_ff1<uint16_t>::create_ctx(user_key, aes_keylen_e::AES_128, tweak);

        phantom_vector<uint16_t> ct, rt, pt = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18};
        aes_fpe_ff1<uint16_t>::encrypt(ctx, 36, pt, ct);
        EXPECT(nullptr != ctx.get());

        aes_fpe_ff1<uint16_t>::decrypt(ctx, 36, ct, rt);

        for (size_t i=0; i < rt.size(); i++) {
            EXPECT(pt[i] == rt[i]);
        }
    },
    CASE("FPE FF1 Encrypt sample #4")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88,
            0x09, 0xCF, 0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F
        };
        phantom_vector<uint8_t> tweak;

        std::unique_ptr<fpe_ctx> ctx = aes_fpe_ff1<uint16_t>::create_ctx(user_key, aes_keylen_e::AES_192, tweak);

        phantom_vector<uint16_t> ct, rt, pt = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        aes_fpe_ff1<uint16_t>::encrypt(ctx, 10, pt, ct);
        EXPECT(nullptr != ctx.get());

        aes_fpe_ff1<uint16_t>::decrypt(ctx, 10, ct, rt);

        for (size_t i=0; i < rt.size(); i++) {
            EXPECT(pt[i] == rt[i]);
        }
    },
    CASE("FPE FF1 Encrypt sample #5")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88,
            0x09, 0xCF, 0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F
        };
        phantom_vector<uint8_t> tweak = {
            0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30
        };

        std::unique_ptr<fpe_ctx> ctx = aes_fpe_ff1<uint16_t>::create_ctx(user_key, aes_keylen_e::AES_192, tweak);

        phantom_vector<uint16_t> ct, rt, pt = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        aes_fpe_ff1<uint16_t>::encrypt(ctx, 10, pt, ct);
        EXPECT(nullptr != ctx.get());

        aes_fpe_ff1<uint16_t>::decrypt(ctx, 10, ct, rt);

        for (size_t i=0; i < rt.size(); i++) {
            EXPECT(pt[i] == rt[i]);
        }
    },
    CASE("FPE FF1 Encrypt sample #6")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88,
            0x09, 0xCF, 0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F
        };
        phantom_vector<uint8_t> tweak = {0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37};

        std::unique_ptr<fpe_ctx> ctx = aes_fpe_ff1<uint16_t>::create_ctx(user_key, aes_keylen_e::AES_192, tweak);

        phantom_vector<uint16_t> ct, rt, pt = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18};
        aes_fpe_ff1<uint16_t>::encrypt(ctx, 36, pt, ct);
        EXPECT(nullptr != ctx.get());

        aes_fpe_ff1<uint16_t>::decrypt(ctx, 36, ct, rt);

        for (size_t i=0; i < rt.size(); i++) {
            EXPECT(pt[i] == rt[i]);
        }
    },
    CASE("FPE FF1 Encrypt sample #7")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
            0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
            0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94};
        phantom_vector<uint8_t> tweak;

        std::unique_ptr<fpe_ctx> ctx = aes_fpe_ff1<uint16_t>::create_ctx(user_key, aes_keylen_e::AES_256, tweak);

        phantom_vector<uint16_t> ct, rt, pt = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        aes_fpe_ff1<uint16_t>::encrypt(ctx, 10, pt, ct);
        EXPECT(nullptr != ctx.get());

        aes_fpe_ff1<uint16_t>::decrypt(ctx, 10, ct, rt);

        for (size_t i=0; i < rt.size(); i++) {
            EXPECT(pt[i] == rt[i]);
        }
    },
    CASE("FPE FF1 Encrypt sample #8")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
            0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
            0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
        };
        phantom_vector<uint8_t> tweak = {0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30};

        std::unique_ptr<fpe_ctx> ctx = aes_fpe_ff1<uint16_t>::create_ctx(user_key, aes_keylen_e::AES_256, tweak);

        phantom_vector<uint16_t> ct, rt, pt = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        aes_fpe_ff1<uint16_t>::encrypt(ctx, 10, pt, ct);
        EXPECT(nullptr != ctx.get());

        aes_fpe_ff1<uint16_t>::decrypt(ctx, 10, ct, rt);

        for (size_t i=0; i < rt.size(); i++) {
            EXPECT(pt[i] == rt[i]);
        }
    },
    CASE("FPE FF1 Encrypt sample #9")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
            0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
            0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
        };
        phantom_vector<uint8_t> tweak = {0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37};

        std::unique_ptr<fpe_ctx> ctx = aes_fpe_ff1<uint16_t>::create_ctx(user_key, aes_keylen_e::AES_256, tweak);

        phantom_vector<uint16_t> ct, rt, pt = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18};
        aes_fpe_ff1<uint16_t>::encrypt(ctx, 36, pt, ct);
        EXPECT(nullptr != ctx.get());

        aes_fpe_ff1<uint16_t>::decrypt(ctx, 36, ct, rt);

        for (size_t i=0; i < rt.size(); i++) {
            EXPECT(pt[i] == rt[i]);
        }
    },
    /*CASE("FPE FF1 numeric string")
    {
        phantom_vector<uint8_t> user_key = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
        phantom_vector<uint8_t> tweak = {0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30};

        auto ctx = format_preserving_encryption::create_ctx(user_key, AES_FF1_128, FPE_STR_NUMERIC, tweak);

        phantom_vector<uint8_t> ct, rt, pt = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        format_preserving_encryption::encrypt_str(ctx, pt, ct);
        EXPECT(nullptr != ctx.get());

        std::cout << "ct = ";
        for (size_t i=0; i<ct.size(); i++) {
            std::cout << (int)ct[i] << " ";
        }
        std::cout << std::dec << std::endl;

        format_preserving_encryption::decrypt_str(ctx, ct, rt);

        std::cout << "rt = ";
        for (size_t i=0; i<rt.size(); i++) {
            EXPECT(pt[i] == rt[i]);
            std::cout << (int)rt[i] << " ";
        }
        std::cout << std::dec << std::endl;
    },
    CASE("FPE FF1 numeric string")
    {
        phantom_vector<uint8_t> user_key = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
        phantom_vector<uint8_t> tweak;

        auto ctx = format_preserving_encryption::create_ctx(user_key, AES_FF1_128, FPE_STR_ALPHANUMERIC, tweak);

        phantom_vector<uint8_t> ct, rt, pt(62);
        for (size_t i=0; i<62; i++) {
            pt[i] = i;
        }
        std::cout << "pt = ";
        for (size_t i=0; i<pt.size(); i++) {
            std::cout << (int)pt[i] << " ";
        }
        std::cout << std::dec << std::endl;

        format_preserving_encryption::encrypt_str(ctx, pt, ct);
        EXPECT(nullptr != ctx.get());

        std::cout << "ct = ";
        for (size_t i=0; i<ct.size(); i++) {
            std::cout << (int)ct[i] << " ";
        }
        std::cout << std::dec << std::endl;

        format_preserving_encryption::decrypt_str(ctx, ct, rt);

        std::cout << "rt = ";
        for (size_t i=0; i<rt.size(); i++) {
            EXPECT(pt[i] == rt[i]);
            std::cout << (int)rt[i] << " ";
        }
        std::cout << std::dec << std::endl;
    },
    CASE("FPE FF1 ASCII PRINTABLE string")
    {
        phantom_vector<uint8_t> user_key = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
        phantom_vector<uint8_t> tweak = {0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30};

        auto ctx = format_preserving_encryption::create_ctx(user_key, AES_FF1_128, FPE_STR_ASCII_PRINTABLE, tweak);

        phantom_vector<uint8_t> ct, rt, pt(96);
        for (size_t i=0; i<96; i++) {
            pt[i] = i;
        }
        std::cout << "pt = ";
        for (size_t i=0; i<pt.size(); i++) {
            std::cout << (int)pt[i] << " ";
        }
        std::cout << std::dec << std::endl;

        format_preserving_encryption::encrypt_str(ctx, pt, ct);
        EXPECT(nullptr != ctx.get());

        std::cout << "ct = ";
        for (size_t i=0; i<ct.size(); i++) {
            std::cout << (int)ct[i] << " ";
        }
        std::cout << std::dec << std::endl;

        format_preserving_encryption::decrypt_str(ctx, ct, rt);

        std::cout << "rt = ";
        for (size_t i=0; i<rt.size(); i++) {
            EXPECT(pt[i] == rt[i]);
            std::cout << (int)rt[i] << " ";
        }
        std::cout << std::dec << std::endl;
    },*/
    CASE("FPE FF1 ASCII PRINTABLE string")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        phantom_vector<uint8_t> tweak = {0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30};

        auto ctx = format_preserving_encryption::create_ctx(user_key, AES_FF1_128, FPE_STR_ASCII_PRINTABLE, tweak);

        std::string pt = "The red fox jumped over the brown gate";
        std::string m = pt;

        format_preserving_encryption::encrypt(ctx, m);
        EXPECT(nullptr != ctx.get());

        format_preserving_encryption::decrypt(ctx, m);
        EXPECT(m.size() == pt.size());
        for (size_t i=0; i < pt.size(); i++) {
            EXPECT(pt[i] == m[i]);
        }
    },
    CASE("FPE FF1 ALPHANUMERIC string")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        phantom_vector<uint8_t> tweak = {0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30};

        auto ctx = format_preserving_encryption::create_ctx(user_key, AES_FF1_128, FPE_STR_ALPHANUMERIC, tweak);

        std::string pt = "The red fox jumped over the brown gate";
        std::string m = pt;

        format_preserving_encryption::encrypt(ctx, m);
        EXPECT(nullptr != ctx.get());

        format_preserving_encryption::decrypt(ctx, m);
        EXPECT(m.size() == pt.size());
        for (size_t i=0; i < pt.size(); i++) {
            EXPECT(pt[i] == m[i]);
        }
    },
    CASE("FPE FF1 NUMERIC string")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        phantom_vector<uint8_t> tweak = {0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30};

        auto ctx = format_preserving_encryption::create_ctx(user_key, AES_FF1_128, FPE_STR_NUMERIC, tweak);

        std::string pt = "The secret code is 012345-6789-3210";
        std::string m = pt;

        format_preserving_encryption::encrypt(ctx, m);
        EXPECT(nullptr != ctx.get());

        format_preserving_encryption::decrypt(ctx, m);
        EXPECT(m.size() == pt.size());
        for (size_t i=0; i < pt.size(); i++) {
            EXPECT(pt[i] == m[i]);
        }
    },
    CASE("FPE FF1 LOWER CASE ALPHANUMERIC string")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        phantom_vector<uint8_t> tweak = {0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30};

        auto ctx = format_preserving_encryption::create_ctx(user_key, AES_FF1_128, FPE_STR_LOWER_ALPHANUMERIC, tweak);

        std::string pt = "The secret code is 012345-6789-3210";
        std::string m = pt;

        format_preserving_encryption::encrypt(ctx, m);
        EXPECT(nullptr != ctx.get());

        format_preserving_encryption::decrypt(ctx, m);
        EXPECT(m.size() == pt.size());
        for (size_t i=0; i < pt.size(); i++) {
            EXPECT(pt[i] == m[i]);
        }
    },
    CASE("FPE FF1 UPPER CASE ALPHANUMERIC string")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        phantom_vector<uint8_t> tweak = {0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30};

        auto ctx = format_preserving_encryption::create_ctx(user_key, AES_FF1_128, FPE_STR_UPPER_ALPHANUMERIC, tweak);

        std::string pt = "The secret code is 012345-6789-3210";
        std::string m = pt;

        format_preserving_encryption::encrypt(ctx, m);
        EXPECT(nullptr != ctx.get());

        format_preserving_encryption::decrypt(ctx, m);
        EXPECT(m.size() == pt.size());
        for (size_t i=0; i < pt.size(); i++) {
            EXPECT(pt[i] == m[i]);
        }
    },
    CASE("FPE FF1 ALPHABETICAL string")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        phantom_vector<uint8_t> tweak = {0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30};

        auto ctx = format_preserving_encryption::create_ctx(user_key, AES_FF1_128, FPE_STR_ALPHABETICAL, tweak);

        std::string pt = "The secret code is 012345-6789-3210";
        std::string m = pt;

        format_preserving_encryption::encrypt(ctx, m);
        EXPECT(nullptr != ctx.get());

        format_preserving_encryption::decrypt(ctx, m);
        EXPECT(m.size() == pt.size());
        for (size_t i=0; i < pt.size(); i++) {
            EXPECT(pt[i] == m[i]);
        }
    },
    CASE("FPE FF1 LOWER CASE ALPHABETICAL string")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        phantom_vector<uint8_t> tweak = {0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30};

        auto ctx = format_preserving_encryption::create_ctx(user_key, AES_FF1_128, FPE_STR_LOWER_ALPHABETICAL, tweak);

        std::string pt = "The secret code is 012345-6789-3210";
        std::string m = pt;

        format_preserving_encryption::encrypt(ctx, m);
        EXPECT(nullptr != ctx.get());

        format_preserving_encryption::decrypt(ctx, m);
        EXPECT(m.size() == pt.size());
        for (size_t i=0; i < pt.size(); i++) {
            EXPECT(pt[i] == m[i]);
        }
    },
    CASE("FPE FF1 UPPER CASE ALPHABETICAL string")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        phantom_vector<uint8_t> tweak = {0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30};

        auto ctx = format_preserving_encryption::create_ctx(user_key, AES_FF1_128, FPE_STR_UPPER_ALPHABETICAL, tweak);

        std::string pt = "The secret code is 012345-6789-3210";
        std::string m = pt;

        format_preserving_encryption::encrypt(ctx, m);
        EXPECT(nullptr != ctx.get());

        format_preserving_encryption::decrypt(ctx, m);
        EXPECT(m.size() == pt.size());
        for (size_t i=0; i < pt.size(); i++) {
            EXPECT(pt[i] == m[i]);
        }
    },
    CASE("FPE FF1 INTEGER NUMBER string")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        phantom_vector<uint8_t> tweak = {0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30};

        auto ctx = format_preserving_encryption::create_ctx(user_key, AES_FF1_128, FPE_NUMBER_INT, tweak);

        int pt = 22;
        int m = pt;

        format_preserving_encryption::encrypt(ctx, m, 5);
        EXPECT(nullptr != ctx.get());

        format_preserving_encryption::decrypt(ctx, m, 5);
        EXPECT(pt == m);
    },
    CASE("FPE FF1 DOUBLE NUMBER string")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        phantom_vector<uint8_t> tweak = {0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30};

        auto ctx = format_preserving_encryption::create_ctx(user_key, AES_FF1_128, FPE_NUMBER_INT, tweak);

        double pt, ct, rt;

        pt = ct = 22.01;
        format_preserving_encryption::encrypt(ctx, ct, 10, 2);
        rt = ct;
        format_preserving_encryption::decrypt(ctx, rt, 10, 2);
        EXPECT(pt == rt);

        pt = ct = 22.02;
        format_preserving_encryption::encrypt(ctx, ct, 10, 2);
        rt = ct;
        format_preserving_encryption::decrypt(ctx, rt, 10, 2);
        EXPECT(pt == rt);

        pt = ct = 1000000000.00;
        format_preserving_encryption::encrypt(ctx, ct, 10, 2);
        rt = ct;
        format_preserving_encryption::decrypt(ctx, rt, 10, 2);
        EXPECT(pt == rt);

        pt = 0.00;
        while (pt < 1000000) {
            pt += 1387.31;
            ct = pt;
            format_preserving_encryption::encrypt(ctx, ct, 10, 2);
            rt = ct;
            format_preserving_encryption::decrypt(ctx, rt, 10, 2);
            EXPECT(double_equals(pt, rt));
        }

        pt = 0.00;
        while (pt < 1000) {
            pt += 10.31497;
            ct = pt;
            format_preserving_encryption::encrypt(ctx, ct, 5, 7);
            rt = ct;
            format_preserving_encryption::decrypt(ctx, rt, 5, 7);
            EXPECT(double_equals(pt, rt));
        }
    },
    CASE("FPE FF1 ISO8601")
    {
        phantom_vector<uint8_t> user_key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        phantom_vector<uint8_t> tweak = {0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30};

        auto ctx = format_preserving_encryption::create_ctx(user_key, AES_FF1_128, FPE_ISO8601, tweak);

        std::string ct, rt, pt;

        pt = ct = "2021-05-15T12:03:58Z";
        format_preserving_encryption::encrypt(ctx, ct);
        rt = ct;
        format_preserving_encryption::decrypt(ctx, rt);
        EXPECT(pt == rt);

        pt = ct = "2500-12-31T23:59:59Z";
        format_preserving_encryption::encrypt(ctx, ct);
        rt = ct;
        format_preserving_encryption::decrypt(ctx, rt);
        EXPECT(pt == rt);

        pt = ct = "0001-01-01T00:00:00Z";
        format_preserving_encryption::encrypt(ctx, ct);
        rt = ct;
        format_preserving_encryption::decrypt(ctx, rt);
        EXPECT(pt == rt);
    },
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

