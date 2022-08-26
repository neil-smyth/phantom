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
#include "core/number.hpp"

namespace phantom {
using namespace core;  // NOLINT

const lest::test specification[] =
{
    CASE("addition - 8-bit")
    {
        uint8_t a[2] = { 0x00, 0x00 };
        uint8_t b[2] = { 0x00, 0x00 };
        uint8_t s[2];
        number<uint8_t>::uadd(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0x00);
        EXPECT(s[0] == 0x00);
    },
    CASE("addition - 8-bit")
    {
        uint8_t a[2] = { 0x01, 0x00 };
        uint8_t b[2] = { 0xff, 0x00 };
        uint8_t s[2];
        number<uint8_t>::uadd(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0x01);
        EXPECT(s[0] == 0x00);
    },
    CASE("addition - 8-bit")
    {
        uint8_t a[2] = { 0x02, 0xfe };
        uint8_t b[2] = { 0xff, 0x00 };
        uint8_t s[2];
        number<uint8_t>::uadd(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0xff);
        EXPECT(s[0] == 0x01);
    },
    CASE("addition - 8-bit")
    {
        uint8_t a[2] = { 0xff, 0xff };
        uint8_t b[2] = { 0x01, 0x00 };
        uint8_t s[2];
        number<uint8_t>::uadd(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0x00);
        EXPECT(s[0] == 0x00);
    },
    CASE("addition - 16-bit")
    {
        uint16_t a[2] = { 0x0000, 0x0000 };
        uint16_t b[2] = { 0x0000, 0x0000 };
        uint16_t s[2];
        number<uint16_t>::uadd(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0x0000);
        EXPECT(s[0] == 0x0000);
    },
    CASE("addition - 16-bit")
    {
        uint16_t a[2] = { 0x0001, 0x0000 };
        uint16_t b[2] = { 0xffff, 0x0000 };
        uint16_t s[2];
        number<uint16_t>::uadd(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0x0001);
        EXPECT(s[0] == 0x0000);
    },
    CASE("addition - 16-bit")
    {
        uint16_t a[2] = { 0x0002, 0xfffe };
        uint16_t b[2] = { 0xffff, 0x0000 };
        uint16_t s[2];
        number<uint16_t>::uadd(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0xffff);
        EXPECT(s[0] == 0x0001);
    },
    CASE("addition - 16-bit")
    {
        uint16_t a[2] = { 0xffff, 0xffff };
        uint16_t b[2] = { 0x0001, 0x0000 };
        uint16_t s[2];
        number<uint16_t>::uadd(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0x0000);
        EXPECT(s[0] == 0x0000);
    },
    CASE("addition - 32-bit")
    {
        uint32_t a[2] = { 0x00000000, 0x00000000 };
        uint32_t b[2] = { 0x00000000, 0x00000000 };
        uint32_t s[2];
        number<uint32_t>::uadd(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0x00000000UL);
        EXPECT(s[0] == 0x00000000UL);
    },
    CASE("addition - 32-bit")
    {
        uint32_t a[2] = { 0x00000001, 0x00000000 };
        uint32_t b[2] = { 0xffffffff, 0x00000000 };
        uint32_t s[2];
        number<uint32_t>::uadd(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0x00000001UL);
        EXPECT(s[0] == 0x00000000UL);
    },
    CASE("addition - 32-bit")
    {
        uint32_t a[2] = { 0x00000002, 0xfffffffe };
        uint32_t b[2] = { 0xffffffff, 0x00000000 };
        uint32_t s[2];
        number<uint32_t>::uadd(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0xffffffffUL);
        EXPECT(s[0] == 0x00000001UL);
    },
    CASE("addition - 32-bit")
    {
        uint32_t a[2] = { 0xffffffff, 0xffffffff };
        uint32_t b[2] = { 0x00000001, 0x00000000 };
        uint32_t s[2];
        number<uint32_t>::uadd(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0x00000000UL);
        EXPECT(s[0] == 0x00000000UL);
    },
    CASE("addition - 64-bit")
    {
        uint64_t a[2] = { 0x0000000000000000, 0x0000000000000000 };
        uint64_t b[2] = { 0x0000000000000000, 0x0000000000000000 };
        uint64_t s[2];
        number<uint64_t>::uadd(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0x0000000000000000ULL);
        EXPECT(s[0] == 0x0000000000000000ULL);
    },
    CASE("addition - 64-bit")
    {
        uint64_t a[2] = { 0x0000000000000001, 0x0000000000000000 };
        uint64_t b[2] = { 0xffffffffffffffff, 0x0000000000000000 };
        uint64_t s[2];
        number<uint64_t>::uadd(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0x0000000000000001ULL);
        EXPECT(s[0] == 0x0000000000000000ULL);
    },
    CASE("addition - 64-bit")
    {
        uint64_t a[2] = { 0x0000000000000002, 0xfffffffffffffffe };
        uint64_t b[2] = { 0xffffffffffffffff, 0x0000000000000000 };
        uint64_t s[2];
        number<uint64_t>::uadd(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0xffffffffffffffffULL);
        EXPECT(s[0] == 0x0000000000000001ULL);
    },
    CASE("addition - 64-bit")
    {
        uint64_t a[2] = { 0xffffffffffffffff, 0xffffffffffffffff };
        uint64_t b[2] = { 0x0000000000000001, 0x0000000000000000 };
        uint64_t s[2];
        number<uint64_t>::uadd(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0x0000000000000000ULL);
        EXPECT(s[0] == 0x0000000000000000ULL);
    },
    CASE("subtraction - 8-bit")
    {
        uint8_t a[2] = { 0x00, 0x00 };
        uint8_t b[2] = { 0x00, 0x00 };
        uint8_t s[2];
        number<uint8_t>::usub(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0x00);
        EXPECT(s[0] == 0x00);
    },
    CASE("subtraction - 8-bit")
    {
        uint8_t a[2] = { 0x01, 0x00 };
        uint8_t b[2] = { 0xff, 0x00 };
        uint8_t s[2];
        number<uint8_t>::usub(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0xff);
        EXPECT(s[0] == 0x02);
    },
    CASE("subtraction - 8-bit")
    {
        uint8_t a[2] = { 0x02, 0xfe };
        uint8_t b[2] = { 0xff, 0x00 };
        uint8_t s[2];
        number<uint8_t>::usub(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0xfd);
        EXPECT(s[0] == 0x03);
    },
    CASE("subtraction - 8-bit")
    {
        uint8_t a[2] = { 0xff, 0xff };
        uint8_t b[2] = { 0x01, 0x00 };
        uint8_t s[2];
        number<uint8_t>::usub(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0xff);
        EXPECT(s[0] == 0xfe);
    },
    CASE("subtraction - 16-bit")
    {
        uint16_t a[2] = { 0x0000, 0x0000 };
        uint16_t b[2] = { 0x0000, 0x0000 };
        uint16_t s[2];
        number<uint16_t>::usub(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0x0000);
        EXPECT(s[0] == 0x0000);
    },
    CASE("subtraction - 16-bit")
    {
        uint16_t a[2] = { 0x0001, 0x0000 };
        uint16_t b[2] = { 0xffff, 0x0000 };
        uint16_t s[2];
        number<uint16_t>::usub(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0xffff);
        EXPECT(s[0] == 0x0002);
    },
    CASE("subtraction - 16-bit")
    {
        uint16_t a[2] = { 0x0002, 0xfffe };
        uint16_t b[2] = { 0xffff, 0x0000 };
        uint16_t s[2];
        number<uint16_t>::usub(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0xfffd);
        EXPECT(s[0] == 0x0003);
    },
    CASE("subtraction - 16-bit")
    {
        uint16_t a[2] = { 0xffff, 0xffff };
        uint16_t b[2] = { 0x0001, 0x0000 };
        uint16_t s[2];
        number<uint16_t>::usub(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0xffff);
        EXPECT(s[0] == 0xfffe);
    },
    CASE("subtraction - 32-bit")
    {
        uint32_t a[2] = { 0x00000000, 0x00000000 };
        uint32_t b[2] = { 0x00000000, 0x00000000 };
        uint32_t s[2];
        number<uint32_t>::usub(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0x00000000UL);
        EXPECT(s[0] == 0x00000000UL);
    },
    CASE("subtraction - 32-bit")
    {
        uint32_t a[2] = { 0x00000001, 0x00000000 };
        uint32_t b[2] = { 0xffffffff, 0x00000000 };
        uint32_t s[2];
        number<uint32_t>::usub(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0xffffffffUL);
        EXPECT(s[0] == 0x00000002UL);
    },
    CASE("subtraction - 32-bit")
    {
        uint32_t a[2] = { 0x00000002, 0xfffffffe };
        uint32_t b[2] = { 0xffffffff, 0x00000000 };
        uint32_t s[2];
        number<uint32_t>::usub(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0xfffffffdUL);
        EXPECT(s[0] == 0x00000003UL);
    },
    CASE("subtraction - 32-bit")
    {
        uint32_t a[2] = { 0xffffffff, 0xffffffff };
        uint32_t b[2] = { 0x00000001, 0x00000000 };
        uint32_t s[2];
        number<uint32_t>::usub(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0xffffffffUL);
        EXPECT(s[0] == 0xfffffffeUL);
    },
    CASE("subtraction - 64-bit")
    {
        uint64_t a[2] = { 0x0000000000000000, 0x0000000000000000 };
        uint64_t b[2] = { 0x0000000000000000, 0x0000000000000000 };
        uint64_t s[2];
        number<uint64_t>::usub(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0x0000000000000000ULL);
        EXPECT(s[0] == 0x0000000000000000ULL);
    },
    CASE("subtraction - 64-bit")
    {
        uint64_t a[2] = { 0x0000000000000001, 0x0000000000000000 };
        uint64_t b[2] = { 0xffffffffffffffff, 0x0000000000000000 };
        uint64_t s[2];
        number<uint64_t>::usub(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0xffffffffffffffffULL);
        EXPECT(s[0] == 0x0000000000000002ULL);
    },
    CASE("subtraction - 64-bit")
    {
        uint64_t a[2] = { 0x0000000000000002, 0xfffffffffffffffe };
        uint64_t b[2] = { 0xffffffffffffffff, 0x0000000000000000 };
        uint64_t s[2];
        number<uint64_t>::usub(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0xfffffffffffffffdULL);
        EXPECT(s[0] == 0x0000000000000003ULL);
    },
    CASE("subtraction - 64-bit")
    {
        uint64_t a[2] = { 0xffffffffffffffff, 0xffffffffffffffff };
        uint64_t b[2] = { 0x0000000000000001, 0x0000000000000000 };
        uint64_t s[2];
        number<uint64_t>::usub(&s[1], &s[0], a[1], a[0], b[1], b[0]);
        EXPECT(s[1] == 0xffffffffffffffffULL);
        EXPECT(s[0] == 0xfffffffffffffffeULL);
    }
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

