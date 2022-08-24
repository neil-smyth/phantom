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
#include "core/reduction_barrett.hpp"
#include "core/reduction_montgomery.hpp"

namespace phantom {
using namespace core;  // NOLINT

const lest::test specification[] =
{
    CASE("Reduction - Barrett")
    {
        barrett_fp<uint16_t> r(barrett_fp<uint16_t>(12289));
        reduction<reduction_barrett<uint16_t>, uint16_t> red(r);
        uint16_t result;
        result = red.reduce(0);
        EXPECT(0 == result);
        result = red.reduce(1);
        EXPECT(1 == result);
        result = red.reduce(12288);
        EXPECT(12288 == result);
        result = red.reduce(12289);
        EXPECT(0 == result);
        result = red.reduce(12290);
        EXPECT(1 == result);
        result = red.reduce(2*12289 - 1);
        EXPECT(12288 == result);
    },
    CASE("Multiply - Barrett")
    {
        barrett_fp<uint16_t> r(barrett_fp<uint16_t>(12289));
        reduction<reduction_barrett<uint16_t>, uint16_t> red(r);
        uint16_t result;
        result = red.mul(red.convert_to(0), red.convert_to(0));
        EXPECT(red.convert_to(0) == result);
        result = red.mul(red.convert_to(0), red.convert_to(1));
        EXPECT(red.convert_to(0) == result);
        result = red.mul(red.convert_to(1), red.convert_to(1));
        EXPECT(red.convert_to(1) == result);
        result = red.mul(red.convert_to(1), red.convert_to(12288));
        EXPECT(red.convert_to(12288) == result);
        result = red.mul(red.convert_to(1), red.convert_to(12289));
        EXPECT(red.convert_to(0) == result);
        result = red.mul(red.convert_to(1), red.convert_to(12290));
        EXPECT(red.convert_to(1) == result);
        result = red.mul(red.convert_to(1), red.convert_to(2*12289 - 1));
        EXPECT(red.convert_to(12288) == result);
    },
    CASE("Square - Barrett")
    {
        barrett_fp<uint16_t> r(barrett_fp<uint16_t>(12289));
        reduction<reduction_barrett<uint16_t>, uint16_t> red(r);
        uint16_t result;
        result = red.sqr(red.convert_to(0));
        EXPECT(red.convert_to(0) == result);
        result = red.sqr(red.convert_to(1));
        EXPECT(red.convert_to(1) == result);
        result = red.sqr(red.convert_to(100));
        EXPECT(red.convert_to(10000) == result);
        result = red.sqr(red.convert_to(150));
        EXPECT(red.convert_to(10211) == result);
    },
    CASE("Divide - Barrett")
    {
        barrett_fp<uint16_t> r(barrett_fp<uint16_t>(12289));
        reduction<reduction_barrett<uint16_t>, uint16_t> red(r);
        uint16_t result;
        result = red.div(10000, 1);
        EXPECT(red.convert_to(10000) == result);
        result = red.div(12289, 1);
        EXPECT(red.convert_to(0) == result);
        result = red.div(red.convert_to(12288), red.convert_to(2));
        EXPECT(red.convert_to(6144) == result);
    },
    CASE("Inverse - Barrett")
    {
        barrett_fp<uint16_t> r(barrett_fp<uint16_t>(12289));
        reduction<reduction_barrett<uint16_t>, uint16_t> red(r);
        uint16_t result;
        result = red.inverse(red.convert_to(2));
        EXPECT(red.mul(result, red.convert_to(2)) == red.convert_to(1));
        result = red.inverse(red.convert_to(127));
        EXPECT(red.mul(result, red.convert_to(127)) == red.convert_to(1));
        result = red.inverse(red.convert_to(12288));
        EXPECT(red.mul(result, red.convert_to(12288)) == red.convert_to(1));
    },
    CASE("Add - Barrett")
    {
        barrett_fp<uint16_t> r(barrett_fp<uint16_t>(12289));
        reduction<reduction_barrett<uint16_t>, uint16_t> red(r);
        uint16_t result;
        result = red.add(red.convert_to(1), red.convert_to(1));
        EXPECT(result == red.convert_to(2));
        result = red.add(red.convert_to(12288), red.convert_to(1));
        EXPECT(result == red.convert_to(0));
    },
    CASE("Sub - Barrett")
    {
        barrett_fp<uint16_t> r(barrett_fp<uint16_t>(12289));
        reduction<reduction_barrett<uint16_t>, uint16_t> red(r);
        uint16_t result;
        result = red.sub(red.convert_to(0), red.convert_to(1));
        EXPECT(result == red.convert_to(12288));
        result = red.sub(red.convert_to(12288), red.convert_to(1));
        EXPECT(result == red.convert_to(12287));
    },
    CASE("Right shift 1 bit - Barrett")
    {
        barrett_fp<uint16_t> r(barrett_fp<uint16_t>(12289));
        reduction<reduction_barrett<uint16_t>, uint16_t> red(r);
        uint16_t result;
        result = red.rshift1(0);
        EXPECT(result == 0);
        result = red.rshift1(1);
        EXPECT(result == 6145);
        result = red.rshift1(12288);
        EXPECT(result == 6144);
    },
    CASE("Left shift 1 bit - Barrett")
    {
        barrett_fp<uint16_t> r(barrett_fp<uint16_t>(12289));
        reduction<reduction_barrett<uint16_t>, uint16_t> red(r);
        uint16_t result;
        result = red.lshift1(0);
        EXPECT(result == 0);
        result = red.lshift1(1);
        EXPECT(result == 2);
        result = red.lshift1(6144);
        EXPECT(result == 12288);
        result = red.lshift1(6145);
        EXPECT(result == 1);
        result = red.lshift1(12288);
        EXPECT(result == 12287);
    },
    CASE("x^e - Barrett")
    {
        barrett_fp<uint16_t> r(barrett_fp<uint16_t>(12289));
        reduction<reduction_barrett<uint16_t>, uint16_t> red(r);
        uint16_t result;
        result = red.pow(red.convert_to(0), 2);
        EXPECT(result == red.convert_to(0));
        result = red.pow(red.convert_to(2), 1);
        EXPECT(result == red.convert_to(2));
        result = red.pow(red.convert_to(2), 8);
        EXPECT(result == red.convert_to(256));
        result = red.pow(red.convert_to(12288), 2);
        EXPECT(result == red.convert_to(1));
    },
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

