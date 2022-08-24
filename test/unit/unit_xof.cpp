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
#include "crypto/xof_sha3.hpp"

using namespace phantom;  // NOLINT
using namespace crypto;   // NOLINT

const lest::test specification[] =
{
    CASE("XOF Construct")
    {
        std::unique_ptr<xof_sha3> xof = std::unique_ptr<xof_sha3>(new xof_sha3());
        EXPECT(nullptr != xof);
    },
    CASE("XOF Init")
    {
        std::unique_ptr<xof_sha3> xof = std::unique_ptr<xof_sha3>(new xof_sha3());
        EXPECT(nullptr != xof);
        bool retval = xof->init(0);
        EXPECT(false == retval);
        retval = xof->init(1);
        EXPECT(false == retval);
        retval = xof->init(16);
        EXPECT(true == retval);
        retval = xof->init(64);
        EXPECT(false == retval);
        retval = xof->init(32);
        EXPECT(true == retval);
    },
    CASE("XOF Absorb")
    {
        std::unique_ptr<xof_sha3> xof = std::unique_ptr<xof_sha3>(new xof_sha3());
        EXPECT(nullptr != xof);
        bool retval = xof->init(16);
        EXPECT(true == retval);

        uint8_t data[8] = {0};
        xof->absorb(0, 0);
        xof->absorb(0, 8);
        xof->absorb(data, 8);
    },
    CASE("XOF Final")
    {
        std::unique_ptr<xof_sha3> xof = std::unique_ptr<xof_sha3>(new xof_sha3());
        EXPECT(nullptr != xof);
        bool retval = xof->init(16);
        EXPECT(true == retval);

        uint8_t data[8] = {0};
        xof->absorb(data, 8);
        xof->final();
    },
    CASE("XOF Squeeze")
    {
        std::unique_ptr<xof_sha3> xof = std::unique_ptr<xof_sha3>(new xof_sha3());
        EXPECT(nullptr != xof);
        bool retval = xof->init(32);
        EXPECT(true == retval);

        uint8_t data[8] = {0};
        xof->absorb(data, 8);
        xof->final();

        uint8_t out[64] = {0};
        xof->squeeze(0, 0);
        xof->squeeze(out, 0);
        for (size_t i=0; i < 64; i++) {
            EXPECT(0 == out[i]);
        }
        xof->squeeze(out, 8);
        uint8_t nonzero = 0;
        for (size_t i=0; i < 8; i++) {
            nonzero |= out[i];
        }
        EXPECT(0 != nonzero);
        for (size_t i=8; i < 64; i++) {
            EXPECT(0 == out[i]);
        }
    },
};

int main(int argc, char *argv[])
{
    return lest::run(specification, argc, argv);
}

