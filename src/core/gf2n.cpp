/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "core/gf2n.hpp"

namespace phantom {
namespace core {


static const uint16_t morton_lut_256[256] =
{
    0x0000, 0x0001, 0x0004, 0x0005, 0x0010, 0x0011, 0x0014, 0x0015,
    0x0040, 0x0041, 0x0044, 0x0045, 0x0050, 0x0051, 0x0054, 0x0055,
    0x0100, 0x0101, 0x0104, 0x0105, 0x0110, 0x0111, 0x0114, 0x0115,
    0x0140, 0x0141, 0x0144, 0x0145, 0x0150, 0x0151, 0x0154, 0x0155,
    0x0400, 0x0401, 0x0404, 0x0405, 0x0410, 0x0411, 0x0414, 0x0415,
    0x0440, 0x0441, 0x0444, 0x0445, 0x0450, 0x0451, 0x0454, 0x0455,
    0x0500, 0x0501, 0x0504, 0x0505, 0x0510, 0x0511, 0x0514, 0x0515,
    0x0540, 0x0541, 0x0544, 0x0545, 0x0550, 0x0551, 0x0554, 0x0555,
    0x1000, 0x1001, 0x1004, 0x1005, 0x1010, 0x1011, 0x1014, 0x1015,
    0x1040, 0x1041, 0x1044, 0x1045, 0x1050, 0x1051, 0x1054, 0x1055,
    0x1100, 0x1101, 0x1104, 0x1105, 0x1110, 0x1111, 0x1114, 0x1115,
    0x1140, 0x1141, 0x1144, 0x1145, 0x1150, 0x1151, 0x1154, 0x1155,
    0x1400, 0x1401, 0x1404, 0x1405, 0x1410, 0x1411, 0x1414, 0x1415,
    0x1440, 0x1441, 0x1444, 0x1445, 0x1450, 0x1451, 0x1454, 0x1455,
    0x1500, 0x1501, 0x1504, 0x1505, 0x1510, 0x1511, 0x1514, 0x1515,
    0x1540, 0x1541, 0x1544, 0x1545, 0x1550, 0x1551, 0x1554, 0x1555,
    0x4000, 0x4001, 0x4004, 0x4005, 0x4010, 0x4011, 0x4014, 0x4015,
    0x4040, 0x4041, 0x4044, 0x4045, 0x4050, 0x4051, 0x4054, 0x4055,
    0x4100, 0x4101, 0x4104, 0x4105, 0x4110, 0x4111, 0x4114, 0x4115,
    0x4140, 0x4141, 0x4144, 0x4145, 0x4150, 0x4151, 0x4154, 0x4155,
    0x4400, 0x4401, 0x4404, 0x4405, 0x4410, 0x4411, 0x4414, 0x4415,
    0x4440, 0x4441, 0x4444, 0x4445, 0x4450, 0x4451, 0x4454, 0x4455,
    0x4500, 0x4501, 0x4504, 0x4505, 0x4510, 0x4511, 0x4514, 0x4515,
    0x4540, 0x4541, 0x4544, 0x4545, 0x4550, 0x4551, 0x4554, 0x4555,
    0x5000, 0x5001, 0x5004, 0x5005, 0x5010, 0x5011, 0x5014, 0x5015,
    0x5040, 0x5041, 0x5044, 0x5045, 0x5050, 0x5051, 0x5054, 0x5055,
    0x5100, 0x5101, 0x5104, 0x5105, 0x5110, 0x5111, 0x5114, 0x5115,
    0x5140, 0x5141, 0x5144, 0x5145, 0x5150, 0x5151, 0x5154, 0x5155,
    0x5400, 0x5401, 0x5404, 0x5405, 0x5410, 0x5411, 0x5414, 0x5415,
    0x5440, 0x5441, 0x5444, 0x5445, 0x5450, 0x5451, 0x5454, 0x5455,
    0x5500, 0x5501, 0x5504, 0x5505, 0x5510, 0x5511, 0x5514, 0x5515,
    0x5540, 0x5541, 0x5544, 0x5545, 0x5550, 0x5551, 0x5554, 0x5555
};

template<>
uint8_t gf2n<uint8_t>::square_0(uint8_t w)
{
    uint8_t result = morton_lut_256[w];
    return result;
}

template<>
uint16_t gf2n<uint16_t>::square_0(uint16_t w)
{
    uint16_t result = morton_lut_256[w & 0xff];
    return result;
}

template<>
uint32_t gf2n<uint32_t>::square_0(uint32_t w)
{
    uint32_t result =  (uint32_t)morton_lut_256[ w       & 0xff]        |
                      ((uint32_t)morton_lut_256[(w >> 8) & 0xff] << 16);
    return result;
}

template<>
uint64_t gf2n<uint64_t>::square_0(uint64_t w)
{
    uint64_t result =  (uint64_t)morton_lut_256[ w        & 0xff]        |
                      ((uint64_t)morton_lut_256[(w >>  8) & 0xff] << 16) |
                      ((uint64_t)morton_lut_256[(w >> 16) & 0xff] << 32) |
                      ((uint64_t)morton_lut_256[(w >> 24) & 0xff] << 48);
    return result;
}

template<>
uint8_t gf2n<uint8_t>::square_1(uint8_t w)
{
    uint8_t result = morton_lut_256[w >> 4];
    return result;
}

template<>
uint16_t gf2n<uint16_t>::square_1(uint16_t w)
{
    uint16_t result = morton_lut_256[(w >> 8) & 0xff];
    return result;
}

template<>
uint32_t gf2n<uint32_t>::square_1(uint32_t w)
{
    uint32_t result =  (uint32_t)morton_lut_256[(w >> 16) & 0xff]        |
                      ((uint32_t)morton_lut_256[(w >> 24) & 0xff] << 16);
    return result;
}

template<>
uint64_t gf2n<uint64_t>::square_1(uint64_t w)
{
    uint64_t result =  (uint64_t)morton_lut_256[(w >> 32) & 0xff]        |
                      ((uint64_t)morton_lut_256[(w >> 40) & 0xff] << 16) |
                      ((uint64_t)morton_lut_256[(w >> 48) & 0xff] << 32) |
                      ((uint64_t)morton_lut_256[(w >> 56) & 0xff] << 48);
    return result;
}


template<>
void gf2n<uint8_t>::mul_1x1(uint8_t* r1, uint8_t* r0, const uint8_t a, const uint8_t b)
{
    uint8_t h, l, s;
    uint8_t tab[2];
    uint8_t a1, a2;

    a1 = a & (0x7F);

    tab[0] = 0;
    tab[1] = a1;

    s = tab[b & 0x1];
    l = s;
    s = tab[b >> 1 & 0x1];
    l ^= s << 1;
    h = s >> 7;
    s = tab[b >> 2 & 0x1];
    l ^= s << 2;
    h ^= s >> 6;
    s = tab[b >> 3 & 0x1];
    l ^= s << 3;
    h ^= s >> 5;
    s = tab[b >> 4 & 0x1];
    l ^= s << 4;
    h ^= s >> 4;
    s = tab[b >> 5 & 0x1];
    l ^= s << 5;
    h ^= s >> 3;
    s = tab[b >> 6 & 0x1];
    l ^= s << 6;
    h ^= s >> 2;
    s = tab[b >> 7 & 0x1];
    l ^= s << 7;
    h ^= s >> 1;

    *r1 = h;
    *r0 = l;
}

template<>
void gf2n<uint16_t>::mul_1x1(uint16_t* r1, uint16_t* r0, const uint16_t a, const uint16_t b)
{
    uint16_t h, l, s;
    uint16_t tab[4], top1b = a >> 15;
    uint16_t a1, a2;

    a1 = a & (0x7FFF);
    a2 = a1 << 1;

    tab[0] = 0;
    tab[1] = a1;
    tab[2] = a2;
    tab[3] = a1 ^ a2;

    s = tab[b & 0x3];
    l = s;
    s = tab[b >> 2 & 0x3];
    l ^= s << 2;
    h = s >> 14;
    s = tab[b >> 4 & 0x3];
    l ^= s << 4;
    h ^= s >> 12;
    s = tab[b >> 6 & 0x3];
    l ^= s << 6;
    h ^= s >> 10;
    s = tab[b >> 8 & 0x3];
    l ^= s << 8;
    h ^= s >> 8;
    s = tab[b >> 10 & 0x3];
    l ^= s << 10;
    h ^= s >> 6;
    s = tab[b >> 12 & 0x3];
    l ^= s << 12;
    h ^= s >> 4;
    s = tab[b >> 14 & 0x3];
    l ^= s << 14;
    h ^= s >> 2;

    // Compensate for the top bit of a
    if (top1b & 01) {
        l ^= b << 15;
        h ^= b >> 1;
    }

    *r1 = h;
    *r0 = l;
}

template<>
void gf2n<uint32_t>::mul_1x1(uint32_t* r1, uint32_t* r0, const uint32_t a, const uint32_t b)
{
    uint32_t h, l, s;
    uint32_t tab[8], top2b = a >> 30;
    uint32_t a1, a2, a4;

    a1 = a & (0x3FFFFFFF);
    a2 = a1 << 1;
    a4 = a2 << 1;

    tab[0] = 0;
    tab[1] = a1;
    tab[2] = a2;
    tab[3] = a1 ^ a2;
    tab[4] = a4;
    tab[5] = a1 ^ a4;
    tab[6] = a2 ^ a4;
    tab[7] = tab[3] ^ a4;

    s = tab[b & 0x7];
    l = s;
    s = tab[b >> 3 & 0x7];
    l ^= s << 3;
    h = s >> 29;
    s = tab[b >> 6 & 0x7];
    l ^= s << 6;
    h ^= s >> 26;
    s = tab[b >> 9 & 0x7];
    l ^= s << 9;
    h ^= s >> 23;
    s = tab[b >> 12 & 0x7];
    l ^= s << 12;
    h ^= s >> 20;
    s = tab[b >> 15 & 0x7];
    l ^= s << 15;
    h ^= s >> 17;
    s = tab[b >> 18 & 0x7];
    l ^= s << 18;
    h ^= s >> 14;
    s = tab[b >> 21 & 0x7];
    l ^= s << 21;
    h ^= s >> 11;
    s = tab[b >> 24 & 0x7];
    l ^= s << 24;
    h ^= s >> 8;
    s = tab[b >> 27 & 0x7];
    l ^= s << 27;
    h ^= s >> 5;
    s = tab[b >> 30];
    l ^= s << 30;
    h ^= s >> 2;

    // Compensate for the top two bits of a
    if (top2b & 01) {
        l ^= b << 30;
        h ^= b >> 2;
    }
    if (top2b & 02) {
        l ^= b << 31;
        h ^= b >> 1;
    }

    *r1 = h;
    *r0 = l;
}

template<>
void gf2n<uint64_t>::mul_1x1(uint64_t* r1, uint64_t* r0, const uint64_t a, const uint64_t b)
{
    uint64_t h, l, s;
    uint64_t tab[16], top3b = a >> 61;
    uint64_t a1, a2, a4, a8;

    a1 = a & 0x1FFFFFFFFFFFFFFFULL;
    a2 = a1 << 1;
    a4 = a2 << 1;
    a8 = a4 << 1;

    tab[0] = 0;
    tab[1] = a1;
    tab[2] = a2;
    tab[3] = a1 ^ a2;
    tab[4] = a4;
    tab[5] = a1 ^ a4;
    tab[6] = a2 ^ a4;
    tab[7] = tab[3] ^ a4;
    tab[8] = a8;
    tab[9] = a1 ^ a8;
    tab[10] = a2 ^ a8;
    tab[11] = tab[3] ^ a8;
    tab[12] = a4 ^ a8;
    tab[13] = a1 ^ tab[12];
    tab[14] = a2 ^ tab[12];
    tab[15] = a1 ^ tab[14];

    s = tab[b & 0xF];
    l = s;
    s = tab[b >> 4 & 0xF];
    l ^= s << 4;
    h = s >> 60;
    s = tab[b >> 8 & 0xF];
    l ^= s << 8;
    h ^= s >> 56;
    s = tab[b >> 12 & 0xF];
    l ^= s << 12;
    h ^= s >> 52;
    s = tab[b >> 16 & 0xF];
    l ^= s << 16;
    h ^= s >> 48;
    s = tab[b >> 20 & 0xF];
    l ^= s << 20;
    h ^= s >> 44;
    s = tab[b >> 24 & 0xF];
    l ^= s << 24;
    h ^= s >> 40;
    s = tab[b >> 28 & 0xF];
    l ^= s << 28;
    h ^= s >> 36;
    s = tab[b >> 32 & 0xF];
    l ^= s << 32;
    h ^= s >> 32;
    s = tab[b >> 36 & 0xF];
    l ^= s << 36;
    h ^= s >> 28;
    s = tab[b >> 40 & 0xF];
    l ^= s << 40;
    h ^= s >> 24;
    s = tab[b >> 44 & 0xF];
    l ^= s << 44;
    h ^= s >> 20;
    s = tab[b >> 48 & 0xF];
    l ^= s << 48;
    h ^= s >> 16;
    s = tab[b >> 52 & 0xF];
    l ^= s << 52;
    h ^= s >> 12;
    s = tab[b >> 56 & 0xF];
    l ^= s << 56;
    h ^= s >> 8;
    s = tab[b >> 60];
    l ^= s << 60;
    h ^= s >> 4;

    // Compensate for the top three bits of a
    if (top3b & 01) {
        l ^= b << 61;
        h ^= b >> 3;
    }
    if (top3b & 02) {
        l ^= b << 62;
        h ^= b >> 2;
    }
    if (top3b & 04) {
        l ^= b << 63;
        h ^= b >> 1;
    }

    *r1 = h;
    *r0 = l;
}

}  // namespace core
}  // namespace phantom
