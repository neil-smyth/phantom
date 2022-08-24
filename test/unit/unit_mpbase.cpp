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
#include "core/mpbase.hpp"
#include "core/mpz.hpp"

namespace phantom {
using namespace core;  // NOLINT

const lest::test specification[] =
{
    CASE("modular multiplicative inverse - 16-bit")
    {
        mpz<uint16_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        size_t n = 12;

        uint16_t* pm = m.get_limbs().data();

        uint16_t inv = mpbase<uint16_t>::binvert_limb(pm[0]);
        uint16_t w = (inv * pm[0]) & ((1 << bits_log2<uint16_t>::value()) - 1);

        EXPECT(w == 1);
    },
    CASE("mul_gradeschool - 16-bit")
    {
        mpz<uint16_t> a("33333333", 16);
        mpz<uint16_t> b("12345678", 16);
        mpz<uint16_t> p;
        size_t n = 2;

        uint16_t* pa = a.get_limbs().data();
        uint16_t* pb = b.get_limbs().data();
        p.get_limbs().resize(n + n);
        uint16_t* pp = p.get_limbs().data();

        mpbase<uint16_t>::mul_gradeschool(pp, pa, n, pb, n);
        EXPECT(p.get_str(16) == "3a4114b2f8f21e8");
    },
    CASE("mul_toom22 - 16-bit")
    {
        mpz<uint16_t> a("ffffffff", 16);
        mpz<uint16_t> b("ffffffff", 16);
        mpz<uint16_t> p;
        size_t n = 2;

        uint16_t* pa = a.get_limbs().data();
        uint16_t* pb = b.get_limbs().data();
        p.get_limbs().resize(n + n);
        uint16_t* pp = p.get_limbs().data();

        mpbase<uint16_t>::mul_gradeschool(pp, pa, n, pb, n);
        EXPECT(p.get_str(16) == "fffffffe00000001");

        auto temp_mem = aligned_malloc(sizeof(uint16_t) * ((2*(n) + 2*std::numeric_limits<uint16_t>::digits)));
        uint16_t* scratch = reinterpret_cast<uint16_t*>(temp_mem);
        mpbase<uint16_t>::mul_toom22(pp, pa, n, pb, n, scratch);
        aligned_free(scratch);
        EXPECT(p.get_str(16) == "fffffffe00000001");
    },
    CASE("mul_toom33 - 16-bit")
    {
        mpz<uint16_t> a("139070083316430716933105782829882982469783761747350962758433261259"
                        "483024560988327118439496405919360209470605775491956769155276233566"
                        "680175341469504742094820748571532550529029142864765270626407668466"
                        "404105248436290516846222608147972140137774353362991625247865137718"
                        "64212436793357165124295689588335788376829338",
                        10);
        mpz<uint16_t> b("129456913135221230419860966727734460014053208378182553276756577678"
                        "309852349013448496103066242310517272875300811951068692189889731211"
                        "177164307804606528856274613159947644817865893829742037224143102920"
                        "111956195006961291567736367049275449407365586908213435938246363046"
                        "979819697610444530781953044196108094240471122",
                        10);
        mpz<uint16_t> r("18003583695603150573177042525224623206139428352856625216"
                        "76421461983510822732264432296542759263171997321449829122"
                        "94467055709658076017383185585221903053787212590942022741"
                        "32553228179139807638293735225834245143397026562896879751"
                        "66102776320677058590887634301110367456929943735757845526"
                        "34594587895642864686085513054228278689218617156863399863"
                        "29452638803010904219110762141883864114024005714791072097"
                        "22866628125506758145087527084177205852877629858812824164"
                        "96342460068701541758696081098202879771688889219156581503"
                        "62275319745651018076637525382263445959382008402361285889"
                        "55472695720263243491162785489943243052382192481711377236",
                        10);
        mpz<uint16_t> p;
        size_t n = 64;

        uint16_t* pa = a.get_limbs().data();
        uint16_t* pb = b.get_limbs().data();
        p.get_limbs().resize(n + n);
        uint16_t* pp = p.get_limbs().data();

        mpbase<uint16_t>::mul_gradeschool(pp, pa, n, pb, n);
        EXPECT(p.get_str(10) == r.get_str(10));

        auto temp_mem2 = aligned_malloc(sizeof(uint16_t) * ((2*(n) + 2*std::numeric_limits<uint16_t>::digits)));
        uint16_t* scratch = reinterpret_cast<uint16_t*>(temp_mem2);
        mpbase<uint16_t>::mul_toom22(pp, pa, n, pb, n, scratch);
        aligned_free(temp_mem2);
        EXPECT(p.get_str(10) == r.get_str(10));

        auto temp_mem3 = aligned_malloc(sizeof(uint16_t) * ((2*(n) + 2*std::numeric_limits<uint16_t>::digits)));
        scratch = reinterpret_cast<uint16_t*>(temp_mem3);
        mpbase<uint16_t>::mul_toom33(pp, pa, n, pb, n, scratch);
        aligned_free(temp_mem3);
        EXPECT(p.get_str(10) == r.get_str(10));
    },
    CASE("squaring - 16-bit")
    {
        mpz<uint16_t> a("139070083316430716933105782829882982469783761747350962758433261259"
                        "483024560988327118439496405919360209470605775491956769155276233566"
                        "680175341469504742094820748571532550529029142864765270626407668466"
                        "404105248436290516846222608147972140137774353362991625247865137718"
                        "64212436793357165124295689588335788376829338",
                        10);
        mpz<uint16_t> r("19340488073638981235401451950662921304607904105339638372"
                        "29129902978535679783848956739462702996988869154414581395"
                        "03923456051115791421234131985144263220538522300600321398"
                        "83973960346038568940637582641370490376252864587451137977"
                        "29445470635036681098330071020569167151456318914198648917"
                        "32695893691985850402873956031769947705776733059297847309"
                        "21056952650428277512800164327134734636240066943134861542"
                        "12322596087409619385817207334304857228634774452687102247"
                        "98113110700401427489522945482150986570622338683093005214"
                        "28644382188698252589415554934389236264711005346162862424"
                        "1868361147018097212274464928289233079169497037977518244",
                        10);
        mpz<uint16_t> p;
        size_t n = a.get_limbs().size();

        uint16_t* pa = a.get_limbs().data();
        p.get_limbs().resize(n + n);
        uint16_t* pp = p.get_limbs().data();

        mpbase<uint16_t>::sqr_gradeschool(pp, pa, n);
        EXPECT(p.get_str(16) == r.get_str(16));

        auto temp_mem = aligned_malloc(sizeof(uint16_t) * ((2*(n) + 2*std::numeric_limits<uint16_t>::digits)));
        uint16_t* scratch = reinterpret_cast<uint16_t*>(temp_mem);
        mpbase<uint16_t>::sqr_toom2(pp, pa, n, scratch);
        aligned_free(temp_mem);
        EXPECT(p.get_str(16) == r.get_str(16));

        auto temp_mem2 = aligned_malloc(sizeof(uint16_t) * ((3*(n) + std::numeric_limits<uint16_t>::digits)));
        scratch = reinterpret_cast<uint16_t*>(temp_mem2);
        mpbase<uint16_t>::sqr_toom3(pp, pa, n, scratch);
        aligned_free(temp_mem2);
        EXPECT(p.get_str(16) == r.get_str(16));
    },
    CASE("redcify - 16-bit")
    {
        mpz<uint16_t> a("29", 10);
        mpz<uint16_t> m("53", 10);
        mpz<uint16_t> r, r2;
        size_t n = 1;

        uint16_t* pa = a.get_limbs().data();
        uint16_t* pm = m.get_limbs().data();
        r.get_limbs().resize(n + n);
        uint16_t* pr = r.get_limbs().data();
        r2.get_limbs().resize(n + n);
        uint16_t* pr2 = r2.get_limbs().data();

        uint16_t inv = -mpbase<uint16_t>::binvert_limb(pm[0]);
        mpbase<uint16_t>::redcify(pr, pa, 1, pm, n);
        mpbase<uint16_t>::redc_1_fix(pr2, pr, pm, n, inv);
        if (mpbase<uint16_t>::cmp(pr2, pm, n) >= 0) {
            mpbase<uint16_t>::sub_n(pr2, pr2, pm, n);
        }
        EXPECT(r2.get_str(10) == "29");
        EXPECT(r2.is_negative() == false);
    },
    CASE("redcify - 16-bit")
    {
        mpz<uint16_t> a("10", 16);
        mpz<uint16_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint16_t> r, r2;
        size_t n = 12;

        uint16_t* pa = a.get_limbs().data();
        uint16_t* pm = m.get_limbs().data();
        r.get_limbs().resize(n + n);
        uint16_t* pr = r.get_limbs().data();
        r2.get_limbs().resize(n + n);
        uint16_t* pr2 = r2.get_limbs().data();

        uint16_t inv = -mpbase<uint16_t>::binvert_limb(pm[0]);
        mpbase<uint16_t>::redcify(pr, pa, 1, pm, n);
        mpbase<uint16_t>::redc_1_fix(pr2, pr, pm, n, inv);
        if (mpbase<uint16_t>::cmp(pr2, pm, n) >= 0) {
            mpbase<uint16_t>::sub_n(pr2, pr2, pm, n);
        }
        EXPECT(r2.get_str(16) == "10");
        EXPECT(r2.is_negative() == false);
    },
    CASE("redcify - 16-bit")
    {
        mpz<uint16_t> a("4af727e037724df822483db3ded8547c78fa2bb861681498d894a659e482fbe9", 16);
        mpz<uint16_t> m("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16);
        mpz<uint16_t> r, r2;
        size_t n = 16;

        uint16_t* pa = a.get_limbs().data();
        uint16_t* pm = m.get_limbs().data();
        r.get_limbs().resize(n + n);
        uint16_t* pr = r.get_limbs().data();
        r2.get_limbs().resize(n + n);
        uint16_t* pr2 = r2.get_limbs().data();

        uint16_t inv = -mpbase<uint16_t>::binvert_limb(pm[0]);
        mpbase<uint16_t>::redcify(pr, pa, n, pm, n);
        mpbase<uint16_t>::redc_1_fix(pr2, pr, pm, n, inv);
        if (mpbase<uint16_t>::cmp(pr2, pm, n) >= 0) {
            mpbase<uint16_t>::sub_n(pr2, pr2, pm, n);
        }
        EXPECT(r2.get_str(16) == "4af727e037724df822483db3ded8547c78fa2bb861681498d894a659e482fbe9");
        EXPECT(r2.is_negative() == false);
    },
    CASE("powm - 16-bit")
    {
        mpz<uint16_t> b("2", 10);
        mpz<uint16_t> e("64", 10);
        mpz<uint16_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint16_t> r;
        r.get_limbs().resize(m.get_limbs().size());
        phantom_vector<uint16_t> tp(2 * m.get_limbs().size());

        mpbase<uint16_t>::powm(r.get_limbs().data(), b.get_limbs().data(), 1, e.get_limbs().data(), 1,
                m.get_limbs().data(), m.get_limbs().size(), tp.data());

        EXPECT(r.get_str(16) == "10000000000000000");
        EXPECT(r.is_negative() == false);
    },
    CASE("powm - 16-bit")
    {
        mpz<uint16_t> b("2", 10);
        mpz<uint16_t> e("192", 10);
        mpz<uint16_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint16_t> r;
        r.get_limbs().resize(m.get_limbs().size());
        phantom_vector<uint16_t> tp(2 * m.get_limbs().size());

        mpbase<uint16_t>::powm(r.get_limbs().data(), b.get_limbs().data(), 1, e.get_limbs().data(), 1,
                m.get_limbs().data(), m.get_limbs().size(), tp.data());

        EXPECT(r.get_str(16) == "10000000000000001");
        EXPECT(r.is_negative() == false);
    },
    CASE("powm - 16-bit")
    {
        mpz<uint16_t> b("2", 10);
        mpz<uint16_t> e("256", 10);
        mpz<uint16_t> m("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16);
        mpz<uint16_t> r;
        r.get_limbs().resize(m.get_limbs().size());
        phantom_vector<uint16_t> tp(2 * m.get_limbs().size());

        mpbase<uint16_t>::powm(r.get_limbs().data(), b.get_limbs().data(), 1, e.get_limbs().data(), 1,
                m.get_limbs().data(), m.get_limbs().size(), tp.data());

        EXPECT(r.get_str(16) == "100000000000000010000000000000000");
        EXPECT(r.is_negative() == false);
    },
    CASE("powm - 16-bit")
    {
        mpz<uint16_t> b("4af727e037724df822483db3ded8547c78fa2bb861681498d894a659e482fbe9", 16);
        mpz<uint16_t> e("1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb", 16);
        mpz<uint16_t> m("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16);
        mpz<uint16_t> r;
        r.get_limbs().resize(m.get_limbs().size());
        phantom_vector<uint16_t> tp(5 * m.get_limbs().size());

        mpbase<uint16_t>::powm(r.get_limbs().data(), b.get_limbs().data(), b.get_limbs().size(),
            e.get_limbs().data(), e.get_limbs().size(),
            m.get_limbs().data(), m.get_limbs().size(), tp.data());

        EXPECT(r.get_str(16) == "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec");
        EXPECT(r.is_negative() == false);
    },
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

