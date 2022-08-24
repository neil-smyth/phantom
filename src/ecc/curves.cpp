/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "ecc/curves.hpp"
#include "./phantom_types.hpp"


namespace phantom {
namespace elliptic {


const ec_params_t curves::param_ec_secp192r1 = {
    192,
    24,
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",
    "-3",
    "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
    "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
    "7192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
    "5872D24048BAFB98C050736E2D83D69A6A72C5FC9E66CB3B",
    "38CE388F78EDAB2CC215B177263B1F02A0A99D48863C7612",
    "secp192r1",
};

const ec_params_t curves::param_ec_secp224r1 = {
    224,
    28,
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
    "-3",
    "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
    "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
    "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
    "0",
    "0",
    "secp224r1",
};

const ec_params_t curves::param_ec_secp256r1 = {
    256,
    32,
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    "-3",
    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    "0",
    "0",
    "secp256r1",
};

const ec_params_t curves::param_ec_secp384r1 = {
    384,
    48,
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    "-3",
    "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
    "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
    "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
    "0",
    "0",
    "secp384r1",
};

const ec_params_t curves::param_ec_secp521r1 = {
    521,
    66,
    "1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "ffffffffffffffffffffffffffffffffffffffff",
    "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148"
    "f709a5d03bb5c9b8899c47aebb6fb71e91386409",
    "-3",
    "51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3"
    "bb1bf073573df883d2c34f1ef451fd46b503f00",
    "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a"
    "2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
    "11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b901"
    "3fad0761353c7086a272c24088be94769fd16650",
    "0",
    "0",
    "secp521r1",
};

const ec_params_t curves::param_ec_sect163r2 = {
    163,
    21,
    "800000000000000000000000000000000000000c9",
    "40000000000000000000292fe77e70c12a4234c33",
    "1",
    "20a601907b8c953ca1481eb10512f78744a3205fd",
    "3f0eba16286a2d57ea0991168d4994637e8343e36",
    "d51fbc6c71a0094fa2cdd545b11c5c0c797324f1",
    "0",
    "0",
    "sect163r2",
};

const ec_params_t curves::param_ec_sect233r1 = {
    233,
    30,
    "20000000000000000000000000000000000000004000000000000000001",
    "1000000000000000000000000000013e974e72f8a6922031d2603cfe0d7",
    "1",
    "66647ede6c332c7f8c0923bb58213b333b20e9ce4281fe115f7d8f90ad",
    "fac9dfcbac8313bb2139f1bb755fef65bc391f8b36f8f8eb7371fd558b",
    "1006a08a41903350678e58528bebf8a0beff867a7ca36716f7e01f81052",
    "0",
    "0",
    "sect233r1",
};

const ec_params_t curves::param_ec_sect283r1 = {
    283,
    36,
    "800000000000000000000000000000000000000000000000000000000000000000010a1",
    "3ffffffffffffffffffffffffffffffffffef90399660fc938a90165b042a7cefadb307",
    "1",
    "27b680ac8b8596da5a4af8a19a0303fca97fd7645309fa2a581485af6263e313b79a2f5",
    "5f939258db7dd90e1934f8c70b0dfec2eed25b8557eac9c80e2e198f8cdbecd86b12053",
    "3676854fe24141cb98fe6d4b20d02b4516ff702350eddb0826779c813f0df45be8112f4",
    "0",
    "0",
    "sect283r1",
};

const ec_params_t curves::param_ec_sect409r1 = {
    409,
    52,
    "2000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000001",
    "10000000000000000000000000000000000000000000000000001e2aad6a612f33307be5fa47c3c9e052f838164cd37d9a21173",
    "1",
    "21a5c2c8ee9feb5c4b9a753b7b476b7fd6422ef1f3dd674761fa99d6ac27c8a9a197b272822f6cd57a55aa4f50ae317b13545f",
    "15d4860d088ddb3496b0c6064756260441cde4af1771d4db01ffe5b34e59703dc255a868a1180515603aeab60794e54bb7996a7",
    "61b1cfab6be5f32bbfa78324ed106a7636b9c5a7bd198d0158aa4f5488d08f38514f1fdf4b4f40d2181b3681c364ba0273c706",
    "0",
    "0",
    "sect409r1",
};

const ec_params_t curves::param_ec_sect571r1 = {
    571,
    72,
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000425",
    "3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe661ce18ff559873080"
    "59b186823851ec7dd9ca1161de93d5174d66e8382e9bb2fe84e47",
    "1",
    "2f40e7e2221f295de297117b7f3d62f5c6a97ffcb8ceff1cd6ba8ce4a9a18ad84ffabbd8efa59332be7ad6756a"
    "66e294afd185a78ff12aa520e4de739baca0c7ffeff7f2955727a",
    "303001d34b856296c16c0d40d3cd7750a93d1d2955fa80aa5f40fc8db7b2abdbde53950f4c0d293cdd711a35b6"
    "7fb1499ae60038614f1394abfa3b4c850d927e1e7769c8eec2d19",
    "37bf27342da639b6dccfffeb73d69d78c6c27a6009cbbca1980f8533921e8a684423e43bab08a576291af8f461"
    "bb2a8b3531d2f0485c19b16e2f1516e23dd3c1a4827af1b8ac15b",
    "0",
    "0",
    "sect571r1",
};

const ec_params_t curves::param_ec_sect163k1 = {
    163,
    21,
    "800000000000000000000000000000000000000c9",
    "4000000000000000000020108a2e0cc0d99f8a5ef",
    "1",
    "1",
    "2fe13c0537bbc11acaa07d793de4e6d5e5c94eee8",
    "289070fb05d38ff58321f2e800536d538ccdaa3d9",
    "0",
    "0",
    "sect163k1",
};

const ec_params_t curves::param_ec_sect233k1 = {
    233,
    30,
    "20000000000000000000000000000000000000004000000000000000001",
    "8000000000000000000000000000069d5bb915bcd46efb1ad5f173abdf",
    "0",
    "1",
    "17232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126",
    "1db537dece819b7f70f555a67c427a8cd9bf18aeb9b56e0c11056fae6a3",
    "0",
    "0",
    "sect233k1",
};

const ec_params_t curves::param_ec_sect283k1 = {
    283,
    36,
    "800000000000000000000000000000000000000000000000000000000000000000010a1",
    "1ffffffffffffffffffffffffffffffffffe9ae2ed07577265dff7f94451e061e163c61",
    "0",
    "1",
    "503213f78ca44883f1a3b8162f188e553cd265f23c1567a16876913b0c2ac2458492836",
    "1ccda380f1c9e318d90f95d07e5426fe87e45c0e8184698e45962364e34116177dd2259",
    "0",
    "0",
    "sect283k1",
};

const ec_params_t curves::param_ec_sect409k1 = {
    409,
    52,
    "2000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000001",
    "7ffffffffffffffffffffffffffffffffffffffffffffffffffe5f83b2d4ea20400ec4557d5ed3e3e7ca5b4b5c83b8e01e5fcf",
    "0",
    "1",
    "60f05f658f49c1ad3ab1890f7184210efd0987e307c84c27accfb8f9f67cc2c460189eb5aaaa62ee222eb1b35540cfe9023746",
    "1e369050b7c4e42acba1dacbf04299c3460782f918ea427e6325165e9ea10e3da5f6c42e9c55215aa9ca27a5863ec48d8e0286b",
    "0",
    "0",
    "sect409k1",
};

const ec_params_t curves::param_ec_sect571k1 = {
    571,
    72,
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000425",
    "20000000000000000000000000000000000000000000000000000000000000000000000131850e1f19a63e4b391"
    "a8db917f4138b630d84be5d639381e91deb45cfe778f637c1001",
    "0",
    "1",
    "26eb7a859923fbc82189631f8103fe4ac9ca2970012d5d46024804801841ca44370958493b205e647da304db4ce"
    "b08cbbd1ba39494776fb988b47174dca88c7e2945283a01c8972",
    "349dc807f4fbf374f4aeade3bca95314dd58cec9f307a54ffc61efc006d8a2c9d4979c0ac44aea74fbebbb9f772"
    "aedcb620b01a7ba7af1b320430c8591984f601cd4c143ef1c7a3",
    "0",
    "0",
    "sect571k1",
};

const ec_params_t curves::param_ec_curve25519 = {
    255,
    32,
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
    "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
    "76D06",
    "1",
    "9",
    "20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9",
    "0",
    "0",
    "curve25519",
};

const ec_params_t curves::param_ec_curve448 = {
    448,
    56,
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
    "262a6",
    "1",
    "5",
    "7D235D1295F5B1F66C98AB6E58326FCECBAE5D34F55545D060F75DC28DF3F6EDB8027E2346430D211312C4B150677AF76FD7223D457B5B1A",
    "0",
    "0",
    "curve448",
};

const ec_params_t curves::param_ec_edwards25519 = {
    255,
    32,
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
    "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
    "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3",
    "-1",
    "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a",
    "6666666666666666666666666666666666666666666666666666666666666658",
    "0",
    "0",
    "edwards25519",
};

const ec_params_t curves::param_ec_edwards448 = {
    448,
    56,
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
    "-98a9",
    "1",
    "4F1970C66BED0DED221D15A622BF36DA9E146570470F1767EA6DE324A3D3A46412AE1AF72AB66511433B80E18B00938E2626A82BC70CC05E",
    "693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14",
    "0",
    "0",
    "edwards448",
};

}  // namespace elliptic
}  // namespace phantom
