/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include "./phantom_memory.hpp"


#if defined(_MSC_VER)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif


#if defined(__GNUG__)
#if defined(__SIZEOF_INT128__)
// Define 128-bit integer types as per stdint naming convention if compiler supported
/// @{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

using uint128_t = unsigned __int128;
using int128_t  = __int128;

#pragma GCC diagnostic pop
/// @}
#endif
#endif


namespace phantom {


#if defined(ENABLE_PKC)

/**
 * @brief Core implementation
 * 
 * This namespace defines private APIs for core types, functions, variables, etc.
 */
namespace core {}

/**
 * @brief Cryptographic implementation
 * 
 * This namespace defines private APIs for cryptographic types, functions, variables, etc.
 */
namespace crypto {}

/**
 * @brief Elliptic Curve Cryptography (ECC) implementation
 * 
 * This namespace defines private APIs for ECC types, functions, variables, etc.
 */
namespace elliptic {}

/**
 * @brief Logging and tracing implementation
 * 
 * This namespace defines private APIs for logging types, functions, variables, etc.
 */
namespace logging {}

/**
 * @brief NTRU implementation
 * 
 * This namespace defines private APIs for NTRU types, functions, variables, etc.
 */
namespace ntru {}

/**
 * @brief Data encoding and parsing implementation
 * 
 * This namespace defines private APIs for data packing types, functions, variables, etc.
 */
namespace packing {}

/**
 * @brief Random sampling implementation
 * 
 * This namespace defines private APIs for sampling types, functions, variables, etc.
 */
namespace sampling {}

/**
 * @brief Cryptographic schemes implementation
 * 
 * This namespace defines private APIs for scheme types, functions, variables, etc.
 */
namespace schemes {}

/**
 * @brief Utilities implementation
 * 
 * This namespace defines private APIs for general purpose utilities
 */
namespace utilities {}

#endif  // ENABLE_PKC


/// CSPRNG pool size used to store random 32-bit words
#define RANDOM_POOL_SIZE        64

/// The enumerated logging level
enum log_level_e {
    LOG_LEVEL_NONE = 0,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
};


extern log_level_e g_pkc_log_level;  ///< A global logging level associated with PKC

/// An enumerated type for security strengths
enum security_strength_e {
    SECURITY_STRENGTH_60 = 0,
    SECURITY_STRENGTH_80,
    SECURITY_STRENGTH_96,
    SECURITY_STRENGTH_112,
    SECURITY_STRENGTH_128,
    SECURITY_STRENGTH_160,
    SECURITY_STRENGTH_192,
    SECURITY_STRENGTH_224,
    SECURITY_STRENGTH_256,
    SECURITY_STRENGTH_288,
    SECURITY_STRENGTH_320,
};

/// An enumerated type to describe the word size of the CPU
enum cpu_word_size_e {
    CPU_WORD_SIZE_8 = 8,
    CPU_WORD_SIZE_16 = 16,
    CPU_WORD_SIZE_32 = 32,
    CPU_WORD_SIZE_64 = 64,
};

/// The native machine word size
#if defined (__x86_64) || defined(_WIN64)
#define IS_64BIT
#define NATIVE_CPU_WORD_SIZE    phantom::cpu_word_size_e::CPU_WORD_SIZE_64
#else
#define NATIVE_CPU_WORD_SIZE    phantom::cpu_word_size_e::CPU_WORD_SIZE_32
#endif


#if defined(ENABLE_PKC)

/// The public-key crypto types
enum pkc_e {
    PKC_IBE_DLP = 0,
    PKC_KEM_SABER,
    PKC_KEM_KYBER,
    PKC_KEY_ECDH,
    PKC_PKE_KYBER,
    PKC_PKE_SABER,
    PKC_PKE_RSAES_OAEP,
    PKC_SIG_DILITHIUM,
    PKC_SIG_FALCON,
    PKC_SIG_ECDSA,
    PKC_SIG_EDDSA,
    PKC_SIG_RSASSA_PSS,
};

#endif  // ENABLE_PKC


/// FPE types (algorithm and key size)
enum fpe_type_e
{
    AES_FF1_128 = 0,
    AES_FF1_192,
    AES_FF1_256,
    AES_FF3_1_128,
    AES_FF3_1_192,
    AES_FF3_1_256,
    AES_FEA_1_128,
    AES_FEA_1_192,
    AES_FEA_1_256,
    AES_FEA_2_128,
    AES_FEA_2_192,
    AES_FEA_2_256,
};

// Data format used with Format Preserving Encryption
enum fpe_format_e
{
    FPE_STR_NUMERIC = 0,
    FPE_STR_ALPHANUMERIC,
    FPE_STR_LOWER_ALPHANUMERIC,
    FPE_STR_UPPER_ALPHANUMERIC,
    FPE_STR_ALPHABETICAL,
    FPE_STR_LOWER_ALPHABETICAL,
    FPE_STR_UPPER_ALPHABETICAL,
    FPE_STR_ASCII_PRINTABLE,
    FPE_STR_UTF8,
    FPE_STR_UTF16,
    FPE_NUMBER_INT,
    FPE_ISO8601,
};

/// An enumerated type for a block cipher keylength and type
enum symmetric_key_type_e {
    SYMKEY_AES_128_ENC = 0,
    SYMKEY_AES_192_ENC,
    SYMKEY_AES_256_ENC,
    SYMKEY_AES_128_DEC,
    SYMKEY_AES_192_DEC,
    SYMKEY_AES_256_DEC,
    SYMKEY_AES_128_CTR,
    SYMKEY_AES_192_CTR,
    SYMKEY_AES_256_CTR,
    SYMKEY_AES_128_GCM,
    SYMKEY_AES_192_GCM,
    SYMKEY_AES_256_GCM,
    SYMKEY_AES_128_CCM,
    SYMKEY_AES_192_CCM,
    SYMKEY_AES_256_CCM
};

/// An enumerated type for hashing functions
enum hash_alg_e {
    HASH_SHA2_224 = 0,
    HASH_SHA2_256,
    HASH_SHA2_384,
    HASH_SHA2_512,
    HASH_SHA2_512_224,
    HASH_SHA2_512_256,
    HASH_SHA3_224,
    HASH_SHA3_256,
    HASH_SHA3_384,
    HASH_SHA3_512,
};

/// An enumerated type for XOF's
enum xof_alg_e {
    XOF_SHAKE_128 = 0,
    XOF_SHAKE_256,
};

/// An enumerated type for key sharing
enum key_sharing_type_e {
    KEY_SHARING_SHAMIRS,
};


/// fpe_ctx A struct to define the FPE context
struct fpe_ctx
{
    fpe_type_e   type;
    fpe_format_e format;
};

/// pad_code A struct defining the character set symbols for FPE
struct pad_code
{
    uint16_t codeword;
    size_t   position;
};

/// Definition of the entropy callback function
using csprng_entropy_cb = void (*)(size_t, uint8_t*);

}  // namespace phantom
