/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include "./phantom_types.hpp"


typedef struct cfpe       cfpe;
typedef struct cfpe_ctx   cfpe_ctx;

#ifdef __cplusplus
extern "C" {
#endif

    /// Create an FPE object and return a pointer to its handle
    cfpe* create_fpe(int max_size);

    /// Destroy an FPE object and release its memory resources
    void destroy_fpe(cfpe *p_abc);

    /// Create a specific context based on the key, type, format and tweak value
    void create_fpe_ctx(cfpe *p_fpe, cfpe_ctx* p_ctx,
        const uint8_t* user_key, int user_key_len,
        phantom::fpe_type_e type, phantom::fpe_format_e format,
        const uint8_t* tweak, int tweak_len);

    /// Create a specific context based on the key, type, format and tweak value
    /// and cache the value using a user-supplied unique hashkey
    bool cache_fpe_key_add(cfpe *p_fpe, const char* hashkey,
        const uint8_t* user_key, int user_key_len,
        phantom::fpe_type_e type, phantom::fpe_format_e format,
        const uint8_t* tweak, int tweak_len);

    /// Remove a cached conext from the specified FPE object hsndle
    void cache_fpe_key_remove(cfpe *p_fpe, const char* hashkey);

    /**
     * @brief Encrypt/decrypt an array of n strings
     * 
     * @param p_fpe FPE handle
     * @param encrypt_flag True for encrypt, false for decrypt
     * @param p_ctx FPE context handle
     * @param inout Data to be transformed in-place
     * @param n Number of strings in array
     * @return true Success
     * @return false Failure
     */
    bool fpe_encrypt_str(cfpe* p_fpe, bool encrypt_flag, cfpe_ctx* p_ctx,
        char** inout, int n);

    /**
     * @brief Encrypt/decrypt an array of n integers
     * 
     * @param p_fpe FPE handle
     * @param encrypt_flag True for encrypt, false for decrypt
     * @param p_ctx FPE context handle
     * @param inout Data to be transformed in-place
     * @param n Number of integers in array
     * @return true Success
     * @return false Failure
     */
    bool fpe_encrypt_number(cfpe* p_fpe, bool encrypt_flag, cfpe_ctx* p_ctx,
        int* inout, int n, int range);

    /**
     * @brief Encrypt/decrypt an array of n floating-point numbers
     * 
     * @param p_fpe FPE handle
     * @param encrypt_flag True for encrypt, false for decrypt
     * @param p_ctx FPE context handle
     * @param inout Data to be transformed in-place
     * @param n Number of doubles in array
     * @return true Success
     * @return false Failure
     */
    bool fpe_encrypt_float(cfpe* p_fpe, bool encrypt_flag, cfpe_ctx* p_ctx,
        double* inout, int n, int range, int precision);

    /**
     * @brief Encrypt/decrypt an array of n ISO-8601 strings
     * 
     * @param p_fpe FPE handle
     * @param encrypt_flag True for encrypt, false for decrypt
     * @param p_ctx FPE context handle
     * @param inout Data to be transformed in-place
     * @param n Number of strings in array
     * @return true Success
     * @return false Failure
     */
    bool fpe_encrypt_iso8601(cfpe* p_fpe, bool encrypt_flag, cfpe_ctx* p_ctx,
        char** inout, int n);

    /**
     * @brief Encrypt/decrypt an array of n strings using a cached context
     * 
     * @param p_fpe FPE handle
     * @param encrypt_flag True for encrypt, false for decrypt
     * @param p_ctx FPE context handle
     * @param inout Data to be transformed in-place
     * @param n Number of strings in array
     * @return true Success
     * @return false Failure
     */
    bool fpe_cache_encrypt_str(cfpe* p_fpe, bool encrypt_flag,
        const char* hashkey, char** inout, int n);

    /**
     * @brief Encrypt/decrypt an array of n integers using a cached context
     * 
     * @param p_fpe FPE handle
     * @param encrypt_flag True for encrypt, false for decrypt
     * @param p_ctx FPE context handle
     * @param inout Data to be transformed in-place
     * @param n Number of integers in array
     * @return true Success
     * @return false Failure
     */
    bool fpe_cache_encrypt_number(cfpe* p_fpe, bool encrypt_flag,
        const char* hashkey, int* inout, int n, int range);

    /**
     * @brief Encrypt/decrypt an array of n floating-point numbers using a cached context
     * 
     * @param p_fpe FPE handle
     * @param encrypt_flag True for encrypt, false for decrypt
     * @param p_ctx FPE context handle
     * @param inout Data to be transformed in-place
     * @param n Number of doubles in array
     * @return true Success
     * @return false Failure
     */
    bool fpe_cache_encrypt_float(cfpe* p_fpe, bool encrypt_flag,
        const char* hashkey, double* inout, int n, int range, int precision);

    /**
     * @brief Encrypt/decrypt an array of n ISO-8601 strings using a cached context
     * 
     * @param p_fpe FPE handle
     * @param encrypt_flag True for encrypt, false for decrypt
     * @param p_ctx FPE context handle
     * @param inout Data to be transformed in-place
     * @param n Number of strings in array
     * @return true Success
     * @return false Failure
     */
    bool fpe_cache_encrypt_iso8601(cfpe* p_fpe, bool encrypt_flag,
        const char* hashkey, char** inout, int n);

#ifdef __cplusplus
}
#endif
