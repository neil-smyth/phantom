/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "bindings/c/fpe_wrapper.h"
#include <algorithm>
#include <cstdio>
#include <map>
#include <memory>
#include <string>
#include "./phantom.hpp"

extern "C" {

    /// A struct used to hide the C++ FPE object
    struct cfpe_ctx
    {
        std::unique_ptr<phantom::fpe_ctx> smart_ctx;
    };

    /// A struct used to hide the C++ FPE context object
    struct cfpe
    {
        std::map<std::string, cfpe_ctx> m;
    };

    cfpe* create_fpe(int max_size)
    {
        cfpe* handle = new cfpe;
        handle->m.clear();
        return handle;
    }

    void destroy_fpe(cfpe *p_fpe)
    {
        p_fpe->m.clear();
        delete p_fpe;
    }

    void create_fpe_ctx(cfpe *p_fpe, cfpe_ctx* p_ctx, const uint8_t* user_key, int user_key_len,
        phantom::fpe_type_e type, phantom::fpe_format_e format, const uint8_t* tweak, int tweak_len)
    {
        phantom::phantom_vector<uint8_t> k(user_key, user_key + user_key_len), t(tweak, tweak + tweak_len);
        p_ctx->smart_ctx = phantom::format_preserving_encryption::create_ctx(k, type, format, t);
    }

    bool cache_fpe_key_add(cfpe *p_fpe, const char* hashkey, const uint8_t* user_key, int user_key_len,
        phantom::fpe_type_e type, phantom::fpe_format_e format, const uint8_t* tweak, int tweak_len)
    {
        phantom::phantom_vector<uint8_t> k(user_key, user_key + user_key_len), t(tweak, tweak + tweak_len);

        if (p_fpe->m.find(hashkey) != p_fpe->m.end()) {
            return false;
        }
        p_fpe->m[hashkey].smart_ctx =
            std::unique_ptr<phantom::fpe_ctx>(phantom::format_preserving_encryption::create_ctx(k, type, format, t));
        return true;
    }

    void cache_fpe_key_remove(cfpe *p_fpe, const char* hashkey)
    {
        auto it = p_fpe->m.find(hashkey);
        if (it != p_fpe->m.end()) {
            p_fpe->m.erase(it);
        }
    }

    bool fpe_encrypt_str(cfpe* p_fpe, bool encrypt_flag, cfpe_ctx* p_ctx, char** inout, int n)
    {
        if (nullptr == p_ctx || nullptr == p_ctx->smart_ctx.get() || nullptr == inout) {
            return false;
        }

        phantom::phantom_vector<std::string> vec;
        for (int i=0; i < n; i++) {
            vec.push_back(std::string(inout[i]));
        }

        if (encrypt_flag) {
            phantom::format_preserving_encryption::encrypt_str(p_ctx->smart_ctx, vec);
        }
        else {
            phantom::format_preserving_encryption::decrypt_str(p_ctx->smart_ctx, vec);
        }

        for (int i=0; i < n; i++) {
            std::copy(vec[i].begin(), vec[i].end(), inout[i]);
        }

        return true;
    }

    bool fpe_encrypt_number(cfpe* p_fpe, bool encrypt_flag, cfpe_ctx* p_ctx, int* inout, int n, int range)
    {
        if (nullptr == p_ctx || nullptr == p_ctx->smart_ctx.get() || nullptr == inout) {
            return false;
        }

        phantom::phantom_vector<int> vec = phantom::phantom_vector<int>(inout, inout + n);
        if (encrypt_flag) {
            phantom::format_preserving_encryption::encrypt_number(p_ctx->smart_ctx, vec, range);
        }
        else {
            phantom::format_preserving_encryption::decrypt_number(p_ctx->smart_ctx, vec, range);
        }
        std::copy(vec.begin(), vec.end(), inout);

        return true;
    }

    bool fpe_encrypt_float(cfpe* p_fpe, bool encrypt_flag, cfpe_ctx* p_ctx,
        double* inout, int n, int range, int precision)
    {
        if (nullptr == p_ctx || nullptr == p_ctx->smart_ctx.get() || nullptr == inout) {
            return false;
        }

        phantom::phantom_vector<double> vec = phantom::phantom_vector<double>(inout, inout + n);
        if (encrypt_flag) {
            phantom::format_preserving_encryption::encrypt_float(p_ctx->smart_ctx, vec, range, precision);
        }
        else {
            phantom::format_preserving_encryption::decrypt_float(p_ctx->smart_ctx, vec, range, precision);
        }
        std::copy(vec.begin(), vec.end(), inout);

        return true;
    }

    bool fpe_encrypt_iso8601(cfpe* p_fpe, bool encrypt_flag, cfpe_ctx* p_ctx, char** inout, int n)
    {
        if (nullptr == p_ctx || nullptr == p_ctx->smart_ctx.get() || nullptr == inout) {
            return false;
        }

        phantom::phantom_vector<std::string> vec;
        for (int i=0; i < n; i++) {
            vec.push_back(std::string(inout[i]));
        }

        if (encrypt_flag) {
            phantom::format_preserving_encryption::encrypt_iso8601(p_ctx->smart_ctx, vec);
        }
        else {
            phantom::format_preserving_encryption::decrypt_iso8601(p_ctx->smart_ctx, vec);
        }

        for (int i=0; i < n; i++) {
            std::copy(vec[i].begin(), vec[i].end(), inout[i]);
        }

        return true;
    }

    bool fpe_cache_encrypt_str(cfpe* p_fpe, bool encrypt_flag, const char* hashkey, char** inout, int n)
    {
        if (nullptr == inout) {
            return false;
        }

        auto it = p_fpe->m.find(hashkey);
        if (it == p_fpe->m.end()) {
            return false;
        }

        cfpe_ctx* ctx = &it->second;
        fpe_encrypt_str(p_fpe, encrypt_flag, ctx, inout, n);
        return true;
    }

    bool fpe_cache_encrypt_number(cfpe* p_fpe, bool encrypt_flag, const char* hashkey, int* inout, int n, int range)
    {
        if (nullptr == inout) {
            return false;
        }

        auto it = p_fpe->m.find(hashkey);
        if (it == p_fpe->m.end()) {
            return false;
        }

        cfpe_ctx* ctx = &it->second;
        fpe_encrypt_number(p_fpe, encrypt_flag, ctx, inout, n, range);
        return true;
    }

    bool fpe_cache_encrypt_float(cfpe* p_fpe, bool encrypt_flag, const char* hashkey,
        double* inout, int n, int range, int precision)
    {
        if (nullptr == inout) {
            return false;
        }

        auto it = p_fpe->m.find(hashkey);
        if (it == p_fpe->m.end()) {
            return false;
        }

        cfpe_ctx* ctx = &it->second;
        fpe_encrypt_float(p_fpe, encrypt_flag, ctx, inout, n, range, precision);
        return true;
    }

    bool fpe_cache_encrypt_iso8601(cfpe* p_fpe, bool encrypt_flag, const char* hashkey, char** inout, int n)
    {
        if (nullptr == inout) {
            return false;
        }

        auto it = p_fpe->m.find(hashkey);
        if (it == p_fpe->m.end()) {
            return false;
        }

        cfpe_ctx* ctx = &it->second;
        fpe_encrypt_iso8601(p_fpe, encrypt_flag, ctx, inout, n);
        return true;
    }
}
