/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "bindings/c/shamirs_secret_sharing_wrapper.h"
#include <map>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <memory>
#include <string>
#include "crypto/random_seed.hpp"
#include "crypto/shamirs_secret_sharing.hpp"
#include "utils/third_party/cpp-base64/base64.h"


extern "C" {

    typedef struct csss_ctx   csss_ctx;

    /// A struct used to hide the C++ Shamir's Secret Sharing context object
    struct csss_ctx
    {
        std::shared_ptr<phantom::csprng> prng;
        phantom::phantom_vector<std::string> shards;
        int n;
        int k;
    };

    /// A struct used to hide the C++ Shamir's Secret Sharing object
    struct csss
    {
        phantom::shamirs_secret_sharing* obj;
        csss_ctx ctx;
    };

    csss* create_shamirs_secret_sharing(int n, int k)
    {
        if (0 == n || 0 == k) {
            return nullptr;
        }

        csss* handle = new csss;
        if (handle->ctx.prng == nullptr) {
            handle->ctx.prng =
                std::shared_ptr<phantom::csprng>(phantom::csprng::make(10000, phantom::random_seed::seed_cb));
        }
        handle->obj = new phantom::shamirs_secret_sharing(handle->ctx.prng);
        handle->ctx.n = n;
        handle->ctx.k = k;
        handle->ctx.shards = phantom::phantom_vector<std::string>();
        return handle;
    }

    void destroy_shamirs_secret_sharing(csss *p_sss)
    {
        delete p_sss->obj;
        delete p_sss;
    }

    int get_key_length()
    {
        return phantom::shamirs_secret_sharing::key_bytes;
    }

    int get_shard_length()
    {
        return phantom::shamirs_secret_sharing::shard_length;
    }

    int clear_shards(csss *p_sss)
    {
        p_sss->ctx.shards = phantom::phantom_vector<std::string>();
        return EXIT_SUCCESS;
    }

    bool add_shard(csss *p_sss, const char* shard, int len)
    {
        // Check for max supported shards before adding any more???

        p_sss->ctx.shards.push_back(std::string(shard, len));
        return true;
    }

    const char* get_shard(csss *p_sss, int idx)
    {
        int avail = p_sss->ctx.shards.size();
        if (idx < 0 || idx >= avail) {
            return nullptr;
        }
        return strncpy(new char[p_sss->ctx.shards[idx].length()],  // flawfinder: ignore
                       p_sss->ctx.shards[idx].c_str(),
                       p_sss->ctx.shards[idx].length());
    }

    bool shamirs_secret_sharing_split(csss *p_sss, const char* key)
    {
        if ( nullptr == key ) {
            return false;
        }
        std::string decodedKey = base64_decode(key);
        if ( decodedKey.length() != phantom::shamirs_secret_sharing::key_bytes ) {
            return false;
        }

        phantom::phantom_vector<uint8_t> keyBytes(32);
        for (size_t i=0; i < 32; i++) {
            keyBytes[i] = static_cast<uint8_t>(decodedKey.c_str()[i]);
        }

        size_t n = p_sss->ctx.n;
        size_t k = p_sss->ctx.k;
        phantom::phantom_vector<phantom::phantom_vector<uint8_t>> user_shares(n);
        p_sss->obj->create(user_shares, keyBytes.data(), n, k);

        p_sss->ctx.shards = phantom::phantom_vector<std::string>(n);

        for (size_t i=0; i < n; i++) {
            auto shard_base64 = base64_encode(&user_shares[i][0], phantom::shamirs_secret_sharing::shard_length);
            p_sss->ctx.shards[i] = shard_base64;
        }

        return true;
    }

    const char* shamirs_secret_sharing_combine(csss *p_sss)
    {
        size_t k = p_sss->ctx.k;

        if (p_sss->ctx.shards.size() < k) {
            return nullptr;
        }

        phantom::phantom_vector<phantom::phantom_vector<uint8_t>> quorum_shares(k);
        for (size_t i=0; i < k; i++) {
            std::string share = base64_decode(p_sss->ctx.shards[i]);
            quorum_shares[i] = phantom::phantom_vector<uint8_t>(share.c_str(), share.c_str() + share.size());
        }
        phantom::phantom_vector<uint8_t> key(phantom::shamirs_secret_sharing::key_bytes);
        p_sss->obj->combine(key.data(), quorum_shares, k);
        auto key_base64 = base64_encode(&key[0], phantom::shamirs_secret_sharing::key_bytes);
        return strncpy(new char[key_base64.length()],  // flawfinder: ignore
                       key_base64.c_str(),
                       key_base64.length());
    }
}

