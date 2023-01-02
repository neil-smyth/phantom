/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "bindings/c/ibe_wrapper.h"
#include <algorithm>
#include <cstdio>
#include <map>
#include <memory>
#include <string>
#include "./phantom.hpp"

extern "C" {

    /// A struct used to hide the C++ IBE object
    struct cibe_ctx
    {
        std::unique_ptr<phantom::user_ctx> context;
    };

    /// A struct used to hide the C++ IBE context object
    struct cibe
    {
        std::unique_ptr<phantom::pkc> instance;
    };

    cibe* create_ibe(phantom::pkc_e type)
    {
        cibe* p_ibe = new cibe;
        p_ibe->instance = std::unique_ptr<phantom::pkc>(new phantom::pkc(type));
        return p_ibe;
    }

    void destroy_ibe(cibe *p_ibe)
    {
        delete p_ibe;
    }

    cibe_ctx* create_ibe_ctx(cibe* p_ibe, phantom::security_strength_e strength)
    {
        auto p = new cibe_ctx;
        p->context = std::unique_ptr<phantom::user_ctx>(p_ibe->instance->create_ctx(strength));
        return p;
    }

    void destroy_ibe_ctx(cibe_ctx* ctx)
    {
        delete ctx;
    }

    bool ibe_gen_master_key(cibe* p_ibe, cibe_ctx* ctx)
    {
        return p_ibe->instance->keygen(ctx->context);
    }

    bool ibe_load_master_key(cibe* p_ibe, cibe_ctx* ctx, const uint8_t* master_key, size_t len)
    {
        phantom::phantom_vector<uint8_t> k(master_key, master_key + len);
        return p_ibe->instance->set_private_key(ctx->context, k);
    }

    uint8_t * ibe_store_master_key(cibe* p_ibe, cibe_ctx* ctx, size_t* len)
    {
        uint8_t *master_key = nullptr;
        phantom::phantom_vector<uint8_t> k;
        bool retval = p_ibe->instance->get_private_key(ctx->context, k);
        if (retval) {
            master_key = new uint8_t[k.size()];
            std::copy(k.begin(), k.end(), master_key);
            *len = k.size();
        }
        return master_key;
    }

    bool ibe_load_public_key(cibe* p_ibe, cibe_ctx* ctx, const uint8_t* public_key, size_t len)
    {
        phantom::phantom_vector<uint8_t> k(public_key, public_key + len);
        return p_ibe->instance->set_public_key(ctx->context, k);
    }

    uint8_t * ibe_store_public_key(cibe* p_ibe, cibe_ctx* ctx, size_t* len)
    {
        uint8_t *public_key = nullptr;
        phantom::phantom_vector<uint8_t> k;
        bool retval = p_ibe->instance->get_public_key(ctx->context, k);
        if (retval) {
            public_key = new uint8_t[k.size()];
            std::copy(k.begin(), k.end(), public_key);
            *len = k.size();
        }
        return public_key;
    }

    uint8_t * ibe_extract_user_key(cibe *p_ibe, cibe_ctx *ctx,
                              const uint8_t *id, size_t id_len,
                              size_t *key_len)
    {
        uint8_t *user_key = nullptr;
        phantom::phantom_vector<uint8_t> id_vec(id, id + id_len);
        phantom::phantom_vector<uint8_t> user_key_vec;
        bool retval = p_ibe->instance->ibe_extract(ctx->context, id_vec, user_key_vec);
        if (retval) {
            user_key = new uint8_t[user_key_vec.size()];
            std::copy(user_key_vec.begin(), user_key_vec.end(), user_key);
            *key_len = user_key_vec.size();
        }
        return user_key;
    }

    bool ibe_load_user_key(cibe *p_ibe, cibe_ctx *ctx,
                        const uint8_t *id, size_t id_len,
                        const uint8_t *key, size_t key_len)
    {
        phantom::phantom_vector<uint8_t> id_vec(id, id + id_len);
        phantom::phantom_vector<uint8_t> key_vec(key, key + key_len);
        return p_ibe->instance->ibe_load_user_key(ctx->context, id_vec, key_vec);
    }

    uint8_t * ibe_encrypt(cibe *p_ibe, cibe_ctx *ctx,
                    const uint8_t *id, size_t id_len,
                    const uint8_t *m, size_t m_len,
                    size_t *c_len)
    {
        uint8_t *c = nullptr;
        phantom::phantom_vector<uint8_t> id_vec(id, id + id_len);
        phantom::phantom_vector<uint8_t> m_vec(m, m + m_len);
        phantom::phantom_vector<uint8_t> c_vec;
        bool retval =  p_ibe->instance->ibe_encrypt(ctx->context, id_vec, m_vec, c_vec);
        if (retval) {
            c = new uint8_t[c_vec.size()];
            std::copy(c_vec.begin(), c_vec.end(), c);
            *c_len = c_vec.size();
        }
        return c;
    }

    uint8_t * ibe_decrypt(cibe *p_ibe, cibe_ctx *ctx,
                    const uint8_t *c, size_t c_len,
                    size_t *m_len)
    {
        uint8_t *m = nullptr;
        phantom::phantom_vector<uint8_t> c_vec(c, c + c_len);
        phantom::phantom_vector<uint8_t> m_vec;

        bool retval =  p_ibe->instance->ibe_decrypt(ctx->context, c_vec, m_vec);
        if (retval) {
            m = new uint8_t[m_vec.size()];
            std::copy(m_vec.begin(), m_vec.end(), m);
            *m_len = m_vec.size();
        }
        return m;
    }

    void ibe_free_mem(uint8_t* p)
    {
        delete[] p;
    }

}
