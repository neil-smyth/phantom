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


typedef struct cibe       cibe;
typedef struct cibe_ctx   cibe_ctx;

#ifdef __cplusplus
extern "C" {
#endif

    /// Create an IBE object and return a pointer to its handle
    cibe* create_ibe(phantom::pkc_e type);

    /// Destroy an IBE object and release its memory resources
    void destroy_ibe(cibe *p_ibe);

    /// Create a specific context based on the algorithm and key length
    cibe_ctx* create_ibe_ctx(cibe* p_ibe, phantom::security_strength_e strength);

    /// Destroy a context
    void destroy_ibe_ctx(cibe_ctx* ctx);

    /// Generate a master key
    bool ibe_gen_master_key(cibe* p_ibe, cibe_ctx* ctx);

    /// Load a master key
    bool ibe_load_master_key(cibe* p_ibe, cibe_ctx* ctx, const uint8_t* master_key, size_t len);

    /// Store a master key
    uint8_t * ibe_store_master_key(cibe* p_ibe, cibe_ctx* ctx, size_t* len);

    /// Load a public key
    bool ibe_load_public_key(cibe *p_ibe, cibe_ctx *ctx, const uint8_t *public_key, size_t len);

    /// Store a public key
    uint8_t * ibe_store_public_key(cibe *p_ibe, cibe_ctx *ctx, size_t *len);

    /// Extract a user key using the master key and a specified public identity
    uint8_t * ibe_extract_user_key(cibe *p_ibe, cibe_ctx *ctx,
                 const uint8_t *id, size_t id_len,
                 size_t *key_len);

    // Load a user key
    bool ibe_load_user_key(cibe *p_ibe, cibe_ctx *ctx,
                       const uint8_t *id, size_t id_len,
                       const uint8_t *key, size_t key_len);

    // Encrypt a message intended for the specified public identity using the public key
    uint8_t * ibe_encrypt(cibe *p_ibe, cibe_ctx *ctx,
                 const uint8_t *id, size_t id_len,
                 const uint8_t *m, size_t m_len,
                 size_t *c_len);
    
    // Decrypt a message using the user key
    uint8_t * ibe_decrypt(cibe *p_ibe, cibe_ctx *ctx,
                 const uint8_t *c, size_t c_len,
                 size_t *m_len);

    void ibe_free_mem(uint8_t *p);

#ifdef __cplusplus
}
#endif
