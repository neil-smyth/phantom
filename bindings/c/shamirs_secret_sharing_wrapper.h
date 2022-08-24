/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <stdint.h>


typedef struct csss       csss;


#ifdef __cplusplus
extern "C" {
#endif

    /**
     * @brief Create a Shamir's Secret Sharing object and return a pointer to its handle
     * 
     * @param n Number of shares to create
     * @param k Quorum required to generate a valid secret from the shares
     * @return csss* Handle to a Shamir's Secret Sharing object
     */
    csss* create_shamirs_secret_sharing(int n, int k);

    /**
     * @brief Destroy an FPE object and release its memory resources
     * 
     * @param p_sss Handle to a Shamir's Secret Sharing object
     */
    void destroy_shamirs_secret_sharing(csss *p_sss);

    /// Return the key length that is sharded
    int get_key_length();

    /// Get the length of each key shard that is generated
    int get_shard_length();

    /**
     * @brief Clear the buffer of all stored key shards
     * 
     * @param p_sss Handle to the Shamir's Secret Sharing object
     * @return int EXIT_SUCCESS on success, EXIT_FAILURE otherwise
     */
    int clear_shards(csss *p_sss);

    /**
     * @brief Add a shard to the buffer
     * 
     * @param p_sss Handle to the Shamir's Secret Sharing object
     * @param shard Base-64 encoded user shard
     * @param len Length of the shard
     * @return true Success
     * @return false Failure
     */
    bool add_shard(csss *p_sss, const char* shard, int len);

    /**
     * @brief Get a key shard
     * 
     * @param p_sss Handle to the Shamir's Secret Sharing object
     * @param idx Index of the key shard
     * @return const char* Base-64 encoded key shard
     */
    const char* get_shard(csss *p_sss, int idx);

    /**
     * @brief Split a secret key into the specified number of key shards
     * 
     * @param p_sss Handle to the Shamir's Secret Sharing object
     * @param key Secret key to be sharded
     * @return true Success
     * @return false Failure
     */
    bool shamirs_secret_sharing_split(csss *p_sss, const char* key);

    /**
     * @brief Combine key shards to regenerate the secret key
     * 
     * @param p_sss Handle to the Shamir's Secret Sharing object
     * @return const char* Secret key asabase-64 encoded string, a NULL pointer upon failure
     */
    const char* shamirs_secret_sharing_combine(csss *p_sss);

#ifdef __cplusplus
}
#endif
