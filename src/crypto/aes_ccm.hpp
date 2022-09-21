/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <memory>
#include "crypto/aes.hpp"
#include "crypto/symmetric_key_auth_enc.hpp"


namespace phantom {
namespace crypto {

/**
 * @ingroup symmetric
 * @brief AES CTR mode with CBC-MAC authenticated encryption
 */
class aes_ccm : public symmetric_key_auth_enc, public aligned_base<DEFAULT_MEM_ALIGNMENT>
{
public:
    /**
     * @brief Destroy the aes_ccm object, erasing all memory
     * 
     */
    virtual ~aes_ccm();

    /**
     * @brief Factory method to create an AES-GCM object supporting the specified key length
     * 
     * @param key_len AES-key length
     * @return aes_ccm* Pointer to an aes_ccm object
     */
    static aes_ccm* make(aes_keylen_e key_len);

    /**
     * @brief Set the key
     * 
     * @param key An array of key bytes
     * @param key_len Length of the key (16, 24 or 32)
     * @return int32_t EXIT_SUCCESS on success, EXIT_FAILURE otherwise
     */
    virtual int32_t set_key(const uint8_t *key, size_t key_len);

    /// Encrypt an array of data using the specified symmetric cipher context
    /// {@

    /**
     * @brief Start an authenticated encryption operation
     * 
     * @param iv Initialization vector (IV)
     * @param iv_len Length of IV
     * @param aad Additional authentication data
     * @param aad_len Length of additional authentication data
     * @return int32_t EXIT_SUCCESS on success, EXIT_FAILURE otherwise
     */
    virtual int32_t encrypt_start(const uint8_t *iv, size_t iv_len,
        const uint8_t *aad, size_t aad_len);

    /**
     * @brief Continue authenticated encryption with plaintext data.
     * Additional calls to encrypt_update can be made if the previous calls used
     * a plaintext length of an integer number of block sizes.
     * @param out Ciphertext
     * @param in Plaintext
     * @param len Length of plaintext byte array
     * @return int32_t EXIT_SUCCESS on success, EXIT_FAILURE otherwise
     */
    virtual int32_t encrypt_update(uint8_t *out, const uint8_t *in, size_t len);

    /**
     * @brief Generate authentication tag
     * 
     * @param tag Tag
     * @param tag_len Length of tag in bytes
     * @return int32_t EXIT_SUCCESS on success, EXIT_FAILURE otherwise
     */
    virtual int32_t encrypt_finish(uint8_t *tag, size_t tag_len);

    /// @}

    /// Decrypt an array of data using the specified symmetric cipher context
    /// {@

    /**
     * @brief Start an authenticated decryption operation
     * 
     * @param iv Initialization vector (IV)
     * @param iv_len Length of IV
     * @param aad Additional authentication data
     * @param aad_len Length of additional authentication data
     * @return int32_t EXIT_SUCCESS on success, EXIT_FAILURE otherwise
     */
    virtual int32_t decrypt_start(const uint8_t *iv, size_t iv_len,
        const uint8_t *aad, size_t aad_len);

    /**
     * @brief Continue authenticated decryption with plaintext data.
     * Additional calls to decrypt_update can be made if the previous calls used
     * a ciphertext length of an integer number of block sizes.
     * @param out Plaintext
     * @param in Ciphertext
     * @param len Length of ciphertext byte array
     * @return int32_t EXIT_SUCCESS on success, EXIT_FAILURE otherwise
     */
    virtual int32_t decrypt_update(uint8_t *out, const uint8_t *in, size_t len);

    /**
     * @brief Generate authentication tag
     * 
     * @param tag Tag
     * @param tag_len Length of tag in bytes
     * @return int32_t EXIT_SUCCESS on success, EXIT_FAILURE otherwise
     */
    virtual int32_t decrypt_finish(uint8_t *tag, size_t tag_len);

    /// @}

protected:
    explicit aes_ccm(aes_keylen_e key_len);

    /// A nonce struct for AES-CTR
    struct taes_ctr_nonce_ctr {
        uint8_t m_nonce[4];
        uint8_t m_iv[8];
        uint8_t m_ctr[4];
    };

    /// A union for an AES-CTR
    union taes_ctr_iv {
        taes_ctr_nonce_ctr components;
        uint8_t            data[16];
    };

    /// A union for access to bytes within a 32-bit word
    union u {
        uint8_t b[4];
        uint32_t w;
    };

    std::unique_ptr<aes_encrypt> m_aes;
    uint8_t m_ctr[16];
    uint8_t m_b[16];

    /// The length of nonce
    size_t m_iv_len;

    /// Length of the message used in the 1st CBC-MAC block
    uint64_t m_q;

    uint8_t m_S0[16];

    /// Authentication buffer (updates during the authenticated encryption process)
    alignas(DEFAULT_MEM_ALIGNMENT) uint8_t m_authbuf[16];

    /// The length of additional authentication data
    size_t m_aad_len;

    /// Length of plaintext/ciphertext (updates during the authenticated encryption process)
    size_t m_length;
};

}  // namespace crypto
}  // namespace phantom
