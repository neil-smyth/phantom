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
 * @brief AES Galois Counter Mode authenticated encryption
 */
class aes_gcm : public symmetric_key_auth_enc
{
public:
    /**
     * @brief Destroy the aes_gcm object, erasing all memory
     * 
     */
    virtual ~aes_gcm();

    /**
     * @brief Factory method to create an AES-GCM object supporting the specified key length
     * 
     * @param key_len AES-key length
     * @return aes_gcm* Pointer to an aes_gcm object
     */
    static aes_gcm* make(aes_keylen_e key_len);

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
    /**
     * @brief Construct a new aes_gcm object, hidden ctor as factory method is used
     * 
     * @param key_len Length of AES key encoded as an aes_keylen_e
     */
    explicit aes_gcm(aes_keylen_e key_len);

    /**
     * @brief XOR two 16 byte input blocks
     * 
     * @param out The output block of bytes
     * @param in1 Input 1
     * @param in2 Input 2
     */
    static inline void xor_block_16(uint8_t *out, const uint8_t *in1, const uint8_t *in2);

    /**
     * @brief XOR two variable length input blocks
     * 
     * @param out The output block of bytes
     * @param in1 Input 1
     * @param in2 Input 2
     * @param n Length of input 1 and input 2
     */
    static inline void xor_block(uint8_t *out, const uint8_t *in1, const uint8_t *in2, size_t n);

    /**
     * @brief GCM multiplication of a 16 byte array
     * 
     * @param out Output
     * @param in Input
     */
    void gcm_mult(uint8_t* out, const uint8_t* in);

    /**
     * @brief Perform an AES_GCM authenticated encryption update
     * 
     * @param out Output byte array
     * @param in Input byte array
     * @param len Length of the input byte array
     * @param encrypt_flag True if encryption, false if decryption
     * @return int32_t 
     */
    int32_t update(uint8_t *out, const uint8_t *in, size_t len, bool encrypt_flag);

    /// The AES encryption object
    std::unique_ptr<aes_encrypt> m_aes;

    /// Authentication data
    phantom_vector<uint8_t> m_auth_data;

    /// Key related material used for the GCM multiplication
    alignas(DEFAULT_MEM_ALIGNMENT) uint64_t m_hh[16], m_hl[16];

    /// GCM multiplication constants
    alignas(DEFAULT_MEM_ALIGNMENT) static const uint64_t m_last4[16];

    /// The initialization vector (IV)
    alignas(DEFAULT_MEM_ALIGNMENT) uint8_t m_iv[16];

    /// The encrypted base IV
    alignas(DEFAULT_MEM_ALIGNMENT) uint8_t m_iv_enc[16];

    /// Authentication buffer (updates during the authenticated encryption process)
    alignas(DEFAULT_MEM_ALIGNMENT) uint8_t m_authbuf[16];

    /// The length of additional authentication data
    size_t m_aad_len;

    /// Length of plaintext/ciphertext (updates during the authenticated encryption process)
    size_t m_length;
};

}  // namespace crypto
}  // namespace phantom
