/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <memory>
#include <new>
#include <string>
#include <vector>

#include "./phantom_types.hpp"

/**
 * @brief Phantom namespace for library-wide scope
 * 
 * This namespace defines all public APIs for the phantom library.
 */
namespace phantom {

/**
 * @brief Build information
 * 
 * A class with static methods used to provide build information 
 */
class build_info
{
public:
    static const std::string version();
    static const std::string build_date();
    static const std::string compiler();
};

/** 
 * @brief User context
 * 
 * An interface class for the user context to a specific scheme and parameter set
 */
class user_ctx : public aligned_base<DEFAULT_MEM_ALIGNMENT>
{
public:
    virtual ~user_ctx() {}

    virtual pkc_e get_scheme() = 0;
    virtual size_t get_set() = 0;
};

// Forward declaration of the scheme interface class
class scheme;

/** 
 * @brief Public Key Encryption
 * 
 * A simple wrapper class to provide an interface to the various schemes
 */
class pkc
{
public:
    /// Class constructor based on the selected scheme and parameter set
    explicit pkc(pkc_e type);

    /// Class destructor
    ~pkc();

    /// Create a context for the pkc instance based on the required security strength
    std::unique_ptr<user_ctx> create_ctx(security_strength_e strength,
                                         cpu_word_size_e size_hint = NATIVE_CPU_WORD_SIZE,
                                         bool masking = true) const;

    /// Create a context for the pkc instance based on a specific parameter set
    std::unique_ptr<user_ctx> create_ctx(size_t set,
                                         cpu_word_size_e size_hint = NATIVE_CPU_WORD_SIZE,
                                         bool masking = true) const;

    /// @brief Key generation - creates a public/private key pair
    /// @param ctx The user context containing the key
    /// @return True on success, false otherwise
    bool keygen(std::unique_ptr<user_ctx>& ctx);

    /// @brief Load an encoded public key into the specified user context
    /// @param ctx The user context containing the key
    /// @param k The input public key
    /// @return True on success, false otherwise
    bool set_public_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k);

    /// @brief Retrieve a public key as an encoded byte array
    /// @param ctx The user context containing the key
    /// @param k The output public key
    /// @return True on success, false otherwise
    bool get_public_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k);

    /// @brief Load an encoded private key into the specified user context
    /// @param ctx The user context containing the key
    /// @param k The input private key
    /// @return True on success, false otherwise
    bool set_private_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& k);

    /// @brief Retrieve a private key as an encoded byte array
    /// @param ctx The user context containing the key
    /// @param k The output private key
    /// @return True on success, false otherwise
    bool get_private_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& k);

    /// @brief Get the message length associated with the cryptosystem
    /// @param ctx The user context containing the key
    /// @return Message length
    size_t get_msg_len(std::unique_ptr<user_ctx>& ctx) const;

    /// @brief Signing of a message
    /// @param ctx The user context containing the key
    /// @param m The input message to be signed
    /// @param s The output signature
    /// @return True on success, false otherwise
    bool sig_sign(std::unique_ptr<user_ctx>& ctx,
        const phantom_vector<uint8_t>& m, phantom_vector<uint8_t>& s);
    bool sig_sign(std::unique_ptr<user_ctx>& ctx,
        const phantom_vector<uint8_t>& m, phantom_vector<uint8_t>& s, const phantom_vector<uint8_t>& c);

    /// @brief Verification of a message
    /// @param ctx The user context containing the key
    /// @param m The input message to be signed
    /// @param s The input signature
    /// @return True on success, false otherwise
    bool sig_verify(std::unique_ptr<user_ctx>& ctx,
        const phantom_vector<uint8_t>& m, const phantom_vector<uint8_t>& s);
    bool sig_verify(std::unique_ptr<user_ctx>& ctx,
        const phantom_vector<uint8_t>& m, const phantom_vector<uint8_t>& s, const phantom_vector<uint8_t>& c);

    /// @brief Encryption of a message
    /// @param ctx The user context containing the key
    /// @param pt The input plaintext message to be encrypted
    /// @param ct The output ciphertext message
    /// @return True on success, false otherwise
    bool pke_encrypt(std::unique_ptr<user_ctx>& ctx,
        const phantom_vector<uint8_t> pt, phantom_vector<uint8_t>& ct);

    /// @brief Decryption of a message
    /// @param ctx The user context containing the key
    /// @param ct The input ciphertext message to be decrypted
    /// @param pt The output plaintext message
    /// @return True on success, false otherwise
    bool pke_decrypt(std::unique_ptr<user_ctx>& ctx,
        const phantom_vector<uint8_t> ct, phantom_vector<uint8_t>& pt);

    /// @brief Use a public key to encapsulate the ciphertext message c and output a shared key
    /// @param ctx The user context containing the key
    /// @param pk The public key associated with the other party
    /// @param c The output ciphertext message to be exchanged
    /// @param key The output shared key
    /// @return True on success, false otherwise
    bool kem_encapsulate(std::unique_ptr<user_ctx>& ctx,
        const phantom_vector<uint8_t>& pk, phantom_vector<uint8_t>& c, phantom_vector<uint8_t>& key);

    /// @brief Use a private key to decapsulate the ciphertext message c and output a shared key
    /// @param ctx The user context containing the key
    /// @param c The input ciphertext message to be exchanged
    /// @param key The output shared key
    /// @return True on success, false otherwise
    bool kem_decapsulate(std::unique_ptr<user_ctx>& ctx,
        const phantom_vector<uint8_t>& c, phantom_vector<uint8_t>& key);

    /// @brief Perform all setup and precomputation for the base point
    /// @param ctx The user context containing the key
    /// @return True on success, false otherwise
    bool key_exchange_setup(std::unique_ptr<user_ctx>& ctx);

    /// @brief Generate a random key pair and exchange the public key
    /// @param ctx The user context containing the key
    /// @param m The output message containing the public key to be exchanged
    /// @return True on success, false otherwise
    bool key_exchange_init(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& m);

    /// @brief Generate a shared key using the key pair and the recipient's public key
    /// @param ctx The user context containing the random key pair
    /// @param m The input message containing the receipient's public key to be exchanged
    /// @param shared_key The output shared key
    /// @return True on success, false otherwise
    bool key_exchange_final(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& m,
        phantom_vector<uint8_t>& shared_key);

    /// @brief Load an IBE User Key
    /// @param ctx The user context containing the key
    /// @param id The ID of the user for which a User Key is being extracted
    /// @param key The output User Key
    /// @return True on success, false otherwise
    bool ibe_load_user_key(std::unique_ptr<user_ctx>& ctx,
        const phantom_vector<uint8_t>& id, const phantom_vector<uint8_t>& key);

    /// @brief Extract an IBE User Key
    /// @param ctx The user context containing the key
    /// @param id The ID of the user for which a User Key is being extracted
    /// @param key The output User Key
    /// @return True on success, false otherwise
    bool ibe_extract(std::unique_ptr<user_ctx>& ctx,
        const phantom_vector<uint8_t>& id, phantom_vector<uint8_t>& key);

    /// @brief Use a public key to encapsulate the ciphertext message c and output a shared key
    /// @param ctx The user context containing the key
    /// @param id The ID of the user for which a message will be encrypted
    /// @param m The message to be encrypted
    /// @param c The output ciphertext message to be exchanged
    /// @return True on success, false otherwise
    bool ibe_encrypt(std::unique_ptr<user_ctx>& ctx,
        const phantom_vector<uint8_t>& id, const phantom_vector<uint8_t>& m, phantom_vector<uint8_t>& c);

    /// @brief Use a private key to decapsulate the ciphertext message c and output a shared key
    /// @param ctx The user context containing the key
    /// @param c The input ciphertext message that is exchanged
    /// @param m The output received message
    /// @return True on success, false otherwise
    bool ibe_decrypt(std::unique_ptr<user_ctx>& ctx,
        const phantom_vector<uint8_t> c, phantom_vector<uint8_t>& m);

private:
    /// An instance of the selected PKC scheme - PIMPL idiom
    std::unique_ptr<scheme> m_scheme;
};


/// Forward declaration of classes required by csprng
/// @{

namespace crypto {

class aes_ctr_drbg;
class csprng_buffer;

}  // namespace crypto

/// @}

/**
 * @ingroup random
 * @brief CSPRNG implementation
 * 
 * An AES-CTR-DRBG based cryptographically secure PRNG.
 */
class csprng : public aligned_base<DEFAULT_MEM_ALIGNMENT>
{
public:
    ~csprng();

    /// @brief Create a CSPRNG object based on the user's selected options
    /// @param seed_period The number of random bytes generated between re-seeding
    /// @param cb A callback used to periodically re-seed the CSPRNG
    /// @return The FPE object
    static csprng* make(size_t seed_period, csprng_entropy_cb cb);

    /// @brief Generate 0 to 32 bits
    /// @param m Number of bits
    /// @return A 32-bit random word, most significant bits padded with 0
    uint32_t get_bits(size_t n);

    /// @brief Generate a specified byte array
    /// @param destination Array pointer to write the random bytes to
    /// @param len Number of bytes to write
    void get_mem(uint8_t* destination, size_t len);

    /// @brief Generate a random boolean - templated
    /// @return A random integer, most significant bits padded with 0
    template<typename T, typename std::enable_if<std::is_integral<T>::value, int>::type* = nullptr>
    T get() { return get_bit(); }

    /// @brief Generate a random double value - templated
    /// @return A random floting point number
    template<typename T, typename std::enable_if<std::is_floating_point<T>::value, int>::type* = nullptr>
    T get() { return get_double(); }

    /// @brief Generate a random boolean
    bool get_bit();

    /// @brief Generate a random 8-bit integer value
    uint8_t get_u8();

    /// @brief Generate a random 16-bit integer value
    uint16_t get_u16();

    /// @brief Generate a random 32-bit integer value
    uint32_t get_u32();

    /// @brief Generate a random 64-bit integer value
    uint64_t get_u64();

    /// @brief Generate a random float value
    float get_float();

    /// @brief Generate a random double value
    double get_double();

private:
    csprng(size_t seed_period, csprng_entropy_cb cb);

    /// Update the buffered random pool
    void update_pool();

    /// Remove 32 bits from the pool and increment the pool read index
    void decrease_pool_bits();

    // A buffer used to maintain random bits for output
    alignas(DEFAULT_MEM_ALIGNMENT) uint32_t  m_random_pool[RANDOM_POOL_SIZE];
    int32_t   m_bits;
    int32_t   m_wr_idx;
    int32_t   m_rd_idx;

    // A buffer used to store bits for the prng_var function
    uint32_t  m_var_buf;
    size_t    m_var_bits;

    // The number of random bytes to be produced before the CSPRNG
    // is reseeded
    size_t    m_seed_period;

    // The underlying CSPRNG - AES-CTR-DRBG
    std::unique_ptr<crypto::aes_ctr_drbg> m_aes_ctr_drbg;

    /// A buffer used to store the AES-CTR-DRBG output
    std::unique_ptr<crypto::csprng_buffer> m_buffer;
};

/// Template specialization for the get methods of csprng
/// @{
template <>
inline uint8_t csprng::get<uint8_t>() { return get_u8(); }
template <>
inline uint16_t csprng::get<uint16_t>() { return get_u16(); }
template <>
inline uint32_t csprng::get<uint32_t>() { return get_u32(); }
template <>
inline uint64_t csprng::get<uint64_t>() { return get_u64(); }
template <>
inline float csprng::get<float>() { return get_float(); }
/// @}


/** 
 * @brief Format Preserving Encryption interface
 * 
 * An interface to create FPE objects and provide a common interface (factory method)
 */
class format_preserving_encryption
{
private:
    /// Constructor is not permitted to be called
    format_preserving_encryption() {}

public:
    virtual ~format_preserving_encryption() {}

    /// @brief Create a context for the fpe instance based on the user's selected options
    /// @param user_key The user;s key (a byte array)
    /// @param type The tpe of FPE to be used
    /// @param format The FPE format to be used (character set, representation)
    /// @param tweak // The FPE tweak to be used (optional)
    /// @return The FPE context returned in a smart pointer
    static std::unique_ptr<fpe_ctx> create_ctx(const phantom_vector<uint8_t>& user_key,
        fpe_type_e type, fpe_format_e format, const phantom_vector<uint8_t>& tweak);

    /// Single value encryption methods
    /// @{
    static void encrypt(std::unique_ptr<fpe_ctx>& ctx, std::string& inout);
    static void encrypt(std::unique_ptr<fpe_ctx>& ctx, int& inout, int range);
    static void encrypt(std::unique_ptr<fpe_ctx>& ctx, double& inout, int range, int precision);
    /// @}

    /// Array encryption methods
    /// @{
    static void encrypt(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<std::string>& inout);
    static void encrypt(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<int>& inout, int range);
    static void encrypt(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<double>& inout, int range, int precision);
    /// @}

    /// Single value decryption methods
    /// @{
    static void decrypt(std::unique_ptr<fpe_ctx>& ctx, std::string& inout);
    static void decrypt(std::unique_ptr<fpe_ctx>& ctx, int& inout, int range);
    static void decrypt(std::unique_ptr<fpe_ctx>& ctx, double& inout, int range, int precision);
    /// @}

    /// Array decryption methods
    /// @{
    static void decrypt(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<std::string>& inout);
    static void decrypt(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<int>& inout, int range);
    static void decrypt(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<double>& inout, int range, int precision);
    /// @}
};

/** 
 * @brief Symmetric Key context
 */
class symmetric_key_ctx
{
public:
    virtual ~symmetric_key_ctx() {}

    /// Setter method to define the cipher type and key length
    void set_keylen(symmetric_key_type_e type)
    {
        m_type = type;
    }

    /// Getter method to retrieve the cipher type and key length
    symmetric_key_type_e get_keylen()
    {
        return m_type;
    }

protected:
    symmetric_key_type_e m_type;
};


/**
 * @brief Symmetric Key Cipher
 * 
 * A common interface to set the key, encrypt and decrypt data
 * using different symmetric key ciphers
 */
class symmetric_key_cipher
{
public:
    /// @brief Create a symmetric key context for a user specified symmetric key cipher
    /// @param cipher_type The symmetric key cipher type and key length
    /// @return A pointer to a symmetric key cipher context
    static symmetric_key_ctx* make(symmetric_key_type_e cipher_type);

    virtual ~symmetric_key_cipher() {}

    /// A method to configure the keyspace
    static int32_t set_key(symmetric_key_ctx* ctx, const uint8_t *key, size_t key_len);

    /// Encrypt an array of data using the specified symmetric cipher context
    /// {@
    static int32_t encrypt_start(symmetric_key_ctx* ctx, const uint8_t *iv, size_t iv_len,
        const uint8_t *authdata = nullptr, size_t authdata_len = 0);
    static int32_t encrypt(symmetric_key_ctx* ctx, uint8_t *out, const uint8_t *in, size_t len);
    static int32_t encrypt_finish(symmetric_key_ctx* ctx, uint8_t *tag, size_t tag_len);
    /// @}

    /// Decrypt an array of data using the specified symmetric cipher context
    /// {@
    static int32_t decrypt_start(symmetric_key_ctx* ctx, const uint8_t *iv, size_t iv_len,
        const uint8_t *authdata = nullptr, size_t authdata_len = 0);
    static int32_t decrypt(symmetric_key_ctx* ctx, uint8_t *out, const uint8_t *in, size_t len);
    static int32_t decrypt_finish(symmetric_key_ctx* ctx, uint8_t *tag, size_t tag_len);
    /// @}

private:
    // Private constructor (factory method used)
    symmetric_key_cipher() {}
};


/// Forward declaration of classes required by hashing_function
/// @{

namespace crypto {

class hash;

}  // namespace crypto

/**
 * @brief Cryptographic hashing function
 * 
 * A common interface to create and operate hashing functions
 */
class hashing_function
{
public:
    virtual ~hashing_function();

    /**
     * @brief Create a hashing context for a user specified hashing function
     * 
     * @param type The type of hashing algorithm
     * @return key_sharing* A pointer to a hashing object
     */
    static hashing_function* make(hash_alg_e type);

    /**
     * @brief Get the length of hash that will be generated
     * 
     * @return size_t Hash length
     */
    size_t get_length() const;

    /**
     * @brief Initialization of the hashing function
     * 
     * @return true Success
     * @return false Failure
     */
    bool init();

    /**
     * @brief Update the hash with a specified number of bytes
     * 
     * This can be called none to many times.
     *
     * @param data A pointer to an array of bytes
     * @param len The number of bytes to be consumed
     */
    void update(const uint8_t *data, size_t len);

    /**
     * @brief Generate the final hash value and copy to the output
     * 
     * @param data A pointer to the hash value output
     */
    void final(uint8_t *data);

private:
    // Private constructor (factory method used)
    hashing_function();

    /// An instance of the selected hashing function - PIMPL idiom
    std::unique_ptr<crypto::hash> m_hash;

    /// The type of hash
    hash_alg_e m_hash_type;
};


/**
 * @brief Key Sharing
 * 
 * A common interface to create shared keys and combine them to retrieve
 * the original secret
 */
class key_sharing
{
public:
    virtual ~key_sharing() {}

    /// Getter method to retrieve the type
    virtual key_sharing_type_e get_keylen() = 0;

    /// @brief Create a key sharing context for a user specified key sharing algorithm
    /// @param type The type of key sharing algorithm
    /// @param key_len The secret key length to be used
    /// @param prng A (CS)PRNG to be used to by the key sharing algorithm where necessary
    /// @return A pointer to a key sharing object
    static key_sharing* make(key_sharing_type_e type, size_t key_len, std::shared_ptr<csprng>& prng);

    /// @brief Consume a secret key and produce an array of shared keys
    /// @param out A reference to n vectors of key shares that are produced
    /// @param key The secret key to be consumed
    /// @param n The total quorum size
    /// @param k The minimum number of users required to retrieve the secret key
    /// @return EXIT_SUCCESS upon success, otherwise EXIT_FAILURE
    virtual int32_t create(phantom_vector<phantom_vector<uint8_t>> &out,
                           const phantom_vector<uint8_t>& key,
                           size_t n,
                           size_t k) = 0;

    /// @brief Consume an array of shared keys and produce the secret key
    /// @param key The secret key to be produced
    /// @param shares A reference to k vectors of key shares that are consumed
    /// @param k The minimum number of users required to retrieve the secret key
    /// @return EXIT_SUCCESS upon success, otherwise EXIT_FAILURE
    virtual int32_t combine(phantom_vector<uint8_t>& key,
                            const phantom_vector<phantom_vector<uint8_t>> &shares,
                            size_t k) = 0;

protected:
    // Private constructor (factory method used)
    key_sharing() {}
};

}  // namespace phantom
