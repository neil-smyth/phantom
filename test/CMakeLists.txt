include_directories(${TEST_SOURCE_DIR}) 
link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

add_executable(unit_aes unit/unit_aes.cpp) 
target_link_libraries(unit_aes phantom_static)

if (ENABLE_AES_CTR)
    add_executable(unit_aes_ctr unit/unit_aes_ctr.cpp) 
    target_link_libraries(unit_aes_ctr phantom_static)

    add_executable(func_aes_ctr functional/func_aes_ctr.cpp)
    target_link_libraries(func_aes_ctr phantom_static)
endif (ENABLE_AES_CTR)

if (ENABLE_AES_GCM)
    add_executable(unit_aes_gcm unit/unit_aes_gcm.cpp) 
    target_link_libraries(unit_aes_gcm phantom_static)

    add_executable(func_aes_gcm functional/func_aes_gcm.cpp)
    target_link_libraries(func_aes_gcm phantom_static)
endif (ENABLE_AES_GCM)

if (ENABLE_FPE_AES_FF1)
    add_executable(unit_ff1 unit/unit_ff1.cpp) 
    target_link_libraries(unit_ff1 phantom_static)

    add_executable(func_ff1 functional/func_ff1.cpp) 
    target_link_libraries(func_ff1 phantom_static)    
endif (ENABLE_FPE_AES_FF1)

if (ENABLE_FPE_AES_FF3_1)
    add_executable(unit_ff3_1 unit/unit_ff3_1.cpp) 
    target_link_libraries(unit_ff3_1 phantom_static)

    add_executable(func_ff3_1 functional/func_ff3_1.cpp) 
    target_link_libraries(func_ff3_1 phantom_static)
endif (ENABLE_FPE_AES_FF3_1)

if (ENABLE_SHAMIRS_SECRET_SHARING)
    add_executable(unit_sss unit/unit_shamirs_secret_sharing.cpp) 
    target_link_libraries(unit_sss phantom_static)

    add_executable(func_shamirs_secret_sharing functional/func_shamirs_secret_sharing.cpp) 
    target_link_libraries(func_shamirs_secret_sharing phantom_static)
endif (ENABLE_SHAMIRS_SECRET_SHARING)

add_executable(unit_csprng unit/unit_csprng.cpp) 
target_link_libraries(unit_csprng phantom_static)

add_executable(unit_sha2 unit/unit_sha2.cpp) 
target_link_libraries(unit_sha2 phantom_static)

add_executable(unit_sha3 unit/unit_sha3.cpp) 
target_link_libraries(unit_sha3 phantom_static)

add_executable(unit_xof unit/unit_xof.cpp) 
target_link_libraries(unit_xof phantom_static)

add_executable(func_hash functional/func_hash.cpp) 
target_link_libraries(func_hash phantom_static)

add_executable(unit_bit_manipulation unit/unit_bit_manipulation.cpp) 
target_link_libraries(unit_bit_manipulation phantom_static)

add_executable(unit_mpbase unit/unit_mpbase.cpp)
target_link_libraries(unit_mpbase phantom_static)

add_executable(unit_mpz_additive unit/unit_mpz_additive.cpp) 
target_link_libraries(unit_mpz_additive phantom_static)

add_executable(unit_mpz_multiplicative unit/unit_mpz_multiplicative.cpp) 
target_link_libraries(unit_mpz_multiplicative phantom_static)

add_executable(unit_mpz_comparative unit/unit_mpz_comparative.cpp) 
target_link_libraries(unit_mpz_comparative phantom_static)

add_executable(unit_mpz_logical unit/unit_mpz_logical.cpp) 
target_link_libraries(unit_mpz_logical phantom_static)

add_executable(unit_mp_gf2n unit/unit_mp_gf2n.cpp) 
target_link_libraries(unit_mp_gf2n phantom_static)

add_executable(unit_number_additive unit/unit_number_additive.cpp) 
target_link_libraries(unit_number_additive phantom_static)

add_executable(unit_number_multiplicative unit/unit_number_multiplicative.cpp) 
target_link_libraries(unit_number_multiplicative phantom_static)

add_executable(unit_number_algorithms unit/unit_number_algorithms.cpp) 
target_link_libraries(unit_number_algorithms phantom_static)

add_executable(unit_reduction_barrett unit/unit_reduction_barrett.cpp) 
target_link_libraries(unit_reduction_barrett phantom_static)

add_executable(unit_reduction_montgomery unit/unit_reduction_montgomery.cpp) 
target_link_libraries(unit_reduction_montgomery phantom_static)

add_executable(unit_build_info unit/unit_build_info.cpp) 
target_link_libraries(unit_build_info phantom_static)

add_executable(tuning_mul tuning/tuning_mul.cpp) 
target_link_libraries(tuning_mul phantom_static)

enable_testing()

add_test(UNIT_BUILD_INFO ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_build_info)

add_test(UNIT_AES ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_aes)
if (ENABLE_AES_CTR)
    add_test(UNIT_AES_CTR ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_aes_ctr)
    add_test(FUNC_AES_CTR ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/func_aes_ctr)
endif (ENABLE_AES_CTR)
if (ENABLE_AES_GCM)
    add_test(UNIT_AES_GCM ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_aes_gcm)
    add_test(FUNC_AES_GCM ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/func_aes_gcm)
endif (ENABLE_AES_GCM)
if (ENABLE_FPE_AES_FF1)
    add_test(UNIT_FF1 ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_ff1)
    add_test(FUNC_FF1 ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/func_ff1)
endif (ENABLE_FPE_AES_FF1)
if (ENABLE_FPE_AES_FF3_1)
    add_test(UNIT_FF3_1 ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_ff3_1)
    add_test(FUNC_FF3_1 ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/func_ff3_1)
endif (ENABLE_FPE_AES_FF3_1)
if (ENABLE_SHAMIRS_SECRET_SHARING)
    add_test(UNIT_SSS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_sss)
    add_test(FUNC_SSS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/func_shamirs_secret_sharing)
endif (ENABLE_SHAMIRS_SECRET_SHARING)

add_test(UNIT_CSPRNG ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_csprng)

add_test(UNIT_SHA2 ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_sha2)
add_test(UNIT_SHA3 ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_sha3)
add_test(UNIT_XOF ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_xof)
add_test(FUNC_HASH ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/func_hash)

add_test(UNIT_BIT_MANIPULATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_bit_manipulation)
add_test(UNIT_MPBASE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_mpbase)
add_test(UNIT_MPZ_COMPARATIVE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_mpz_comparative)
add_test(UNIT_MPZ_LOGICAL ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_mpz_logical)
add_test(UNIT_MPZ_ADDITIVE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_mpz_additive)
add_test(UNIT_MPZ_MULTIPLICATIVE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_mpz_multiplicative)
add_test(UNIT_NUMBER_ADDITIVE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_number_additive)
add_test(UNIT_NUMBER_MULTIPLICATIVE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_number_multiplicative)
add_test(UNIT_NUMBER_ALGORITHMS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_number_algorithms)
add_test(UNIT_REDUCTION_BARRETT ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_reduction_barrett)

if (ENABLE_SIGNATURE_ECDSA)
    add_executable(gen_ecdsa_dual functional/gen_ecdsa_dual.cpp) 
    target_link_libraries(gen_ecdsa_dual phantom_static)

    add_executable(unit_eddsa unit/unit_eddsa.cpp)
    target_link_libraries(unit_eddsa phantom_static)
    
    add_test(GEN_ECDSA_DUAL ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/gen_ecdsa_dual)
    add_test(UNIT_EDDSA ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_eddsa)
endif (ENABLE_SIGNATURE_ECDSA)

if (ENABLE_KEY_EXCHANGE_ECDH)
    add_executable(unit_weierstrass_prime_affine unit/unit_weierstrass_prime_affine.cpp) 
    target_link_libraries(unit_weierstrass_prime_affine phantom_static)

    add_executable(unit_weierstrass_prime_projective unit/unit_weierstrass_prime_projective.cpp) 
    target_link_libraries(unit_weierstrass_prime_projective phantom_static)

    add_executable(unit_weierstrass_prime_jacobian unit/unit_weierstrass_prime_jacobian.cpp) 
    target_link_libraries(unit_weierstrass_prime_jacobian phantom_static)

    add_executable(unit_weierstrass_binary_affine unit/unit_weierstrass_binary_affine.cpp) 
    target_link_libraries(unit_weierstrass_binary_affine phantom_static)

    add_executable(unit_weierstrass_binary_projective unit/unit_weierstrass_binary_projective.cpp) 
    target_link_libraries(unit_weierstrass_binary_projective phantom_static)

    add_executable(unit_weierstrass_binary_jacobian unit/unit_weierstrass_binary_jacobian.cpp) 
    target_link_libraries(unit_weierstrass_binary_jacobian phantom_static)

    add_executable(unit_montgomery_prime_affine unit/unit_montgomery_prime_affine.cpp) 
    target_link_libraries(unit_montgomery_prime_affine phantom_static)

    add_executable(unit_montgomery_prime_projective unit/unit_montgomery_prime_projective.cpp) 
    target_link_libraries(unit_montgomery_prime_projective phantom_static)

    add_executable(unit_edwards_prime_affine unit/unit_edwards_prime_affine.cpp) 
    target_link_libraries(unit_edwards_prime_affine phantom_static)

    add_executable(unit_edwards_prime_projective unit/unit_edwards_prime_projective.cpp) 
    target_link_libraries(unit_edwards_prime_projective phantom_static)

    add_executable(unit_prime_ecc unit/unit_prime_ecc.cpp) 
    target_link_libraries(unit_prime_ecc phantom_static)

    add_executable(unit_binary_ecc unit/unit_binary_ecc.cpp) 
    target_link_libraries(unit_binary_ecc phantom_static)

    add_executable(unit_curve25519_ecc unit/unit_curve25519_ecc.cpp) 
    target_link_libraries(unit_curve25519_ecc phantom_static)

    add_executable(unit_ecdh unit/unit_ecdh.cpp)
    target_link_libraries(unit_ecdh phantom_static)
    
    add_executable(func_key_exchange_ecdh functional/func_key_exchange_ecdh.cpp) 
    target_link_libraries(func_key_exchange_ecdh phantom_static)
    
    add_test(UNIT_WEIERSTRASS_PRIME_AFFINE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_weierstrass_prime_affine)
    add_test(UNIT_WEIERSTRASS_BINARY_AFFINE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_weierstrass_binary_affine)
    add_test(UNIT_WEIERSTRASS_PRIME_PROJECTIVE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_weierstrass_prime_projective)
    add_test(UNIT_WEIERSTRASS_PRIME_JACOBIAN ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_weierstrass_prime_jacobian)
    add_test(UNIT_WEIERSTRASS_BINARY_PROJECTIVE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_weierstrass_binary_projective)
    add_test(UNIT_WEIERSTRASS_BINARY_JACOBIAN ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_weierstrass_binary_jacobian)
    add_test(UNIT_MONTGOMERY_PRIME_AFFINE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_montgomery_prime_affine)
    add_test(UNIT_MONTGOMERY_PRIME_PROJECTIVE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_montgomery_prime_projective)
    add_test(UNIT_EDWARDS_PRIME_AFFINE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_edwards_prime_affine)
    add_test(UNIT_EDWARDS_PRIME_PROJECTIVE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_edwards_prime_projective)
    add_test(UNIT_PRIME_ECC ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_prime_ecc)
    add_test(UNIT_BINARY_ECC ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_binary_ecc)
    add_test(UNIT_CURVE25519_ECC ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_curve25519_ecc)
    add_test(UNIT_ECDH ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_ecdh)
    add_test(FUNC_KEY_ECDH ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/func_key_exchange_ecdh)
endif (ENABLE_KEY_EXCHANGE_ECDH)

if (ENABLE_PKE_RSAES_OAEP)
    add_executable(unit_rsaes_oaep unit/unit_rsaes_oaep.cpp) 
    target_link_libraries(unit_rsaes_oaep phantom_static)

    add_executable(func_pke_rsaes_oaep functional/func_pke_rsaes_oaep.cpp) 
    target_link_libraries(func_pke_rsaes_oaep phantom_static)

    add_test(UNIT_RSAES_OAEP ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_rsaes_oaep)
    add_test(FUNC_PKE_RSAES_OAEP ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/func_pke_rsaes_oaep)
endif (ENABLE_PKE_RSAES_OAEP)

if (ENABLE_SIGNATURE_RSASSA_PSS)
    add_executable(unit_rsassa_pss unit/unit_rsassa_pss.cpp) 
    target_link_libraries(unit_rsassa_pss phantom_static)

    add_executable(func_sig_rsassa_pss functional/func_sig_rsassa_pss.cpp) 
    target_link_libraries(func_sig_rsassa_pss phantom_static)

    add_test(UNIT_RSASSA_PSS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unit_rsassa_pss)
    add_test(FUNC_SIG_RSASSA_PSS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/func_sig_rsassa_pss)
endif (ENABLE_SIGNATURE_RSASSA_PSS)

if (ENABLE_KEM_KYBER)
    add_executable(func_kem_kyber functional/func_kem_kyber.cpp) 
    target_link_libraries(func_kem_kyber phantom_static)

    add_test(FUNC_KEM_KYBER ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/func_kem_kyber)
endif (ENABLE_KEM_KYBER)

if (ENABLE_KEM_SABER)
    add_executable(func_kem_saber functional/func_kem_saber.cpp) 
    target_link_libraries(func_kem_saber phantom_static)

    add_test(FUNC_KEM_SABER ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/func_kem_saber)
endif (ENABLE_KEM_SABER)

if (ENABLE_PKE_KYBER)
    add_executable(func_pke_kyber functional/func_pke_kyber.cpp) 
    target_link_libraries(func_pke_kyber phantom_static)

    add_test(FUNC_PKE_KYBER ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/func_pke_kyber)
endif (ENABLE_PKE_KYBER)

if (ENABLE_PKE_SABER)
    add_executable(func_pke_saber functional/func_pke_saber.cpp) 
    target_link_libraries(func_pke_saber phantom_static)

    add_test(FUNC_PKE_SABER ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/func_pke_saber)
endif (ENABLE_PKE_SABER)

if (ENABLE_SIGNATURE_DILITHIUM)
    add_executable(func_sig_dilithium functional/func_sig_dilithium.cpp) 
    target_link_libraries(func_sig_dilithium phantom_static)

    add_test(FUNC_SIG_DILITHIUM ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/func_sig_dilithium)
endif (ENABLE_SIGNATURE_DILITHIUM)

if (ENABLE_SIGNATURE_FALCON)
    add_executable(func_sig_falcon functional/func_sig_falcon.cpp) 
    target_link_libraries(func_sig_falcon phantom_static)

    add_test(FUNC_SIG_FALCON ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/func_sig_falcon)
endif (ENABLE_SIGNATURE_FALCON)

if (ENABLE_SIGNATURE_ECDSA)
    add_executable(func_sig_ecdsa functional/func_sig_ecdsa.cpp) 
    target_link_libraries(func_sig_ecdsa phantom_static)

    add_test(FUNC_SIG_ECDSA ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/func_sig_ecdsa)
endif (ENABLE_SIGNATURE_ECDSA)

if (ENABLE_SIGNATURE_EDDSA)
    add_executable(func_sig_eddsa functional/func_sig_eddsa.cpp) 
    target_link_libraries(func_sig_eddsa phantom_static)

    add_test(FUNC_SIG_EDDSA ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/func_sig_eddsa)
endif (ENABLE_SIGNATURE_EDDSA)

if (ENABLE_IBE_DLP)
    add_executable(func_ibe_dlp functional/func_ibe_dlp.cpp) 
    target_link_libraries(func_ibe_dlp phantom_static)

    add_test(FUNC_IBE_DLP ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/func_ibe_dlp)
endif (ENABLE_IBE_DLP)
