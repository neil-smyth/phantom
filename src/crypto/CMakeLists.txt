project(phantom_crypto LANGUAGES CXX)

include_directories(
    ${PROJECT_SOURCE_DIR}/../../include
    ${PROJECT_SOURCE_DIR}/
    ${PROJECT_SOURCE_DIR}/../../bindings/c
    ${PROJECT_BINARY_DIR}../../
)

# list of source files
set(libsrc
    ${PROJECT_SOURCE_DIR}/aes_ni.cpp /
    ${PROJECT_SOURCE_DIR}/aes_ni.hpp /
    ${PROJECT_SOURCE_DIR}/aes_sw.cpp /
    ${PROJECT_SOURCE_DIR}/aes_sw.hpp /
    ${PROJECT_SOURCE_DIR}/aes.cpp /
    ${PROJECT_SOURCE_DIR}/aes.hpp /
    ${PROJECT_SOURCE_DIR}/aes_ccm.cpp /
    ${PROJECT_SOURCE_DIR}/aes_ccm.hpp /
    ${PROJECT_SOURCE_DIR}/aes_ctr_drbg.cpp /
    ${PROJECT_SOURCE_DIR}/aes_ctr_drbg.hpp /
    ${PROJECT_SOURCE_DIR}/csprng.cpp /
    ${PROJECT_SOURCE_DIR}/csprng.hpp /
    ${PROJECT_SOURCE_DIR}/fpe.cpp /
    ${PROJECT_SOURCE_DIR}/hash.hpp /
    ${PROJECT_SOURCE_DIR}/hash_sha2.cpp /
    ${PROJECT_SOURCE_DIR}/hash_sha2.hpp /
    ${PROJECT_SOURCE_DIR}/hash_sha3.cpp /
    ${PROJECT_SOURCE_DIR}/hash_sha3.hpp /
    ${PROJECT_SOURCE_DIR}/keccak.cpp /
    ${PROJECT_SOURCE_DIR}/keccak.hpp /
    ${PROJECT_SOURCE_DIR}/xof.hpp /
    ${PROJECT_SOURCE_DIR}/xof_sha3.cpp /
    ${PROJECT_SOURCE_DIR}/xof_sha3.hpp
)

if (ENABLE_AES_CTR)
    set(libsrc ${libsrc} ${PROJECT_SOURCE_DIR}/aes_ctr.cpp)
    set(libsrc ${libsrc} ${PROJECT_SOURCE_DIR}/aes_ctr.hpp)
endif (ENABLE_AES_CTR)

if (ENABLE_AES_GCM)
    set(libsrc ${libsrc} ${PROJECT_SOURCE_DIR}/aes_gcm.cpp)
    set(libsrc ${libsrc} ${PROJECT_SOURCE_DIR}/aes_gcm.hpp)
endif (ENABLE_AES_GCM)

if (ENABLE_FPE_AES_FF1)
  set(libsrc ${libsrc} ${PROJECT_SOURCE_DIR}/aes_fpe_ff1.hpp)
endif (ENABLE_FPE_AES_FF1)
if (ENABLE_FPE_AES_FF3_1)
  set(libsrc ${libsrc} ${PROJECT_SOURCE_DIR}/aes_fpe_ff3_1.hpp)
endif (ENABLE_FPE_AES_FF3_1)
if (ENABLE_SHAMIRS_SECRET_SHARING)
  set(libsrc ${libsrc} ${PROJECT_SOURCE_DIR}/shamirs_secret_sharing.cpp)
  set(libsrc ${libsrc} ${PROJECT_SOURCE_DIR}/shamirs_secret_sharing.hpp)
endif (ENABLE_SHAMIRS_SECRET_SHARING)

# static library
add_library(crypto_obj OBJECT ${libsrc})

# shared library
add_library(crypto_shared_obj OBJECT ${libsrc})
set_property(TARGET crypto_shared_obj PROPERTY POSITION_INDEPENDENT_CODE 1)
