project(phantom_schemes LANGUAGES CXX)

include_directories(
    ${PROJECT_SOURCE_DIR}/../../include
    ${PROJECT_SOURCE_DIR}/
    ${PROJECT_SOURCE_DIR}/../../bindings/c
    ${PROJECT_BINARY_DIR}../../
)

# list of source files
set(libsrc_ibe_dlp
    ${PROJECT_SOURCE_DIR}/ibe/ibe.hpp /
    ${PROJECT_SOURCE_DIR}/ibe/dlp/ibe_dlp.hpp /
    ${PROJECT_SOURCE_DIR}/ibe/dlp/ibe_dlp.cpp
)

set(libsrc_kem_kyber
    ${PROJECT_SOURCE_DIR}/kem/kyber/ctx_kyber.hpp /
    ${PROJECT_SOURCE_DIR}/kem/kyber/kyber_ntt.cpp /
    ${PROJECT_SOURCE_DIR}/kem/kyber/kyber_ntt.hpp /
    ${PROJECT_SOURCE_DIR}/kem/kyber/kyber_kem.cpp /
    ${PROJECT_SOURCE_DIR}/kem/kyber/kyber_kem.hpp /
    ${PROJECT_SOURCE_DIR}/kem/kyber/kyber_indcpa.cpp /
    ${PROJECT_SOURCE_DIR}/kem/kyber/kyber_indcpa.hpp
)

set(libsrc_kem_saber
    ${PROJECT_SOURCE_DIR}/kem/saber/ctx_saber.hpp /
    ${PROJECT_SOURCE_DIR}/kem/saber/saber_kem.cpp /
    ${PROJECT_SOURCE_DIR}/kem/saber/saber_kem.hpp /
    ${PROJECT_SOURCE_DIR}/kem/saber/saber_indcpa.cpp /
    ${PROJECT_SOURCE_DIR}/kem/saber/saber_indcpa.hpp
)

set(libsrc_key_exchange_ecdh
    ${PROJECT_SOURCE_DIR}/key_exchange/ecdh/ctx_ecdh.hpp /
    ${PROJECT_SOURCE_DIR}/key_exchange/ecdh/ecdh_key_exchange.cpp /
    ${PROJECT_SOURCE_DIR}/key_exchange/ecdh/ecdh_key_exchange.hpp
)

set(libsrc_pke_kyber
    ${PROJECT_SOURCE_DIR}/pke/kyber/ctx_kyber_pke.hpp /
    ${PROJECT_SOURCE_DIR}/pke/kyber/kyber_pke.cpp /
    ${PROJECT_SOURCE_DIR}/pke/kyber/kyber_pke.hpp /
)

set(libsrc_pke_saber
    ${PROJECT_SOURCE_DIR}/pke/saber/ctx_saber_pke.hpp /
    ${PROJECT_SOURCE_DIR}/pke/saber/saber_pke.cpp /
    ${PROJECT_SOURCE_DIR}/pke/saber/saber_pke.hpp
)

set(libsrc_pke_rsaes_oaep
    ${PROJECT_SOURCE_DIR}/pke/rsaes_oaep/rsaes_oaep_pke.cpp /
    ${PROJECT_SOURCE_DIR}/pke/rsaes_oaep/rsaes_oaep_pke.hpp
)

set(libsrc_signatue_dilithium
    ${PROJECT_SOURCE_DIR}/signature/dilithium/ctx_dilithium.hpp /
    ${PROJECT_SOURCE_DIR}/signature/dilithium/dilithium.cpp /
    ${PROJECT_SOURCE_DIR}/signature/dilithium/dilithium.hpp /
    ${PROJECT_SOURCE_DIR}/signature/dilithium/dilithium_signature.cpp /
    ${PROJECT_SOURCE_DIR}/signature/dilithium/dilithium_signature.hpp
)

set(libsrc_signatue_falcon
    ${PROJECT_SOURCE_DIR}/signature/falcon/ctx_falcon.hpp /
    ${PROJECT_SOURCE_DIR}/signature/falcon/falcon_signature.cpp /
    ${PROJECT_SOURCE_DIR}/signature/falcon/falcon_signature.hpp
)

set(libsrc_signatue_ecdsa
    ${PROJECT_SOURCE_DIR}/signature/ecdsa/ctx_ecdsa.hpp /
    ${PROJECT_SOURCE_DIR}/signature/ecdsa/ecdsa_signature.cpp /
    ${PROJECT_SOURCE_DIR}/signature/ecdsa/ecdsa_signature.hpp
)

set(libsrc_signatue_eddsa
    ${PROJECT_SOURCE_DIR}/signature/eddsa/ctx_eddsa.hpp /
    ${PROJECT_SOURCE_DIR}/signature/eddsa/eddsa_signature.cpp /
    ${PROJECT_SOURCE_DIR}/signature/eddsa/eddsa_signature.hpp
)

set(libsrc_signatue_rsassa_pss
    ${PROJECT_SOURCE_DIR}/signature/rsassa_pss/rsassa_pss_signature.cpp /
    ${PROJECT_SOURCE_DIR}/signature/rsassa_pss/rsassa_pss_signature.hpp
)

set(libsrc
    ${PROJECT_SOURCE_DIR}/scheme.hpp /
    ${PROJECT_SOURCE_DIR}/kem/kem.hpp /
    ${PROJECT_SOURCE_DIR}/key_exchange/key_exchange.hpp /
    ${PROJECT_SOURCE_DIR}/pke/pke.hpp /
    ${PROJECT_SOURCE_DIR}/signature/signature.hpp
)

if (ENABLE_IBE_DLP)
    set(libsrc ${libsrc} ${libsrc_ibe_dlp})
endif (ENABLE_IBE_DLP)
if (ENABLE_KEM_KYBER)
    set(libsrc ${libsrc} ${libsrc_kem_kyber})
endif (ENABLE_KEM_KYBER)
if (ENABLE_KEM_SABER)
    set(libsrc ${libsrc} ${libsrc_kem_saber})
endif (ENABLE_KEM_SABER)
if (ENABLE_KEY_EXCHANGE_ECDH)
    set(libsrc ${libsrc} ${libsrc_key_exchange_ecdh})
endif (ENABLE_KEY_EXCHANGE_ECDH)
if (ENABLE_PKE_KYBER)
    set(libsrc ${libsrc} ${libsrc_pke_kyber})
endif (ENABLE_PKE_KYBER)
if (ENABLE_PKE_SABER)
    set(libsrc ${libsrc} ${libsrc_pke_saber})
endif (ENABLE_PKE_SABER)
if (ENABLE_PKE_RSAES_OAEP)
    set(libsrc ${libsrc} ${libsrc_pke_rsaes_oaep})
endif (ENABLE_PKE_RSAES_OAEP)
if (ENABLE_SIGNATURE_DILITHIUM)
    set(libsrc ${libsrc} ${libsrc_signatue_dilithium})
endif (ENABLE_SIGNATURE_DILITHIUM)
if (ENABLE_SIGNATURE_ECDSA)
    set(libsrc ${libsrc} ${libsrc_signatue_ecdsa})
endif (ENABLE_SIGNATURE_ECDSA)
if (ENABLE_SIGNATURE_EDDSA)
    set(libsrc ${libsrc} ${libsrc_signatue_eddsa})
endif (ENABLE_SIGNATURE_EDDSA)
if (ENABLE_SIGNATURE_FALCON)
    set(libsrc ${libsrc} ${libsrc_signatue_falcon})
endif (ENABLE_SIGNATURE_FALCON)
if (ENABLE_SIGNATURE_RSASSA_PSS)
    set(libsrc ${libsrc} ${libsrc_signatue_rsassa_pss})
endif (ENABLE_SIGNATURE_RSASSA_PSS)

# static library
add_library(schemes_obj OBJECT ${libsrc})


# shared library
add_library(schemes_shared_obj OBJECT ${libsrc})
set_property(TARGET schemes_shared_obj PROPERTY POSITION_INDEPENDENT_CODE 1)
