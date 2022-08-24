project(phantom_rsa LANGUAGES CXX)

include_directories(
    ${PROJECT_SOURCE_DIR}/../../include
    ${PROJECT_SOURCE_DIR}/
    ${PROJECT_SOURCE_DIR}/../../bindings/c
    ${PROJECT_BINARY_DIR}../../
)

# list of source files
set(libsrc
    ${PROJECT_SOURCE_DIR}/ctx_rsa.hpp /
    ${PROJECT_SOURCE_DIR}/rsa_cryptosystem.hpp /
    ${PROJECT_SOURCE_DIR}/rsa_cryptosystem_oaep.hpp /
    ${PROJECT_SOURCE_DIR}/rsa_cryptosystem_rsassa_pss.hpp
)

# static library
add_library(rsa_obj OBJECT ${libsrc})

# shared library
add_library(rsa_shared_obj OBJECT ${libsrc})
set_property(TARGET rsa_shared_obj PROPERTY POSITION_INDEPENDENT_CODE 1)
