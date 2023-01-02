# --------------------------- CMake project setup --------------------------- #

cmake_minimum_required(VERSION 3.1)

project(phantom VERSION 1.0.0 LANGUAGES CXX)

message(STATUS "We are on a ${CMAKE_SYSTEM_NAME} system")
message(STATUS "The host processor is ${CMAKE_HOST_SYSTEM_PROCESSOR}")


# -------------------------- Configure for C++11 ---------------------------- #

set(CMAKE_CXX_STANDARD 11)           # The C++11 standard is requested
set(CMAKE_CXX_STANDARD_REQUIRED ON)  # C++11 is a requirement
set(CMAKE_CXX_EXTENSIONS OFF)        # Compiler extensions are disabled, e.g. gnu++11


# ---------------------- Configure compiler toolchain ----------------------- #

# If a toolchain file is not defined, i,e, this is a native build and
# host/target are identical, then configure compilation flags
if (NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    # Detect the compiler
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
        # Using Clang
        # TODO - Remove and fix warnings
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-missing-braces")
    elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        # Using GCC
        # TODO - Remove and fix warnings
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -Werror")
    elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Intel")
        # Using Intel C++
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
    elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
        # Using Visual Studio C++
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -W4 -DNOMINMAX")
    endif ()
endif ()

# Disable the JSON library IO
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DJSON_NO_IO")


# ------------------------- Configure all options --------------------------- #

option(BUILD_STATIC_LIBS "Build the static library" ON)
option(BUILD_SHARED_LIBS "Build the shared library" ON)
option(BUILD_TESTS "Build test programs" OFF)
option(ENABLE_LOGGING "Enable log and trace" OFF)
option(ENABLE_IBE_DLP "Build IBE-DLP" OFF)
option(ENABLE_KEM_KYBER "Build KEM Kyber" OFF)
option(ENABLE_KEM_SABER "Build KEM SABER" OFF)
option(ENABLE_KEY_EXCHANGE_ECDH "Build Key exchange ECDH" OFF)
option(ENABLE_PKE_KYBER "Build Public Key Encryption Kyber" OFF)
option(ENABLE_PKE_SABER "Build Public Key Encryption SABER" OFF)
option(ENABLE_PKE_RSAES_OAEP "Build Public Key Encryption RSAES-OAEP" OFF)
option(ENABLE_SIGNATURE_DILITHIUM "Build Signature Dilithium" OFF)
option(ENABLE_SIGNATURE_ECDSA "Build Signature ECDSA" OFF)
option(ENABLE_SIGNATURE_EDDSA "Build Signature EDDSA" OFF)
option(ENABLE_SIGNATURE_FALCON "Build Signature Falcon" OFF)
option(ENABLE_SIGNATURE_RSASSA_PSS "Build Signature RSASSA-PSS" OFF)
option(ENABLE_HASH "Build hashes" OFF)
option(ENABLE_XOF "Build XOF's" OFF)
option(ENABLE_CSPRNG "Build CSPRNG" OFF)
option(ENABLE_AES_CTR "Build AES-CTR" OFF)
option(ENABLE_AES_GCM "Build AES-GCM" OFF)
option(ENABLE_AES_CCM "Build AES-CCM" OFF)
option(ENABLE_FPE_AES_FF1 "Build FPE AES-FF1" OFF)
option(ENABLE_FPE_AES_FF3_1 "Build FPE AES-FF3-1" OFF)
option(ENABLE_SHAMIRS_SECRET_SHARING "Build Shamir's Secret Sharing" OFF)
option(ENABLE_PKC "Build all Public Key Cryptography cryptosystems" OFF)
option(ENABLE_PKC_IBE "Build all PKC Identity-Based Encryption cryptosystems" OFF)
option(ENABLE_PKC_KEM "Build all PKC Key Exchange Mechanism cryptosystems" OFF)
option(ENABLE_PKC_KEX "Build all PKC Key Exchange cryptosystems" OFF)
option(ENABLE_PKC_PKE "Build all PKC Public Key Encryption cryptosystems" OFF)
option(ENABLE_PKC_SIG "Build all PKC Signature cryptosystems" OFF)
option(ENABLE_FPE "Build all Format Preserving Encryption cryptosystems" OFF)
option(ENABLE_KEY_SHARING "Build all Key Sharing cryptosystems" OFF)
option(ENABLE_ALL "Build all cryptosystems" ON)


# -------- Enable/disable cryptosystems and features as appropriate --------- #

if (ENABLE_LOGGING)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_ENABLE_LOGGING")
endif (ENABLE_LOGGING)

set(REQUIRE_PKC_LIBS OFF)
set(REQUIRE_MPZ OFF)

if (ENABLE_ALL OR ENABLE_PKC OR ENABLE_PKC_IBE)
    if (NOT ENABLE_IBE_DLP)
        set (ENABLE_IBE_DLP ON CACHE BOOL "" FORCE)
    endif (NOT ENABLE_IBE_DLP)

    set (ENABLE_PKC_IBE ON CACHE BOOL "" FORCE)
    
    if (ENABLE_IBE_DLP)
        add_definitions("-DENABLE_PKC_IBE")
    endif (ENABLE_IBE_DLP)
endif (ENABLE_ALL OR ENABLE_PKC OR ENABLE_PKC_IBE)

if (ENABLE_ALL OR ENABLE_PKC OR ENABLE_PKC_KEM)
    if (NOT ENABLE_KEM_KYBER)
        set (ENABLE_KEM_KYBER ON CACHE BOOL "" FORCE)
    endif (NOT ENABLE_KEM_KYBER)
    if (NOT ENABLE_KEM_SABER)
        set (ENABLE_KEM_SABER ON CACHE BOOL "" FORCE)
    endif (NOT ENABLE_KEM_SABER)

    set (ENABLE_PKC_KEM ON CACHE BOOL "" FORCE)

    if (ENABLE_KEM_KYBER OR ENABLE_KEM_SABER)
        add_definitions("-DENABLE_PKC_KEM")
    endif (ENABLE_KEM_KYBER OR ENABLE_KEM_SABER)
endif (ENABLE_ALL OR ENABLE_PKC OR ENABLE_PKC_KEM)

if (ENABLE_ALL OR ENABLE_PKC OR ENABLE_PKC_KEX)
    if (NOT ENABLE_KEY_EXCHANGE_ECDH)
        set (ENABLE_KEY_EXCHANGE_ECDH ON CACHE BOOL "" FORCE)
    endif (NOT ENABLE_KEY_EXCHANGE_ECDH)

    set (ENABLE_PKC_KEX ON CACHE BOOL "" FORCE)

    if (ENABLE_KEY_EXCHANGE_ECDH)
        add_definitions("-DENABLE_PKC_KEX")
    endif (ENABLE_KEY_EXCHANGE_ECDH)
endif (ENABLE_ALL OR ENABLE_PKC OR ENABLE_PKC_KEX)

if (ENABLE_ALL OR ENABLE_PKC OR ENABLE_PKC_PKE)
    if (NOT ENABLE_PKE_KYBER)
        set (ENABLE_PKE_KYBER ON CACHE BOOL "" FORCE)
    endif (NOT ENABLE_PKE_KYBER)
    if (NOT ENABLE_PKE_SABER)
        set (ENABLE_PKE_SABER ON CACHE BOOL "" FORCE)
    endif (NOT ENABLE_PKE_SABER)
    if (NOT ENABLE_PKE_RSAES_OAEP)
        set (ENABLE_PKE_RSAES_OAEP ON CACHE BOOL "" FORCE)
    endif (NOT ENABLE_PKE_RSAES_OAEP)

    set (ENABLE_PKC_PKE ON CACHE BOOL "" FORCE)

    if (ENABLE_PKE_KYBER OR ENABLE_PKE_KYBER OR ENABLE_PKE_SABER)
        add_definitions("-DENABLE_PKC_PKE")
    endif (ENABLE_PKE_KYBER OR ENABLE_PKE_KYBER OR ENABLE_PKE_SABER)
endif (ENABLE_ALL OR ENABLE_PKC OR ENABLE_PKC_PKE)

if (ENABLE_ALL OR ENABLE_PKC OR ENABLE_PKC_SIG)
    if (NOT ENABLE_SIGNATURE_DILITHIUM)
        set (ENABLE_SIGNATURE_DILITHIUM ON CACHE BOOL "" FORCE)
    endif (NOT ENABLE_SIGNATURE_DILITHIUM)
    if (NOT ENABLE_SIGNATURE_ECDSA)
        set (ENABLE_SIGNATURE_ECDSA ON CACHE BOOL "" FORCE)
    endif (NOT ENABLE_SIGNATURE_ECDSA)
    if (NOT ENABLE_SIGNATURE_EDDSA)
        set (ENABLE_SIGNATURE_EDDSA ON CACHE BOOL "" FORCE)
    endif (NOT ENABLE_SIGNATURE_EDDSA)
    if (NOT ENABLE_SIGNATURE_FALCON)
        set (ENABLE_SIGNATURE_FALCON ON CACHE BOOL "" FORCE)
    endif (NOT ENABLE_SIGNATURE_FALCON)
    if (NOT ENABLE_SIGNATURE_RSASSA_PSS)
        set (ENABLE_SIGNATURE_RSASSA_PSS ON CACHE BOOL "" FORCE)
    endif (NOT ENABLE_SIGNATURE_RSASSA_PSS)

    set (ENABLE_PKC_SIG ON CACHE BOOL "" FORCE)

    if (ENABLE_SIGNATURE_DILITHIUM OR ENABLE_SIGNATURE_ECDSA OR ENABLE_SIGNATURE_EDDSA OR ENABLE_SIGNATURE_FALCON OR ENABLE_SIGNATURE_RSASSA_PSS)
        add_definitions("-DENABLE_PKC_SIG")
    endif (ENABLE_SIGNATURE_DILITHIUM OR ENABLE_SIGNATURE_ECDSA OR ENABLE_SIGNATURE_EDDSA OR ENABLE_SIGNATURE_FALCON OR ENABLE_SIGNATURE_RSASSA_PSS)
endif (ENABLE_ALL OR ENABLE_PKC OR ENABLE_PKC_SIG)

if (ENABLE_ALL OR ENABLE_FPE)
    if (NOT ENABLE_FPE_AES_FF1)
        set (ENABLE_FPE_AES_FF1 ON CACHE BOOL "" FORCE)
    endif (NOT ENABLE_FPE_AES_FF1)
    if (NOT ENABLE_FPE_AES_FF3_1)
        set (ENABLE_FPE_AES_FF3_1 ON CACHE BOOL "" FORCE)
    endif (NOT ENABLE_FPE_AES_FF3_1)
    set(REQUIRE_MPZ ON)
endif (ENABLE_ALL OR ENABLE_FPE)

if (ENABLE_ALL OR ENABLE_KEY_SHARING)
    if (NOT ENABLE_SHAMIRS_SECRET_SHARING)
        set (ENABLE_SHAMIRS_SECRET_SHARING ON CACHE BOOL "" FORCE)
    endif (NOT ENABLE_SHAMIRS_SECRET_SHARING)
endif (ENABLE_ALL OR ENABLE_KEY_SHARING)

if (ENABLE_ALL)
    if (NOT ENABLE_CSPRNG)
        set (ENABLE_CSPRNG ON CACHE BOOL "" FORCE)
    endif (NOT ENABLE_CSPRNG)
    if (NOT ENABLE_AES_CTR)
        set (ENABLE_AES_CTR ON CACHE BOOL "" FORCE)
    endif (NOT ENABLE_AES_CTR)
    if (NOT ENABLE_AES_GCM)
        set (ENABLE_AES_GCM ON CACHE BOOL "" FORCE)
    endif (NOT ENABLE_AES_GCM)
    if (NOT ENABLE_AES_CCM)
        set (ENABLE_AES_CCM ON CACHE BOOL "" FORCE)
    endif (NOT ENABLE_AES_CCM)

    if (NOT ENABLE_HASH)
        set (ENABLE_HASH ON CACHE BOOL "" FORCE)
    endif (NOT ENABLE_HASH)
    if (NOT ENABLE_XOF)
        set (ENABLE_XOF ON CACHE BOOL "" FORCE)
    endif (NOT ENABLE_XOF)
endif (ENABLE_ALL)

# If AES-GCM is enabled then AES-CTR must also be enabled
if (ENABLE_AES_GCM)
    set (ENABLE_AES_CTR ON CACHE BOOL "" FORCE)
endif (ENABLE_AES_GCM)

if (ENABLE_IBE_DLP)
    add_definitions("-DENABLE_IBE_DLP")
endif (ENABLE_IBE_DLP)
if (ENABLE_KEM_KYBER)
    add_definitions("-DENABLE_KEM_KYBER")
endif (ENABLE_KEM_KYBER)
if (ENABLE_KEM_SABER)
    add_definitions("-DENABLE_KEM_SABER")
endif (ENABLE_KEM_SABER)
if (ENABLE_KEY_EXCHANGE_ECDH)
    add_definitions("-DENABLE_KEY_EXCHANGE_ECDH")
endif (ENABLE_KEY_EXCHANGE_ECDH)
if (ENABLE_PKE_KYBER)
    add_definitions("-DENABLE_PKE_KYBER")
endif (ENABLE_PKE_KYBER)
if (ENABLE_PKE_SABER)
    add_definitions("-DENABLE_PKE_SABER")
endif (ENABLE_PKE_SABER)
if (ENABLE_PKE_RSAES_OAEP)
    add_definitions("-DENABLE_PKE_RSAES_OAEP")
endif (ENABLE_PKE_RSAES_OAEP)
if (ENABLE_SIGNATURE_DILITHIUM)
    add_definitions("-DENABLE_SIGNATURE_DILITHIUM")
endif (ENABLE_SIGNATURE_DILITHIUM)
if (ENABLE_SIGNATURE_ECDSA)
    add_definitions("-DENABLE_SIGNATURE_ECDSA")
endif (ENABLE_SIGNATURE_ECDSA)
if (ENABLE_SIGNATURE_EDDSA)
    add_definitions("-DENABLE_SIGNATURE_EDDSA")
endif (ENABLE_SIGNATURE_EDDSA)
if (ENABLE_SIGNATURE_FALCON)
    add_definitions("-DENABLE_SIGNATURE_FALCON")
endif (ENABLE_SIGNATURE_FALCON)
if (ENABLE_SIGNATURE_RSASSA_PSS)
    add_definitions("-DENABLE_SIGNATURE_RSASSA_PSS")
endif (ENABLE_SIGNATURE_RSASSA_PSS)

if (ENABLE_CSPRNG)
    add_definitions("-DENABLE_AES_ECB")
endif (ENABLE_CSPRNG)
if (ENABLE_AES_CTR)
    add_definitions("-DENABLE_AES_CTR")
endif (ENABLE_AES_CTR)
if (ENABLE_AES_GCM)
    add_definitions("-DENABLE_AES_GCM")
endif (ENABLE_AES_GCM)
if (ENABLE_AES_CCM)
    add_definitions("-DENABLE_AES_CCM")
endif (ENABLE_AES_CCM)

if (ENABLE_FPE_AES_FF1)
    add_definitions("-DENABLE_FPE_AES_FF1")
endif (ENABLE_FPE_AES_FF1)
if (ENABLE_FPE_AES_FF3_1)
    add_definitions("-DENABLE_FPE_AES_FF3_1")
endif (ENABLE_FPE_AES_FF3_1)

if (ENABLE_SHAMIRS_SECRET_SHARING)
    add_definitions("-DENABLE_SHAMIRS_SECRET_SHARING")
endif (ENABLE_SHAMIRS_SECRET_SHARING)

if (ENABLE_IBE_DLP OR
    ENABLE_KEM_KYBER OR
    ENABLE_KEM_SABER OR
    ENABLE_KEY_EXCHANGE_ECDH OR
    ENABLE_PKE_KYBER OR
    ENABLE_PKE_SABER OR
    ENABLE_PKE_RSAES_OAEP OR
    ENABLE_SIGNATURE_DILITHIUM OR
    ENABLE_SIGNATURE_ECDSA OR
    ENABLE_SIGNATURE_EDDSA OR
    ENABLE_SIGNATURE_FALCON OR
    ENABLE_SIGNATURE_RSASSA_PSS)
    set(REQUIRE_PKC_LIBS ON)
    set(REQUIRE_MPZ ON)
    set (ENABLE_HASH ON CACHE BOOL "" FORCE)
    set (ENABLE_XOF ON CACHE BOOL "" FORCE)
    set (ENABLE_PKC ON CACHE BOOL "" FORCE)
    add_definitions("-DENABLE_PKC")
endif ()

if (ENABLE_HASH)
    add_definitions("-DENABLE_HASH")
endif (ENABLE_HASH)

if (ENABLE_XOF)
    add_definitions("-DENABLE_XOF")
endif (ENABLE_XOF)


# -------- Guard against in-source builds and bad build-type strings -------- #

include(cmake/safeguards.cmake)


# --------- Place binaries and libraries according to GNU standards --------- #

include(GNUInstallDirs)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR})


# ------------------------------ Get git hash ------------------------------- #
include(cmake/git_revision.cmake)


# -------------------------- Configure versioning --------------------------- #

file(READ "version" ver)

string(REGEX MATCH "VERSION_MAJOR ([0-9]*)" _ ${ver})
set(VERSION_MAJOR ${CMAKE_MATCH_1})

string(REGEX MATCH "VERSION_MINOR ([0-9]*)" _ ${ver})
set(VERSION_MINOR ${CMAKE_MATCH_1})

string(REGEX MATCH "VERSION_PATCH ([0-9]*)" _ ${ver})
set(VERSION_PATCH ${CMAKE_MATCH_1})

string(SUBSTRING "${GIT_REVISION}" 0 8 GIT_SHORT_COMMIT)
set(PHANTOM_BUILD_VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}-${GIT_SHORT_COMMIT}")

message(STATUS "Version is ${PHANTOM_BUILD_VERSION}")

configure_file(
    ${PROJECT_SOURCE_DIR}/cmake/config.hpp.in
    ${PROJECT_BINARY_DIR}/config.hpp
)


# -------------------------------- libuuid ---------------------------------- #

include(cmake/libuuid.cmake)
if (LIBUUID_LIBRARIES)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DENABLE_LIBUUID")
    link_libraries("-luuid")
endif (LIBUUID_LIBRARIES)


# -------------------------- Set the include paths -------------------------- #

include_directories(
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/src/utils/third_party/json/single_include/
    ${PROJECT_SOURCE_DIR}
    ${PROJECT_BINARY_DIR}
)


# ------------------------------ Source files ------------------------------- #

set(libsrc
    ${PROJECT_SOURCE_DIR}/include/phantom.hpp /
    ${PROJECT_SOURCE_DIR}/src/phantom.cpp /
    ${PROJECT_SOURCE_DIR}/src/utils/third_party/cpp-base64/base64.cpp /
    ${PROJECT_SOURCE_DIR}/src/utils/stopwatch.cpp /
    ${PROJECT_SOURCE_DIR}/src/utils/uuid.cpp
)

set(libsrc ${libsrc} ${PROJECT_SOURCE_DIR}/bindings/c/build_info.cpp)
if (ENABLE_FPE_AES_FF1 OR ENABLE_FPE_AES_FF3_1)
    set(libsrc ${libsrc} ${PROJECT_SOURCE_DIR}/bindings/c/fpe_wrapper.cpp)
endif (ENABLE_FPE_AES_FF1 OR ENABLE_FPE_AES_FF3_1)
if (ENABLE_SHAMIRS_SECRET_SHARING)
    set(libsrc ${libsrc} ${PROJECT_SOURCE_DIR}/bindings/c/shamirs_secret_sharing_wrapper.cpp)
endif (ENABLE_SHAMIRS_SECRET_SHARING)
if (ENABLE_PKC_IBE)
    set(libsrc ${libsrc} ${PROJECT_SOURCE_DIR}/bindings/c/ibe_wrapper.cpp)
endif (ENABLE_PKC_IBE)


set(libsrc_static ${libsrc})
set(libsrc_shared ${libsrc})

add_subdirectory(src/crypto)
add_subdirectory(src/logging)
add_subdirectory(src/packing)

if (REQUIRE_PKC_LIBS OR REQUIRE_MPZ)
    add_subdirectory(src/core)

    set(libsrc_static ${libsrc_static} $<TARGET_OBJECTS:core_obj>)
    set(libsrc_shared ${libsrc_shared} $<TARGET_OBJECTS:core_shared_obj>)
endif (REQUIRE_PKC_LIBS OR REQUIRE_MPZ)

if (ENABLE_PKC)
    add_subdirectory(src/ecc)
    add_subdirectory(src/fft)
    add_subdirectory(src/ntru)
    add_subdirectory(src/rsa)
    add_subdirectory(src/sampling)
    add_subdirectory(src/schemes)

    set(libsrc_static ${libsrc_static}
        $<TARGET_OBJECTS:ecc_obj>
        $<TARGET_OBJECTS:rsa_obj>
        $<TARGET_OBJECTS:ntru_obj>
        $<TARGET_OBJECTS:sampling_obj>
        $<TARGET_OBJECTS:fft_obj>
        $<TARGET_OBJECTS:schemes_obj>)
    set(libsrc_shared ${libsrc_shared}
        $<TARGET_OBJECTS:ecc_shared_obj>
        $<TARGET_OBJECTS:rsa_shared_obj>
        $<TARGET_OBJECTS:ntru_shared_obj>
        $<TARGET_OBJECTS:sampling_shared_obj>
        $<TARGET_OBJECTS:fft_shared_obj>
        $<TARGET_OBJECTS:schemes_shared_obj>)
endif (ENABLE_PKC)

if (REQUIRE_MPZ)
    set(libsrc_static ${libsrc_static} $<TARGET_OBJECTS:core_obj>)
    set(libsrc_shared ${libsrc_shared} $<TARGET_OBJECTS:core_shared_obj>)
endif (REQUIRE_MPZ)


# ------------------------------ Header files ------------------------------- #

set(PHANTOM_PUBLIC_HEADERS
    ${PROJECT_SOURCE_DIR}/include/phantom_machine.hpp
    ${PROJECT_SOURCE_DIR}/include/phantom_memory.hpp
    ${PROJECT_SOURCE_DIR}/include/phantom_types.hpp
    ${PROJECT_SOURCE_DIR}/include/phantom.hpp
)


# ----------------------------- Static library ------------------------------ #

if (BUILD_STATIC_LIBS)
    set(libsrc_static ${libsrc_static}
        $<TARGET_OBJECTS:logging_obj>
        $<TARGET_OBJECTS:crypto_obj>
        $<TARGET_OBJECTS:packing_obj>)
    add_library(phantom_static STATIC ${libsrc_static})
    set_target_properties(phantom_static PROPERTIES
        OUTPUT_NAME phantom_static
        VERSION ${PROJECT_VERSION}
        PUBLIC_HEADER "${PHANTOM_PUBLIC_HEADERS}")
endif (BUILD_STATIC_LIBS)


# ----------------------------- Shared library ------------------------------ #

if (BUILD_SHARED_LIBS)
    set(libsrc_shared ${libsrc_shared}
        $<TARGET_OBJECTS:logging_shared_obj>
        $<TARGET_OBJECTS:crypto_shared_obj>
        $<TARGET_OBJECTS:packing_shared_obj>)
    add_library(phantom_shared SHARED ${libsrc_shared})
    set_property(TARGET phantom_shared PROPERTY POSITION_INDEPENDENT_CODE 1)
    set_target_properties(phantom_shared PROPERTIES
        OUTPUT_NAME phantom
        VERSION ${PROJECT_VERSION}
        SOVERSION 1
        PUBLIC_HEADER "${PHANTOM_PUBLIC_HEADERS}")
endif (BUILD_SHARED_LIBS)


# ------------------------------ Installation ------------------------------- #

configure_file(phantom.pc.in phantom.pc @ONLY)

target_include_directories(phantom_static PRIVATE .)
target_include_directories(phantom_shared PRIVATE .)

if (BUILD_STATIC_LIBS)
    install(TARGETS phantom_static
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif (BUILD_STATIC_LIBS)

if (BUILD_SHARED_LIBS)
    if (WIN32)
        install(TARGETS phantom_shared
            RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
            PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    else ()
        install(TARGETS phantom_shared
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    endif (WIN32)
endif (BUILD_SHARED_LIBS)

install(FILES ${CMAKE_BINARY_DIR}/phantom.pc
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)

if (BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif (BUILD_TESTS)


# --------------------------------- cpplint --------------------------------- #

include(cmake/cpplint.cmake)
if (CPPLINT)
    cpplint_add_subdirectory(src)
    cpplint_add_subdirectory(include)
    cpplint_add_subdirectory(bindings)
endif (CPPLINT)


# ------------------------- Reference documentation ------------------------- #

find_package(Doxygen 1.8.0)
message(STATUS "We can build reference documentation          ${DOXYGEN_FOUND}")
if (DOXYGEN_FOUND)
    # Search for plantUML for creating UML diagrams from doxygen
    find_program(PLANT_UML_PATH plantuml.jar PATH_SUFFIXES PlantUML plantuml Plantuml 
        PATHS /usr/share /usr/local/share/ /usr/local/bin c/Program\ Files* )
    if (NOT PLANT_UML_PATH)
        message(STATUS "PlantUML for custom UML in documentation      NO")
    else ()
        message(STATUS "PlantUML for custom UML in documentation      YES")
    endif ()

    # Search for DOT for autogenerated UML diagrams from doxygen
    find_program(DOT_PATH dot PATH_SUFFIXES graphviz/bin)
    if (NOT DOT_PATH)
        message(STATUS "Graphviz/Dot for graphs in documentation      NO")
    else()
        message(STATUS "Graphviz/Dot for graphs in documentation      YES")
    endif ()

    file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/docs/doxygen/")

    # Configure doxygen configuration file
    set(DOXYFILE_IN ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in)
    set(DOXYFILE ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
    configure_file(${DOXYFILE_IN} ${DOXYFILE} @ONLY)

    # doc builds only target - this must be built explicitly
    add_custom_target(doxygen
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYFILE}
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        COMMENT "Generating doxygen html and latex output"
        VERBATIM)
    add_custom_target(doc
        DEPENDS doxygen
        COMMAND make
        COMMAND cp "${CMAKE_CURRENT_BINARY_DIR}/docs/doxygen/latex/refman.pdf"
                   "${CMAKE_CURRENT_BINARY_DIR}/docs/phantom_reference.pdf"
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/docs/doxygen/latex
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM)

    set_target_properties(doxygen PROPERTIES ADDITIONAL_CLEAN_FILES
        "${CMAKE_CURRENT_BINARY_DIR}/docs/doxygen")
    set_target_properties(doc PROPERTIES ADDITIONAL_CLEAN_FILES
        "${CMAKE_CURRENT_BINARY_DIR}/docs/phantom_reference.pdf")
    
endif (DOXYGEN_FOUND)
