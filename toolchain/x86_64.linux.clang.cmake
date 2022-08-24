# Target operating system
SET (CMAKE_SYSTEM_NAME Linux)

# Compiler selection
SET (CMAKE_C_COMPILER   /usr/lib/llvm-6.0/bin/clang)
SET (CMAKE_CXX_COMPILER /usr/lib/llvm-6.0/bin/clang++)

SET (CMAKE_FIND_ROOT_PATH ${TOOLCHAIN_ROOT})
SET (CMAKE_SYSROOT ${TOOLCHAIN_ROOT})

SET (CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
SET (CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET (CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
SET (CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Configure options for the build type
SET (CMAKE_CXX_FLAGS_INIT                "-Wall -m64 -Wno-unused-variable -Wno-sign-compare -Wno-unused-label -Wno-array-bounds -Wno-unused-function -Wno-missing-braces")
SET (CMAKE_CXX_FLAGS_DEBUG_INIT          "-O0 -g -D_ENABLE_LOGGING")
SET (CMAKE_CXX_FLAGS_MINSIZEREL_INIT     "-Os -DNDEBUG")
SET (CMAKE_CXX_FLAGS_RELEASE_INIT        "-O2 -DNDEBUG")
SET (CMAKE_CXX_FLAGS_RELWITHDEBINFO_INIT "-O2 -g")
