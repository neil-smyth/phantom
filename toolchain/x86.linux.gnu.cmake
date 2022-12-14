# Target operating system
SET (CMAKE_SYSTEM_NAME Linux)

# Compiler selection
SET (CMAKE_C_COMPILER   /usr/bin/x86_64-linux-gnu-gcc-7)
SET (CMAKE_CXX_COMPILER /usr/bin/x86_64-linux-gnu-g++-7)

SET (CMAKE_FIND_ROOT_PATH ${TOOLCHAIN_ROOT})
SET (CMAKE_SYSROOT ${TOOLCHAIN_ROOT})

SET (CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
SET (CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET (CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
SET (CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Configure options for the build type
SET (CMAKE_CXX_FLAGS_INIT                "-Wall -m32")
SET (CMAKE_CXX_FLAGS_DEBUG_INIT          "-O0 -g -D_ENABLE_LOGGING")
SET (CMAKE_CXX_FLAGS_MINSIZEREL_INIT     "-Os -DNDEBUG")
SET (CMAKE_CXX_FLAGS_RELEASE_INIT        "-O2 -DNDEBUG")
SET (CMAKE_CXX_FLAGS_RELWITHDEBINFO_INIT "-O2 -g")
