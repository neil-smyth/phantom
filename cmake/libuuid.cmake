# CMake module to find the libuuid library
#
# The following variables are set:
#   LIBUUID_LIBRARIES - System has libuuid
#   LIBUUID_HEADERS - The libuuid headers

find_library(LIBUUID_LIBRARIES NAMES uuid)

if (LIBUUID_LIBRARIES)
  message(STATUS "libuuid: ${LIBUUID_LIBRARIES}")
else ()
  message(STATUS "libuuid: NOT FOUND!")
endif (LIBUUID_LIBRARIES)

find_path(LIBUUID_HEADERS uuid.h PATH_SUFFIXES uuid/)

if (LIBUUID_HEADERS)
  message(STATUS "libuuid headers: ${LIBUUID_HEADERS}")
else ()
  message(STATUS "libuuid headers: NOT FOUND!")
endif (LIBUUID_HEADERS)
