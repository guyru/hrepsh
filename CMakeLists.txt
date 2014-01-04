cmake_minimum_required (VERSION 2.8.3)
project (hrepsh)

set (PACKAGE "hrepsh")
set (VERSION "0.0.1")
set (PACKAGE_STRING "${PACKAGE}-${VERSION}")

# autogenerate dependency information
set (CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

include (FindPkgConfig)

include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
CHECK_CXX_COMPILER_FLAG("-std=c++0x" COMPILER_SUPPORTS_CXX0X)
if(COMPILER_SUPPORTS_CXX11)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
elseif(COMPILER_SUPPORTS_CXX0X)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
else()
        message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
endif()

# # libcrypto++ support
# pkg_check_modules (CRYPTOPP REQUIRED libcrypto++)
include_directories (${CRYPTOPP_INCLUDE_DIRS})

# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBGCRYPT_CFLAGS}")
set (SRC
	main.cpp
)

include_directories (${PROJECT_SOURCE_DIR})

add_executable (hrepsh ${SRC})
# target_link_libraries (hrepsh ${LIBS} ${LIBGCRYPT_LIBRARIES})
target_link_libraries (hrepsh ${LIBS} ${CRYPTOPP_LIBRARIES})

install(TARGETS hrepsh RUNTIME DESTINATION bin/)

add_custom_target(dist
	COMMAND git archive --format=tar --prefix=${PACKAGE_STRING}/ HEAD
		| xz > ${CMAKE_BINARY_DIR}/${PACKAGE_STRING}.tar.xz
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
