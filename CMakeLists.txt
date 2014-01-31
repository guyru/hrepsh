cmake_minimum_required (VERSION 2.8.3)
project (hrepsh)

set (PACKAGE "hrepsh")
set (VERSION "0.0.1")
set (PACKAGE_STRING "${PACKAGE}-${VERSION}")

# autogenerate dependency information
set (CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

include (FindPkgConfig)
find_package (Boost REQUIRED COMPONENTS program_options)
include_directories (${Boost_INCLUDE_DIRS})

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

set (SECRET_FILE /etc/hrepsh CACHE FILEPATH
	"The location of the file which holds the encryption keys")

configure_file (
	${CMAKE_SOURCE_DIR}/config.h.cmake
	${CMAKE_BINARY_DIR}/config.h
)
include_directories (${CMAKE_BINARY_DIR})

# libcrypto++ support
pkg_check_modules (CRYPTOPP REQUIRED libcrypto++)
include_directories (${CRYPTOPP_INCLUDE_DIRS})

set (SRC
	main.cpp
)

include_directories (${PROJECT_SOURCE_DIR})

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

add_executable (hrepsh ${SRC})
target_link_libraries (hrepsh ${CRYPTOPP_LIBRARIES})
target_link_libraries (hrepsh ${Boost_LIBRARIES})

install(TARGETS hrepsh RUNTIME DESTINATION bin/)

add_custom_target(dist
	COMMAND git archive --format=tar --prefix=${PACKAGE_STRING}/ HEAD
		| xz > ${CMAKE_BINARY_DIR}/${PACKAGE_STRING}.tar.xz
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
