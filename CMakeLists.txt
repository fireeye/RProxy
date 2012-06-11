cmake_minimum_required(VERSION 2.8)

project(RProxy)

set (CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/CMakeModules)

# Retr and build all dependencies for RProxy: -DRPROXY_BUILD_DEPS:STRING=ON
option (RPROXY_BUILD_DEPS "Build external dependencies" OFF)

set(RPROXY_DEPS_INSTALL ${PROJECT_BINARY_DIR}/install/)

if (RPROXY_BUILD_DEPS)
	add_subdirectory(libs)


	set(LIBEVHTP_LIBRARY          evhtp)
	set(LIBEVENT_LIBRARY          event)
	set(LIBEVENT_CORE_LIBRARY     event_core)
	set(LIBEVENT_PTHREADS_LIBRARY event_pthreads)
	set(LIBEVENT_EXTRA_LIBRARY    event_extra)
	set(LIBEVENT_OPENSSL_LIBRARY  event_openssl)
	set(LIBEVHTP_LIBRARY          evhtp)
	set(LIBCONFUSE_LIBRARY        confuse)
	set(OPENSSL_LIBRARIES         ssl crypto)

	link_directories(${RPROXY_DEPS_INSTALL}/lib/)
	include_directories(${RPROXY_DEPS_INSTALL}/include/)

else()
	find_package(LibEvent REQUIRED)
	find_package(libevhtp REQUIRED)
	find_package(LibConfuse REQUIRED)
	find_package(OpenSSL REQUIRED)

	include_directories(
		${LIBEVHTP_INCLUDE_DIR}
		${OPENSSL_INCLUDE_DIR}/openssl
		${LIBCONFUSE_INCLUDE_DIR}
	)
endif()

set (RPROXY_EXTERNAL_LIBS
			${LIBEVHTP_LIBRARY}
			${LIBEVENT_LIBRARY}
			${LIBEVENT_CORE_LIBRARY}
			${LIBEVENT_PTHREADS_LIBRARY}
			${LIBEVENT_OPENSSL_LIBRARY}
			${LIBCONFUSE_LIBRARY}
			${OPENSSL_LIBRARIES}
)

# local system libraries
find_library (LIB_PTHREAD pthread)
find_library (LIB_DL dl)

set (SYS_LIBS
			${LIB_PTHREAD}
			${LIB_DL}
)

if (APPLE)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-deprecated-declarations")
endif(APPLE)

if (NOT APPLE)
    find_library (LIB_RT rt)
    set (SYS_LIBS ${SYS_LIBS} ${LIB_RT})
endif(NOT APPLE)

INCLUDE (CheckFunctionExists)
INCLUDE (CheckIncludeFiles)
INCLUDE (CheckTypeSize)

CHECK_FUNCTION_EXISTS(daemon HAVE_BUILTIN_DAEMON)
CHECK_FUNCTION_EXISTS(mallopt HAVE_MALLOPT)
CHECK_FUNCTION_EXISTS(strndup HAVE_STRNDUP)
CHECK_FUNCTION_EXISTS(strnlen HAVE_STRNLEN)
CHECK_FUNCTION_EXISTS(getrlimit HAVE_GETRLIMIT)
CHECK_FUNCTION_EXISTS(setrlimit HAVE_SETRLIMIT)

if (HAVE_BUILTIN_DAEMON)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DUSE_BUILTIN_DAEMON")
endif(HAVE_BUILTIN_DAEMON)

if (HAVE_MALLOPT)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DUSE_MALLOPT")
endif(HAVE_MALLOPT)

if (NOT HAVE_STRNDUP)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNO_STRNDUP")
endif(NOT HAVE_STRNDUP)

if (NOT HAVE_STRNLEN)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNO_STRNLEN")
endif(NOT HAVE_STRNLEN)

if (NOT HAVE_GETRLIMIT OR NOT HAVE_SETRLIMIT)
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNO_RLIMITS")
endif(NOT HAVE_GETRLIMIT OR NOT HAVE_SETRLIMIT)

if (NOT ${CMAKE_BUILD_TYPE} STREQUAL "Debug")
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNDEBUG")
endif (NOT ${CMAKE_BUILD_TYPE} STREQUAL "Debug")

add_subdirectory(src)
#add_subdirectory(test)

message("BUILD TYPE:  ${CMAKE_BUILD_TYPE}")
message("BUILD FLAGS: ${CMAKE_C_FLAGS}")
