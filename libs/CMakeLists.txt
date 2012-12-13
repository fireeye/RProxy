cmake_minimum_required(VERSION 2.8.4)

include (ExternalProject)

ExternalProject_Add (
	libConfuse
	URL http://savannah.nongnu.org/download/confuse/confuse-2.7.tar.gz
	BUILD_IN_SOURCE 1
	UPDATE_COMMAND ""
	CONFIGURE_COMMAND ./configure --enable-static --disable-shared --prefix=${RPROXY_DEPS_INSTALL}
	BUILD_COMMAND make
	INSTALL_COMMAND make install
)

set (SSL_DSWITCH "")

if (NOT APPLE)
	if (${CMAKE_BUILD_TYPE} matches "Debug")
		set (SSL_DSWITCH "-d")
	endif()

	ExternalProject_Add (
		openssl
		URL http://openssl.org/source/openssl-1.0.0i.tar.gz
		UPDATE_COMMAND ""
		CONFIGURE_COMMAND ./config --prefix=${RPROXY_DEPS_INSTALL} no-shared no-zlib ${SSL_DSWITCH}
		BUILD_IN_SOURCE 1
		BUILD_COMMAND make
		INSTALL_COMMAND make install_sw
	)
else()
	if (${CMAKE_BUILD_TYPE} MATCHES "Debug")
		set (SSL_DSWITCH "-g3 -O0")
	endif()

	ExternalProject_Add(
		openssl
		URL http://openssl.org/source/openssl-1.0.0i.tar.gz
		UPDATE_COMMAND ""
		CONFIGURE_COMMAND ./Configure darwin64-x86_64-cc --prefix=${RPROXY_DEPS_INSTALL} no-shared no-zlib ${SSL_DSWITCH}
		BUILD_IN_SOURCE 1
		BUILD_COMMAND make -j1
		INSTALL_COMMAND make install_sw
	)
endif()

ExternalProject_Add(
	libevent
	DEPENDS openssl
	GIT_REPOSITORY git://github.com/libevent/libevent.git
	GIT_TAG release-2.0.19-stable
	UPDATE_COMMAND ""
	PATCH_COMMAND ./autogen.sh
	CONFIGURE_COMMAND ./configure --disable-shared --prefix=${RPROXY_DEPS_INSTALL} --disable-debug-mode CFLAGS=-I${RPROXY_DEPS_INSTALL}/include LDFLAGS=-L${RPROXY_DEPS_INSTALL}/lib OPENSSL_LIBADD=-ldl
	BUILD_IN_SOURCE 1
	BUILD_COMMAND make
	INSTALL_COMMAND make install
)

ExternalProject_Add(
	libevhtp
	DEPENDS libevent
	GIT_REPOSITORY git://github.com/ellzey/libevhtp.git
	GIT_TAG develop
	UPDATE_COMMAND ""
  CMAKE_ARGS -DCMAKE_FIND_ROOT_PATH:PATH=${RPROXY_DEPS_INSTALL} -DCMAKE_PREFIX_PATH:PATH=${RPROXY_DEPS_INSTALL} -DCMAKE_INSTALL_PREFIX:PATH=${RPROXY_DEPS_INSTALL} -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
)

