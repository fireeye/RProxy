cmake_minimum_required(VERSION 2.8)

set(REGRESS_SOURCES
			${CMAKE_CURRENT_SOURCE_DIR}/../../src/cfg.c
			${CMAKE_CURRENT_SOURCE_DIR}/../../src/downstream.c
			${CMAKE_CURRENT_SOURCE_DIR}/../../src/request.c
			${CMAKE_CURRENT_SOURCE_DIR}/../../src/ssl.c
			${CMAKE_CURRENT_SOURCE_DIR}/../../src/logger.c
			${CMAKE_CURRENT_SOURCE_DIR}/../../test/unit/tinytest.c
			regress_cfg.c
			regress_main.c
)

include_directories(REGRES_INCLUDE_DIRS
			${CMAKE_CURRENT_SOURCE_DIR}/../../src
			${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(regress_main ${REGRESS_SOURCES})
target_link_libraries(regress_main ${RPROXY_EXTERNAL_LIBS} ${SYS_LIBS})

file(COPY regress_cfg.cfg DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/)
