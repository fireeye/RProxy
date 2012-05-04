cmake_minimum_required(VERSION 2.8)

set(SMOKE_SOURCES
			smoke_downstream.c
)

add_executable(smoke_downstream ${SMOKE_SOURCES})
target_link_libraries(smoke_downstream ${EXT_LIBS} ${SYS_LIBS})

set (SMOKE_FILES
	${PROJECT_SOURCE_DIR}/test/smoke/smoke.sh
	${PROJECT_SOURCE_DIR}/test/smoke/smoke_cfg.cfg
	${PROJECT_SOURCE_DIR}/test/smoke/ca.crt
	${PROJECT_SOURCE_DIR}/test/smoke/server.key
	${PROJECT_SOURCE_DIR}/test/smoke/server.crt
	${PROJECT_SOURCE_DIR}/test/smoke/client.key
	${PROJECT_SOURCE_DIR}/test/smoke/client.crt
)

file(COPY ${SMOKE_FILES} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
