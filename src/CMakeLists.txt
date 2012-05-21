cmake_minimum_required(VERSION 2.8)

add_executable(rproxy cfg.c downstream.c request.c ssl.c logger.c rproxy.c)
target_link_libraries(rproxy ${RPROXY_EXTERNAL_LIBS} ${SYS_LIBS})

install(TARGETS rproxy RUNTIME DESTINATION bin)
