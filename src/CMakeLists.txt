cmake_minimum_required(VERSION 2.8)

add_executable(rproxy
	cfg.c
	downstream.c
	rproxy.c
	ssl.c
	request.c
	lzlog.c
	lzq.c
	logger.c
	util.c
	token_bucket.c
	ratelim.c)

target_link_libraries(rproxy ${RPROXY_EXTERNAL_LIBS} ${SYS_LIBS})

install(TARGETS rproxy RUNTIME DESTINATION bin)
