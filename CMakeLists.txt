# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2026 John Crispin <john@phrozen.org>

cmake_minimum_required(VERSION 3.10)
project(umdnsd C)

add_definitions(-Wall -Wextra --std=gnu11 -Wmissing-declarations -Wno-unused-parameter -Wno-sign-compare)

set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

# Find required libraries
find_path(ubox_include_dir NAMES libubox/uloop.h)
find_path(ubus_include_dir NAMES libubus.h)
find_path(ucode_include_dir NAMES ucode/module.h)

include_directories(
	${ubox_include_dir}
	${ubus_include_dir}
	${ucode_include_dir}
	${CMAKE_CURRENT_SOURCE_DIR}/src
)

find_library(ubox NAMES ubox)
find_library(ubus NAMES ubus)
find_library(blobmsg_json NAMES blobmsg_json)
find_library(json NAMES json json-c)
find_library(ucode NAMES ucode)

set(LIBS ${ubox} ${ubus} ${blobmsg_json} ${json} ${ucode})

# C binding module sources
set(BINDING_SOURCES
	src/module.c
	src/packet.c
	src/parse.c
	src/name.c
	src/build.c
	src/socket.c
	src/interface.c
	src/callback.c
	src/util.c
	src/queue.c
)

# Build ucode module (mdns.so)
add_library(mdns MODULE ${BINDING_SOURCES})
set_target_properties(mdns PROPERTIES
	OUTPUT_NAME mdns
	PREFIX ""
	LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
target_link_libraries(mdns ${LIBS})

include(CTest)
if(BUILD_TESTING)
	add_executable(test-queue tests/test_queue.c)
	target_link_libraries(test-queue ${ubox})
	add_test(NAME packet-queue COMMAND test-queue)
	add_executable(test-receive tests/test_receive.c)
	add_test(NAME receive-interface COMMAND test-receive)
	add_executable(test-onlink tests/test_onlink.c src/util.c)
	target_link_libraries(test-onlink ${ubox} ${ucode})
	add_test(NAME ipv6-onlink COMMAND sh -c "unshare -rn true 2>/dev/null || exit 77; exec unshare -rn $0"
		$<TARGET_FILE:test-onlink>)
	set_tests_properties(ipv6-onlink PROPERTIES SKIP_RETURN_CODE 77)
endif()
find_program(UCODE_EXECUTABLE ucode)
find_package(Python3 COMPONENTS Interpreter QUIET)
if(BUILD_TESTING AND UCODE_EXECUTABLE AND Python3_Interpreter_FOUND)
	foreach(test protocol tracker discovery dnssd_registry dnssd_conflict dnssd_update dnssd_link
		dnssd_names dnssd_query dnssd_ubus)
		add_test(NAME ${test} COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_protocol.py"
			"${CMAKE_BINARY_DIR}" "${UCODE_EXECUTABLE}" "test_${test}.uc")
	endforeach()
endif()
if(BUILD_TESTING AND UCODE_EXECUTABLE)
	add_test(NAME codec COMMAND "${UCODE_EXECUTABLE}" -L "${CMAKE_BINARY_DIR}"
		"${CMAKE_CURRENT_SOURCE_DIR}/tests/test_codec.uc")
	foreach(test cache_refresh cache_grace utils cache_scope)
		add_test(NAME ${test} COMMAND "${UCODE_EXECUTABLE}" -L "${CMAKE_BINARY_DIR}"
			-L "${CMAKE_CURRENT_SOURCE_DIR}/ucode/*.uc" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_${test}.uc")
	endforeach()
endif()

# Installation
#
# The C module resolves as the bare `mdns` import and installs onto the
# ucode shared-object search path. The ucode modules import each other by
# bare name, so the daemon is launched with this directory on the ucode
# source path:
#   ucode -L <prefix>/share/umdnsd/*.uc <prefix>/share/umdnsd/ucode-mdns.uc
install(TARGETS mdns
	LIBRARY DESTINATION lib/ucode
)

install(FILES
	ucode-mdns.uc
	ucode/main.uc
	ucode/config.uc
	ucode/mdns_ubus.uc
	ucode/cache.uc
	ucode/service.uc
	ucode/services.uc
	ucode/host.uc
	ucode/discovery.uc
	ucode/query.uc
	ucode/response.uc
	ucode/announce.uc
	ucode/tracker.uc
	ucode/packet.uc
	ucode/nsec.uc
	ucode/utils.uc
	ucode/const.uc
	ucode/dnssd_registry.uc
	ucode/dnssd_ubus.uc
	DESTINATION share/umdnsd
)
