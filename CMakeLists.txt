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

set(LIBS ${ubox} ${ubus} ${blobmsg_json} ${json} ${ucode} resolv)

# C binding module sources
set(BINDING_SOURCES
	src/module.c
	src/packet.c
	src/parse.c
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
	DESTINATION share/umdnsd
)
