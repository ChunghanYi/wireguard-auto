/*
 * Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
 * Copyright (c) 2019 Elhay Rauper
 *
 * SPDX-License-Identifier: MIT
 */

#include <fstream>
#include <iostream>
#include <vector>
#include <cstring>

#include <cstdint>
#include <string>
#include "inc/pipe_ret_t.h"
#include "inc/file_descriptor.h"
#include "inc/common.h"

#include <sys/select.h>

#define SELECT_FAILED -1
#define SELECT_TIMEOUT 0

namespace fd_wait
{

/**
 * monitor file descriptor and wait for I/O operation
 */
Result waitFor(const FileDescriptor& fileDescriptor, uint32_t timeoutSeconds) {
	struct timeval tv;
	tv.tv_sec = timeoutSeconds;
	tv.tv_usec = 0;
	fd_set fds;

	FD_ZERO(&fds);
	FD_SET(fileDescriptor.get(), &fds);
	const int selectRet = select(fileDescriptor.get() + 1, &fds, nullptr, nullptr, &tv);

	if (selectRet == SELECT_FAILED) {
		return Result::FAILURE;
	} else if (selectRet == SELECT_TIMEOUT) {
		return Result::TIMEOUT;
	}
	return Result::SUCCESS;
}

}

///////////////////////////////////////////////////////////////////////////////////////////

pipe_ret_t pipe_ret_t::failure(const std::string& msg) {
    return pipe_ret_t(false, msg);
}

pipe_ret_t pipe_ret_t::success(const std::string& msg) {
    return pipe_ret_t(true, msg);
}

namespace common
{

/**
 * Get a string for mac address bytes 
 */
std::string get_mac_addr_string(const message_t& rmsg) {
	return [rmsg]() -> std::string {
		char xbuf[18];
		snprintf(xbuf, sizeof(xbuf), "%02x:%02x:%02x:%02x:%02x:%02x",
				rmsg.mac_addr[0], rmsg.mac_addr[1],
				rmsg.mac_addr[2], rmsg.mac_addr[3],
				rmsg.mac_addr[4], rmsg.mac_addr[5]);
		std::string s(xbuf);
		return s;
	}();
}

// Exec command in shell and capture output
bool exec(const std::string& cmd, std::vector<std::string>& output_list, std::string& error_text) {
	FILE* pipe = popen(cmd.c_str(), "r");

	if (!pipe) {
		// We need more details in case of failure
		error_text = "error code: " + std::to_string(errno) + " error text: " + strerror(errno);
		return false;
	}

	char buffer[256];

	while (!feof(pipe)) {
		if (fgets(buffer, 256, pipe) != NULL) {
			size_t newbuflen = strlen(buffer);

			// remove newline at the end
			if (buffer[newbuflen - 1] == '\n') {
				buffer[newbuflen - 1] = '\0';
			}

			output_list.push_back(buffer);
		}
	}

	pclose(pipe);
	return true;
}

}
