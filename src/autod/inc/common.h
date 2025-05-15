#pragma once

#include <string>
#include <cstdio>
#include "message.h"

#define MAX_PACKET_SIZE 4096

namespace fd_wait
{

enum Result {
	FAILURE,
	TIMEOUT,
	SUCCESS
};

Result waitFor(const FileDescriptor& fileDescriptor, uint32_t timeoutSeconds = 1);

};

namespace common
{

std::string get_mac_addr_string(const message_t& rmsg);
bool exec(const std::string& cmd, std::vector<std::string>& output_list, std::string& error_text);

};
