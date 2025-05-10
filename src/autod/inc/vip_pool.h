/*
 * Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <sys/socket.h>
#include <netinet/in.h>
#include "configuration.h"

struct _vip_entry {
	uint32_t vpnIP;
	bool used;
	int index;   //vector index
};
using vip_entry_t = struct _vip_entry;

struct pool_indexes {
	uint32_t first;    // first address of the pool(vector table)
	uint32_t last;     // last address of the pool(vector table)
	uint32_t current;  // current available address(vector table)
};

class VipTable {
public:
	VipTable() {}
	~VipTable() {}

	bool init_vip_table();
	vip_entry_t* search_address_binding(const message_t& rmsg);
	vip_entry_t* add_address_binding(const message_t& rmsg);
	bool update_address_binding(const message_t& rmsg);
	bool remove_address_binding(const message_t& rmsg);

	uint32_t byteArrayToIpAddress(const uint8_t ipBytes0, const uint8_t ipBytes1,
			const uint8_t ipBytes2, const uint8_t ipBytes3);
	std::vector<uint8_t> parse_ipv4_address(const std::string& ip_address);

private:
	std::vector<vip_entry_t> vip_pool_table;
	struct pool_indexes vip_pool_index;
	std::map<std::string, vip_entry_t*> vip_used_table;
};

extern VipTable viptable;
