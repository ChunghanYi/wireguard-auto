/*
 * vpn IP table management routines
 * Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <iostream>
#include <cstdio>
#include <string>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <map>
#include "inc/server.h"
#include "inc/vip_pool.h"
#include "inc/pipe_ret_t.h"
#include "spdlog/spdlog.h"

//#define DEBUG

uint32_t VipTable::byteArrayToIpAddress(const uint8_t ipBytes0, const uint8_t ipBytes1,
		const uint8_t ipBytes2, const uint8_t ipBytes3) {
	uint32_t ipAddress = 0;
	ipAddress |= static_cast<uint32_t>(ipBytes0) << 24;
	ipAddress |= static_cast<uint32_t>(ipBytes1) << 16;
	ipAddress |= static_cast<uint32_t>(ipBytes2) << 8;
	ipAddress |= static_cast<uint32_t>(ipBytes3);
	return ipAddress;
}

std::vector<uint8_t> VipTable::parse_ipv4_address(const std::string& ip_address) {
	std::vector<uint8_t> bytes;
	std::stringstream ss(ip_address);
	std::string segment;

	while (std::getline(ss, segment, '.')) {
		try {
			int value = std::stoi(segment);
			if (value >= 0 && value <= 255) {
				bytes.push_back(static_cast<uint8_t>(value));
			} else {
				throw std::out_of_range("Value out of range");
			}
		} catch (const std::invalid_argument& e) {
			throw std::invalid_argument("Invalid input: " + std::string(e.what()));
		} catch (const std::out_of_range& e) {
			throw std::out_of_range("Value out of range: " + std::string(e.what()));
		}
	}

	if (bytes.size() != 4) {
		throw std::runtime_error("Invalid IP address format");
	}

	return bytes;
}

/**
 * Initialize vip-pool-table(vector table)
 */
bool VipTable::init_vip_table() {
	vip_entry_t v {};
	std::string ip_address = configurations.getstr("vpnip_range_begin");
	if (inet_pton(AF_INET, ip_address.c_str(), &(v.vpnIP)) <= 0) {
		return false;
	}
	std::vector<uint8_t> byte_array = parse_ipv4_address(ip_address);
#ifdef DEBUG
	spdlog::debug("### begin/byte_array => {}.{}.{}.{}",
			byte_array[0], byte_array[1], byte_array[2], byte_array[3]);
#endif
	vip_pool_index.first = static_cast<uint32_t>(byte_array[3]);
	vip_pool_index.first -= 1;  /* not 10.1.0.0 but 10.1.0.1 */

	ip_address = configurations.getstr("vpnip_range_end");
	if (inet_pton(AF_INET, ip_address.c_str(), &(v.vpnIP)) <= 0) {
		return false;
	}
	byte_array = parse_ipv4_address(ip_address);
#ifdef DEBUG
	spdlog::debug("### end/byte_array => {}.{}.{}.{}",
			byte_array[0], byte_array[1], byte_array[2], byte_array[3]);
#endif
	vip_pool_index.last = static_cast<uint32_t>(byte_array[3]);
	vip_pool_index.last -= 1;

	if (vip_pool_index.first > vip_pool_index.last) {
		spdlog::warn("Oops, vip_pool_index.first > vip_pool_index.last !!!");
		return false;
	}
	for (int i = vip_pool_index.first; i <= vip_pool_index.last; i++) {
		v.vpnIP = byteArrayToIpAddress(i+1, byte_array[2], byte_array[1], byte_array[0]);
		v.used = false;
		v.index = i;
		vip_pool_table.push_back(v);
#ifdef DEBUG
		struct in_addr xIP;
		xIP.s_addr = v.vpnIP;
		spdlog::info("### i:{}, IP:{} pushed into vip pool table", i, inet_ntoa(xIP));
#endif
	}
	vip_pool_index.current = vip_pool_index.first;
	return true;
}

/**
 * Get an entry from vip-used-table(map table)
 */
struct _vip_entry* VipTable::search_address_binding(const message_t& rmsg) {
	auto get_mac_addr = [rmsg] () -> std::string {
		char s[18];
		snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x",
				rmsg.mac_addr[0], rmsg.mac_addr[1],
				rmsg.mac_addr[2], rmsg.mac_addr[3],
				rmsg.mac_addr[4], rmsg.mac_addr[5]);
		std::string temp(s);
		return temp;
	};
	std::string macstr = get_mac_addr();

	auto it = vip_used_table.find(macstr);
	if (it != vip_used_table.end()) {
#ifdef DEBUG
		struct in_addr xIP;
		xIP.s_addr = it->second->vpnIP;
		spdlog::info("### OK, ip address({}) found for mac address({}).", inet_ntoa(xIP), macstr);
#endif
		return it->second;
	} else {
		return nullptr;
	}
}

/**
 * Add an entry to vip-used-table(map table) and update vip-pool-table(vector table)
 */
vip_entry_t* VipTable::add_address_binding(const message_t& rmsg) {
	bool ok_flag {false};
	auto get_mac_addr = [rmsg] () -> std::string {
		char s[18];
		snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x",
				rmsg.mac_addr[0], rmsg.mac_addr[1],
				rmsg.mac_addr[2], rmsg.mac_addr[3],
				rmsg.mac_addr[4], rmsg.mac_addr[5]);
		std::string temp(s);
		return temp;
	};
	std::string macstr = get_mac_addr();

	vip_entry_t* tip = new vip_entry_t;
	if (!tip) {
		return nullptr;
	}
	while (1) {
		if (vip_pool_index.current > vip_pool_index.last) {
			delete tip;
			vip_pool_index.current = 0;
			ok_flag = false;
			spdlog::warn("Oops, vip_pool_index.current > vip_pool_index.last !!!");
			break;
		} else if (vip_pool_table[vip_pool_index.current].used == false) {
			vip_pool_table[vip_pool_index.current].used = true;
			tip->vpnIP = vip_pool_table[vip_pool_index.current].vpnIP;
			tip->used = vip_pool_table[vip_pool_index.current].used;
			tip->index = vip_pool_table[vip_pool_index.current].index;
			vip_used_table.insert(std::make_pair(macstr, tip));
			vip_pool_index.current++;
			ok_flag = true;
			break;
		} else {
			vip_pool_index.current++;
		}
	}
	
	if (ok_flag) {
#ifdef DEBUG
		struct in_addr xIP;
		xIP.s_addr = tip->vpnIP;
		spdlog::info("### OK, ip address({}) added for mac address({}).", inet_ntoa(xIP), macstr);
		spdlog::debug("### tip->vpnIP => {}, tip->used => {}, tip->index => {}",
				vip_pool_index.current, inet_ntoa(xIP), tip->used, tip->index);
#endif
		return tip;
	} else {
		return nullptr;
	}
}

/**
 * Remove an entry from vip-used-table(map table) and update vip pool table(vector table)
 */
bool VipTable::remove_address_binding(const message_t& rmsg) {
	auto get_mac_addr = [rmsg] () -> std::string {
		char s[18];
		snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x",
				rmsg.mac_addr[0], rmsg.mac_addr[1],
				rmsg.mac_addr[2], rmsg.mac_addr[3],
				rmsg.mac_addr[4], rmsg.mac_addr[5]);
		std::string temp(s);
		return temp;
	};
	std::string macstr = get_mac_addr();

	auto it = vip_used_table.find(macstr);
	if (it != vip_used_table.end()) {
		if (it->second) {
			if (it->second->index <= vip_pool_index.last)
				vip_pool_table[it->second->index].used = false;
#ifdef DEBUG
			struct in_addr xIP;
			xIP.s_addr = it->second->vpnIP;
			spdlog::info("### OK, ip address({}) removed for mac address({}).", inet_ntoa(xIP), macstr);
#endif
			delete it->second;
		}
		vip_used_table.erase(macstr);
		return true;
	} else {
		return false;
	}
}
