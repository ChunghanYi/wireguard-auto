/*
 * Peer table routines
 * Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <iostream>
#include <cstdio>
#include <string>
#include <vector>
#include <map>
#include "inc/server.h"
#include "inc/message.h"
#include "inc/peer_tbl.h"
#include "inc/pipe_ret_t.h"
#include "spdlog/spdlog.h"

/**
 * Get a peer(remote client) from the rclient table
 */
peer_table_t *WgacServer::get_peer_table(const message_t& rmsg) {
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

	auto it = peers.find(macstr);
	if (it != peers.end()) {
		return it->second;
	} else {
		return NULL;
	}
}

/**
 * Add a peer(remote client) to the rclient table
 */
bool WgacServer::add_peer_table(const message_t& rmsg) {
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

	peer_table_t *peer = get_peer_table(rmsg);
	if (peer == nullptr) {
		peer_table_t *peer = new peer_table_t;
		if (peer) {
			memset(peer, 0, sizeof(peer_table_t));
			memcpy(peer->mac_addr, rmsg.mac_addr, 6);

			peers.insert(std::make_pair(macstr, peer));
			return true;
		} else {
			return false;
		}
	} else {
		return true;
	}
}

/**
 * Update a peer(remote client) info to the rclient table
 */
bool WgacServer::update_peer_table(const message_t& rmsg) {
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

	peer_table_t *peer = get_peer_table(rmsg);
	if (peer) {
		memcpy(peer->mac_addr, rmsg.mac_addr, 6);
		peer->vpnIP.s_addr = rmsg.vpnIP.s_addr;
		peer->vpnNetmask.s_addr = rmsg.vpnNetmask.s_addr;
		memcpy(peer->public_key, rmsg.public_key, WG_KEY_LEN_BASE64);
		peer->epIP.s_addr = rmsg.epIP.s_addr;
		peer->epPort = rmsg.epPort;
		memcpy(peer->allowed_ips, rmsg.allowed_ips, 256);
		return true;
	} else {
		return false;
	}
}

/**
 * Remove a peer(remote client) info from the rclient table
 */
bool WgacServer::remove_peer_table(const message_t& rmsg) {
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

	auto it = peers.find(macstr);
	if (it != peers.end()) {
		if (it->second) {
			delete it->second;
		}
		peers.erase(macstr);
		return true;
	} else {
		return false;
	}
}
