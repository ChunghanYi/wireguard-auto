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
#include "inc/common.h"
#include "inc/peer_tbl.h"
#include "spdlog/spdlog.h"
#include <hiredis/hiredis.h>

#ifdef REDIS
unsigned int redis_port = 6379;
std::string redis_host  = "127.0.0.1";

redisContext* redis_init_connection();
void store_data_in_redis(std::string key_name, std::string value_details);
void remove_data_in_redis(std::string key_name);
void get_data_in_redis(std::string key_name);

void store_data_in_redis(std::string key_name, std::string value_details) {
	redisReply* reply           = NULL;
	redisContext* redis_context = redis_init_connection();

	if (!redis_context) {
		spdlog::error("Could not initiate connection to Redis.");
		return;
	}

	reply = (redisReply*)redisCommand(redis_context, "SET %s %s", key_name.c_str(), value_details.c_str());

	// If we store data correctly ...
	if (!reply) {
		spdlog::error("redisCommand() is failed: {}.", redis_context->errstr);

		// Handle redis server restart corectly
		if (redis_context->err == 1 or redis_context->err == 3) {
			// Connection refused
			spdlog::error("Unfortunately we can't store data in Redis because server reject connection");
		}
	} else {
		freeReplyObject(reply);
	}

	redisFree(redis_context);
}

void remove_data_in_redis(std::string key_name) {
	redisReply* reply           = NULL;
	redisContext* redis_context = redis_init_connection();

	if (!redis_context) {
		spdlog::error("Could not initiate connection to Redis.");
		return;
	}

	reply = (redisReply*)redisCommand(redis_context, "DEL %s", key_name.c_str());

	// If we store data correctly ...
	if (!reply) {
		spdlog::error("redisCommand() is failed: {}.", redis_context->errstr);

		// Handle redis server restart corectly
		if (redis_context->err == 1 or redis_context->err == 3) {
			// Connection refused
			spdlog::error("Unfortunately we can't store data in Redis because server reject connection");
		}
	} else {
		freeReplyObject(reply);
	}

	redisFree(redis_context);
}

void get_data_in_redis(std::string key_name) {
	redisReply* reply           = NULL;
	redisContext* redis_context = redis_init_connection();

	if (!redis_context) {
		spdlog::error("Could not initiate connection to Redis.");
		return;
	}

	reply = (redisReply*)redisCommand(redis_context, "GET %s", key_name.c_str());

	// If we store data correctly ...
	if (!reply) {
		spdlog::error("redisCommand() is failed: {}.", redis_context->errstr);

		// Handle redis server restart corectly
		if (redis_context->err == 1 or redis_context->err == 3) {
			// Connection refused
			spdlog::error("Unfortunately we can't store data in Redis because server reject connection");
		}
	} else {
		spdlog::info("### reply->str -----> [{}]", reply->str);
		freeReplyObject(reply);
	}

	redisFree(redis_context);
}

redisContext* redis_init_connection() {
	struct timeval timeout      = { 1, 500000 }; // 1.5 seconds
	redisContext* redis_context = redisConnectWithTimeout(redis_host.c_str(), redis_port, timeout);
	if (redis_context->err) {
		spdlog::error("Redis connection error: {}", redis_context->errstr);
		return NULL;
	}

	// We should check connection with ping because redis do not check connection
	redisReply* reply = (redisReply*)redisCommand(redis_context, "PING");
	if (reply) {
		freeReplyObject(reply);
	} else {
		return NULL;
	}

	return redis_context;
}
#endif

/**
 * Get a peer(remote client) from the rclient table
 */
peer_table_t* WgacServer::get_peer_table(const message_t& rmsg) {
	std::string macstr = common::get_mac_addr_string(rmsg);

	auto it = peers.find(macstr);
	if (it != peers.end()) {
		return it->second;
	} else {
		return nullptr;
	}
}

/**
 * Add a peer(remote client) to the rclient table(and redis server)
 */
bool WgacServer::add_peer_table(const message_t& rmsg) {
	std::string macstr = common::get_mac_addr_string(rmsg);

	peer_table_t* peer = get_peer_table(rmsg);
	if (peer == nullptr) {
		peer_table_t *peer = new peer_table_t;
		if (peer) {
			memset(peer, 0, sizeof(peer_table_t));
			memcpy(peer->mac_addr, rmsg.mac_addr, 6);
			peers.insert(std::make_pair(macstr, peer));

#ifdef REDIS
			char macbuf[32], vpnIP_str[16], vpnNetmask_str[16], xbuf[512];
			char epIP_str[16], allowed_ips[256];
			snprintf(macbuf, sizeof(macbuf), "wgac:%02x%02x.%02x%02x.%02x%02x",
					rmsg.mac_addr[0], rmsg.mac_addr[1],
					rmsg.mac_addr[2], rmsg.mac_addr[3],
					rmsg.mac_addr[4], rmsg.mac_addr[5]);
			snprintf(vpnIP_str, sizeof(vpnIP_str), "%s", inet_ntoa(rmsg.vpnIP));
			snprintf(vpnNetmask_str, sizeof(vpnNetmask_str), "%s", inet_ntoa(rmsg.vpnNetmask));
			snprintf(epIP_str, sizeof(epIP_str), "%s", inet_ntoa(rmsg.epIP));
			snprintf(xbuf, sizeof(xbuf), "%s %s %s %s:%d %s",
					vpnIP_str, vpnNetmask_str, rmsg.public_key,
					epIP_str, rmsg.epPort, rmsg.allowed_ips);

			//SET wgac:xxxx.xxxx.xxxx yyyy yyyy yyyy yyyy yyyy yyyy
			std::string key_name {macbuf};
			std::string value_details {xbuf};
			store_data_in_redis(key_name, value_details);

#ifdef DEBUG
			//GET wgac:xxxx.xxxx.xxxx
			get_data_in_redis(key_name);
#endif
#endif
			return true;
		} else {
			return false;
		}
	} else {
		return true;
	}
}

/**
 * Update a peer(remote client) info to the rclient table(and redis server)
 */
bool WgacServer::update_peer_table(const message_t& rmsg) {
	std::string macstr = common::get_mac_addr_string(rmsg);

	peer_table_t* peer = get_peer_table(rmsg);
	if (peer) {
		memcpy(peer->mac_addr, rmsg.mac_addr, 6);
		peer->vpnIP.s_addr = rmsg.vpnIP.s_addr;
		peer->vpnNetmask.s_addr = rmsg.vpnNetmask.s_addr;
		memcpy(peer->public_key, rmsg.public_key, WG_KEY_LEN_BASE64);
		peer->epIP.s_addr = rmsg.epIP.s_addr;
		peer->epPort = rmsg.epPort;
		memcpy(peer->allowed_ips, rmsg.allowed_ips, 256);

#ifdef REDIS
		char macbuf[32], vpnIP_str[16], vpnNetmask_str[16], xbuf[512];
		char epIP_str[16], allowed_ips[256];
		snprintf(macbuf, sizeof(macbuf), "wgac:%02x%02x.%02x%02x.%02x%02x",
				rmsg.mac_addr[0], rmsg.mac_addr[1],
				rmsg.mac_addr[2], rmsg.mac_addr[3],
				rmsg.mac_addr[4], rmsg.mac_addr[5]);
		snprintf(vpnIP_str, sizeof(vpnIP_str), "%s", inet_ntoa(rmsg.vpnIP));
		snprintf(vpnNetmask_str, sizeof(vpnNetmask_str), "%s", inet_ntoa(rmsg.vpnNetmask));
		snprintf(epIP_str, sizeof(epIP_str), "%s", inet_ntoa(rmsg.epIP));
		snprintf(xbuf, sizeof(xbuf), "%s %s %s %s:%d %s",
				vpnIP_str, vpnNetmask_str, rmsg.public_key,
				epIP_str, rmsg.epPort, rmsg.allowed_ips);

		//SET wgac:xxxx.xxxx.xxxx yyyy yyyy yyyy yyyy yyyy yyyy
		std::string key_name {macbuf};
		std::string value_details {xbuf};
		store_data_in_redis(key_name, value_details);

#ifdef DEBUG
		//GET wgac:xxxx.xxxx.xxxx
		get_data_in_redis(key_name);
#endif
#endif
		return true;
	} else {
		return false;
	}
}

/**
 * Remove a peer(remote client) info from the rclient table(and redis server)
 */
bool WgacServer::remove_peer_table(const message_t& rmsg) {
	std::string macstr = common::get_mac_addr_string(rmsg);

	auto it = peers.find(macstr);
	if (it != peers.end()) {
		if (it->second) {
			delete it->second;
		}
		peers.erase(macstr);

#ifdef REDIS
		char macbuf[32];
		snprintf(macbuf, sizeof(macbuf), "wgac:%02x%02x.%02x%02x.%02x%02x",
				rmsg.mac_addr[0], rmsg.mac_addr[1],
				rmsg.mac_addr[2], rmsg.mac_addr[3],
				rmsg.mac_addr[4], rmsg.mac_addr[5]);

		//DEL wgac:xxxx.xxxx.xxxx
		std::string key_name {macbuf};
		remove_data_in_redis(key_name);

#ifdef DEBUG
		//GET wgac:xxxx.xxxx.xxxx
		get_data_in_redis(key_name);
#endif
#endif
		return true;
	} else {
		return false;
	}
}
