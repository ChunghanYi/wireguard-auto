/*
 * Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <sys/socket.h>
#include <netinet/in.h>
#include "message.h"

/* client storage structure */
struct peer_table {
	uint8_t mac_addr[6];                     // 6 bytes : MAC address
	struct sockaddr_in clientaddr;           // real IP address and port

	struct in_addr vpnIP;                    // VPN IP address
	struct in_addr vpnNetmask;               // VPN Subnet Mask

	uint8_t public_key[WG_KEY_LEN_BASE64];   // my public key
	struct in_addr epIP;                     // 4 bytes : my endpoint IP address (IPv4)
	uint16_t epPort;                         // peer endpoint point(SPN port)
	uint8_t allowed_ips[256];                // peer allowed ips(networks)
	time_t time;                             // last message received (time(NULL))

	int wireguard_enabled;                   // wireguard enabled(0 or 1)
};

using peer_table_t = struct peer_table;
