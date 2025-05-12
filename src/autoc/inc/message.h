/*
 * Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <sys/socket.h>
#include <netinet/in.h>

enum class AUTOCONN {
	HELLO = 0,
	PING  = 1,
	PONG  = 2,
	OK    = 3,
	NOK   = 4,
	BYE   = 5,
	EXIST = 6
};

#define WG_CLIENT_PORT 51820
#define WG_KEY_LEN 32
#define WG_KEY_LEN_BASE64 ((((WG_KEY_LEN) + 2) / 3) * 4 + 1)

struct message {
	enum AUTOCONN type;                      // 4 byte : message type
	uint8_t mac_addr[6];                     // 6 bytes : MAC address
	struct in_addr vpnIP;                    // 4 bytes : vpn IP address (IPv4)
	struct in_addr vpnNetmask;               // 4 bytes : vpn subnet mask (IPv4)
	uint8_t public_key[WG_KEY_LEN_BASE64];   // 45 bytes : curve25519 public key
	struct in_addr epIP;                     // 4 bytes : my endpoint IP address (IPv4)
	uint16_t epPort;                         // 2 bytes : my endpoint port
	uint8_t allowed_ips[256];                // 256 bytes : my allowed ips(networks)
}  __attribute__ ((packed));

#define ENC_MESSAGE_SIZE (sizeof(struct message) + 40)
using message_t = struct message;
