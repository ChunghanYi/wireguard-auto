/*
 * wireguard autoconnect protocol: message send/recv routines
 * Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <iostream>
#include <cstdio>
#include <string>
#include <vector>
#include <map>
#include <net/if.h>
#include <sys/ioctl.h>
#include <time.h>
#include "inc/message.h"
#include "inc/client.h"
#include "inc/configuration.h"
#include "inc/pipe_ret_t.h"
#include "inc/common.h"
#include "spdlog/spdlog.h"

/**
 * Get local mac address
 */
void get_local_mac_address(char* macaddr) {
	struct ifreq s;
	int fd, i;
	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (fd >= 0) {
#ifdef VTYSH
		sprintf((char*)s.ifr_name, "%s", "eth0");
#else
		sprintf((char*)s.ifr_name, "%s", "enp4s0");
#endif
		if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
			for (i = 0; i < 6; i++)
				macaddr[i] = (unsigned char) s.ifr_addr.sa_data[i];
		}
		close(fd);
	}
}

/**
 * Initialize a message with the given fields
 */
static inline void init_smsg(message_t* smsg, enum AUTOCONN type, uint32_t ip, uint32_t mask) {
	memset(smsg, 0, sizeof(message_t));
	smsg->type = type;
	get_local_mac_address(reinterpret_cast<char*>(smsg->mac_addr));
	smsg->vpnIP.s_addr = ip;
	smsg->vpnNetmask.s_addr = mask;
}

/**
 * Send a HELLO message and receive an HELLO/NOK message
 */
bool WgacClient::send_hello_message() {
	message_t smsg;

	init_smsg(&smsg, AUTOCONN::HELLO, 0, 0);

	memcpy(smsg.public_key, _autoConf.getstr("this_public_key").c_str(), WG_KEY_LEN_BASE64);

	if (inet_pton(AF_INET, _autoConf.getstr("this_endpoint_ip").c_str(), &(smsg.epIP)) != 1) {
		spdlog::warn("inet_pton(this_endpoint_ip) failed.");
		return false;
	}
	smsg.epPort = _autoConf.getint("this_endpoint_port");
	memcpy(smsg.allowed_ips, _autoConf.getstr("this_allowed_ips").c_str(), 256);

	pipe_ret_t sendRet = sendMsg(reinterpret_cast<unsigned char*>(&smsg), sizeof(message_t));
	if (!sendRet.isSuccessful()) {
		spdlog::debug(">>> Failed to send message.");
		return false;
	} else {
		spdlog::info(">>> HELLO message sent to server.");
	}

	usleep(500000);

	//Get the vpn ip allocated from server
	message_t rmsg;
	if (handle_message_queue(&rmsg)) {
		if (rmsg.type == AUTOCONN::HELLO) {
			spdlog::info("<<< HELLO message received.");
			/* save the vpnIP and vpnNetmask come from server */
			char s[16];
			snprintf(s, sizeof(s), "%s", inet_ntoa(rmsg.vpnIP));
			std::string value1(s);
			_autoConf.setstr("this_vpn_ip", value1);

			sprintf(s, "%s", inet_ntoa(rmsg.vpnNetmask));
			std::string value2(s);
			_autoConf.setstr("this_vpn_netmask", value2);

			spdlog::info("--- vpnIP({}/{}) received from server.", value1, value2);
			return true;
		} else {
			spdlog::info("<<< Oops, HELLO message NOT received.");
			return false;
		}
	} else {
		spdlog::info("<<< No message has arrived.");
		return false;
	}
}

/**
 * Send a PING message and receive a PONG/NOK message
 */
bool WgacClient::send_ping_message(message_t* pmsg) {
	message_t smsg;

	init_smsg(&smsg, AUTOCONN::PING, 0, 0);

	//from saved vpn ip !!!
	if (inet_pton(AF_INET, _autoConf.getstr("this_vpn_ip").c_str(), &(smsg.vpnIP)) != 1) {
		spdlog::warn("inet_pton(this_vpn_ip) failed.");
		return false;
	}
	if (inet_pton(AF_INET, _autoConf.getstr("this_vpn_netmask").c_str(), &(smsg.vpnNetmask)) != 1) {
		spdlog::warn("inet_pton(this_vpn_netmask) failed.");
		return false;
	}

	memcpy(smsg.public_key, _autoConf.getstr("this_public_key").c_str(), WG_KEY_LEN_BASE64);

	if (inet_pton(AF_INET, _autoConf.getstr("this_endpoint_ip").c_str(), &(smsg.epIP)) != 1) {
		spdlog::warn("inet_pton(this_endpoint_ip) failed.");
		return false;
	}
	smsg.epPort = _autoConf.getint("this_endpoint_port");
	memcpy(smsg.allowed_ips, _autoConf.getstr("this_allowed_ips").c_str(), 256);

	pipe_ret_t sendRet = sendMsg(reinterpret_cast<unsigned char*>(&smsg), sizeof(message_t));
	if (!sendRet.isSuccessful()) {
		spdlog::debug(">>> Failed to send message.");
		return false;
	} else {
		spdlog::info(">>> PING message sent to server.");
	}

	usleep(500000);

	if (handle_message_queue(pmsg)) {
		if (pmsg->type == AUTOCONN::PONG) {
			spdlog::info("<<< PONG message received.");
			return true;
		} else {
			spdlog::info("<<< Oops, PONG message NOT received.");
			return false;
		}
	} else {
		spdlog::info("<<< No message has arrived.");
		return false;
	}
}

/**
 * Send a BYE message and receive an BYE/NOK message
 */
bool WgacClient::send_bye_message() {
	message_t smsg;

	init_smsg(&smsg, AUTOCONN::BYE, 0, 0);

	if (inet_pton(AF_INET, _autoConf.getstr("this_vpn_ip").c_str(), &(smsg.vpnIP)) != 1) {
		spdlog::warn("inet_pton(this_vpn_ip) failed.");
		return false;
	}
	if (inet_pton(AF_INET, _autoConf.getstr("this_vpn_netmask").c_str(), &(smsg.vpnNetmask)) != 1) {
		spdlog::warn("inet_pton(this_vpn_netmask) failed.");
		return false;
	}
	memcpy(smsg.public_key, _autoConf.getstr("this_public_key").c_str(), WG_KEY_LEN_BASE64);

	pipe_ret_t sendRet = sendMsg(reinterpret_cast<unsigned char*>(&smsg), sizeof(message_t));
	if (!sendRet.isSuccessful()) {
		spdlog::debug(">>> Failed to send message.");
		return false;
	} else {
		spdlog::info(">>> BYE message sent to server.");
	}

	usleep(500000);

	message_t rmsg;
	if (handle_message_queue(&rmsg)) {
		if (rmsg.type == AUTOCONN::BYE) {
			spdlog::info("<<< BYE message received.");
			remove_wireguard(&rmsg);
			return true;
		} else {
			spdlog::info("<<< Oops, BYE message NOT received.");
			return false;
		}
	} else {
		spdlog::info("<<< Any message NOT arrived.");
		return false;
	}
}

/**
 * Extract a message from message queue.
 */
bool WgacClient::handle_message_queue(message_t* pmsg) {
	time_t t, last_time = 0;
	last_time = time(NULL);

	while (1) {
		if (!_msgQueue.empty()) {
			*pmsg = _msgQueue.front();
			_msgQueue.pop();
			return true;
		}
		usleep(1000);
		t = time(NULL);
		if (t - last_time > 1) {
			pmsg->type = AUTOCONN::NOK;
			break;
		}
	}
	return false;
}

/**
 * Setup wireguard configuration with the wg tool or vtysh.
 */
void WgacClient::setup_wireguard(message_t* rmsg) {
	char szInfo[512] = {};
	char vpnip_str[32] = {};
	char epip_str[32] = {};

	snprintf(vpnip_str, sizeof(vpnip_str), "%s", inet_ntoa(rmsg->vpnIP));
	snprintf(epip_str, sizeof(epip_str), "%s", inet_ntoa(rmsg->epIP));

#ifdef VTYSH
	snprintf(szInfo, sizeof(szInfo),
			"wg peer %s allowed-ips %s/32 endpoint %s:%d persistent-keepalive 25",
			rmsg->public_key, vpnip_str, epip_str, rmsg->epPort);

	char xbuf[1024];
	sprintf(xbuf, "/usr/bin/qrwg/vtysh -e \"%s\"", szInfo);
	system(xbuf);

	sprintf(xbuf, "/usr/bin/qrwg/vtysh -e \"write\"");
	system(xbuf);

	spdlog::info("--- wireguard rule [{}]", szInfo);
	spdlog::info("--- OK, wireguard setup is complete.");
#else
#ifdef WIREGUARD_C_DAEMON

	send_ac_vpn_message(rmsg);

	send_start_vpn_message(AUTOCONN::START_VPN);

	spdlog::info("--- OK, wireguard setup is complete.");

#else /* WIREGUARD KERNEL */
	std::string error_text;
	std::vector<std::string> output_list;
	snprintf(szInfo, sizeof(szInfo),
			"wg set wg0 peer %s allowed-ips %s/32 endpoint %s:%d persistent-keepalive 25 &",
			rmsg->public_key, vpnip_str, epip_str, rmsg->epPort);

	std::string cmd(szInfo);
	bool exec_result = common::exec(cmd, output_list, error_text);
	if (exec_result) {
		spdlog::info("--- wireguard rule [{}]", szInfo);
		spdlog::info("--- OK, wireguard setup is complete.");
	} else {
		spdlog::warn("{}", error_text);
	}
#endif
#endif
}

/**
 * Remove a wireguard configuration with the wg tool or vtysh.
 */
void WgacClient::remove_wireguard(message_t* rmsg) {
	char szInfo[256] = {};

#ifdef VTYSH
	snprintf(szInfo, sizeof(szInfo), "no wg peer %s", rmsg->public_key);

	char xbuf[512];
	snprintf(xbuf, sizeof(xbuf), "/usr/bin/qrwg/vtysh -e \"%s\"", szInfo);
	system(xbuf);

	sprintf(xbuf, "/usr/bin/qrwg/vtysh -e \"write\"");
	system(xbuf);

	spdlog::info("--- wireugard rule [{}]", szInfo);
	spdlog::info("OK, wireguard rule is removed.");
#else
	std::string error_text;
	std::vector<std::string> output_list;
	snprintf(szInfo, sizeof(szInfo), "wg set wg0 peer %s remove", rmsg->public_key);

	std::string cmd(szInfo);
	bool exec_result = common::exec(cmd, output_list, error_text);
	if (exec_result) {
		spdlog::info("--- wireugard rule [{}]", szInfo);
		spdlog::info("OK, wireguard rule is removed.");
	} else {
		spdlog::warn("{}", error_text);
	}
#endif
}

/**
 * Start PING-PONG negotiations
 */
void WgacClient::start() {
	message_t rmsg;

	while (1) {
		if (send_hello_message()) {
			if (send_ping_message(&rmsg)) {
				setup_wireguard(&rmsg);	
				break;
			}
		}
		sleep(10);
	}

	while (!_flagTerminate) {
		sleep(5);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////

/* wrapper around sendto for non blocking I/O */
#ifdef WIREGUARD_C_DAEMON
ssize_t WgacClient::xsendto(int sockfd, const void* buf, size_t len, int flags, const
		struct sockaddr* dest_addr, socklen_t addrlen) {
	ssize_t r;
	fd_set set;

	while ((r = sendto(sockfd, buf, len, flags, dest_addr, addrlen)) == -1
			&& (errno == EAGAIN || errno == EWOULDBLOCK)) {
		FD_ZERO(&set);
		FD_SET(sockfd, &set);
		select(sockfd+1, NULL, &set, NULL, NULL);
	}
	return r;
}

unsigned short vpn_event_port = 7177;

/* wg_autoc --> wireguard-c daemon */
int WgacClient::send_local_message(ac_message_t* smsg) {
	int sd;
	struct sockaddr_in addr;
	struct hostent *hostent;
	int ret = 0;

	sd = socket(PF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		spdlog::error("Could not create the socket.");
		return -1;
	}

	hostent = gethostbyname("127.0.0.1");
	addr.sin_family = AF_INET;
	addr.sin_port = htons(vpn_event_port);
	memcpy(&addr.sin_addr, hostent->h_addr, hostent->h_length);

	if (xsendto(sd, smsg, sizeof(ac_message_t), 0,
				(struct sockaddr*)&addr, sizeof (addr)) == -1) {
		spdlog::error("xsendto failed.");
		ret = -1;
	}

	::close(sd);
	return ret;
}

void WgacClient::send_ac_vpn_message(message_t* rmsg) {
	ac_message_t xmsg;
	memcpy(&xmsg, rmsg, sizeof(message_t));
	xmsg.m.type = AUTOCONN::SEND_VPN_INFORMATION;
	if (inet_pton(AF_INET, _autoConf.getstr("this_vpn_ip").c_str(), &(xmsg.clientIP)) != 1) {
		spdlog::warn("inet_pton(this_vpn_ip) failed.");
		return;
	}

	if (send_local_message(&xmsg) == 0) {
		spdlog::info("||| VPNINFO sent to wireguard-c daemon thru loopback socket");
		usleep(500000);  /* 0.5 seconds */
	}
}

int WgacClient::send_start_vpn_message(enum AUTOCONN type) {
	int ret = 0;

	ac_message_t xmsg;
	if (type == AUTOCONN::START_VPN) {
		spdlog::info("||| The START_VPN event sent to wireguard-c daemon thru loopback socket");
	} else if (type == AUTOCONN::START_VPN_AGAIN) {
		spdlog::info("||| The START_VPN_AGAIN event sent to wireguard-c daemon thru loopback socket");
	} else {
		spdlog::error("Oops, invalid type value passed.");
		return ret;
	}

	memset(&xmsg, 0, sizeof(ac_message_t));
	xmsg.m.type = type;
	if (send_local_message(&xmsg) == 0) {
		usleep(500000);  /* 0.5 seconds */
	}
	return ret;
}
#endif
