/*
 * Copyright (c) 2025-2026 Chunghan Yi <chunghan.yi@gmail.com>
 * Copyright (c) 2019 Elhay Rauper
 *
 * SPDX-License-Identifier: MIT
 */

#include <functional>
#include <thread>
#include <algorithm>
#include <cstring>
#include "inc/server.h"
#include "inc/message.h"
#include "inc/peer_tbl.h"
#include "inc/vip_pool.h"
#include "inc/configuration.h"
#include "inc/common.h"
#include "inc/vtysh.h"
#include "spdlog/spdlog.h"

WgacServer::WgacServer() {
	_clients.reserve(128);
	_stopRemoveClientsTask = false;
	_flagTerminate = false;
}

WgacServer::~WgacServer() {
	close();
}

void WgacServer::printClients() {
	std::lock_guard<std::mutex> lock(_clientsMtx);
	if (_clients.empty()) {
		std::cout << "no connected clients\n";
	}
	for (const std::shared_ptr<Client> client : _clients) {
		client->print();
	}
}

/**
 * Remove dead clients (disconnected) from clients vector periodically
 */
void WgacServer::removeDeadClients() {
	std::vector<std::shared_ptr<Client>>::const_iterator clientToRemove;
	while (!_stopRemoveClientsTask) {
		{
			std::lock_guard<std::mutex> lock(_clientsMtx);
			do {
				clientToRemove = std::find_if(_clients.begin(), _clients.end(),
						[](auto client) { return !client->isConnected(); });

				if (clientToRemove != _clients.end()) {
					(*clientToRemove)->close();
					std::shared_ptr<Client> t = *clientToRemove;
					t.reset();
					const_cast<std::shared_ptr<Client>&>(*clientToRemove) = nullptr;
					_clients.erase(clientToRemove);
					spdlog::debug("### client is removed in the removeDeadClients thread.");
				}
			} while (clientToRemove != _clients.end());
		}

		sleep(2);
	}
}

void WgacServer::terminateDeadClientsRemover() {
	if (_clientsRemoverThread) {
		_stopRemoveClientsTask = true;
		_clientsRemoverThread->join();
		delete _clientsRemoverThread;
		_clientsRemoverThread = nullptr;
	}
}

/**
 * Handle different client events. Subscriber callbacks should be short and fast, and must not
 * call other server functions to avoid deadlock
 */
void WgacServer::clientEventHandler(const Client& client, ClientEvent event, const message_t& msg) {
	switch (event) {
		case ClientEvent::DISCONNECTED: {
			handleClientDisconnected(client.getIp(), msg);
			break;
		}
		case ClientEvent::INCOMING_MSG: {
			handleClientMsg(client, msg);
			break;
		}
	}
}

#ifndef VTYSH
void WgacServer::init_wireguard() {
	char szInfo[512] = {};
	std::string cmd;
	std::string error_text;
	std::vector<std::string> output_list;
	bool exec_result;

	//TBD: this command should be executed at booting script
	snprintf(szInfo, sizeof(szInfo), "ip link add dev wg0 type wireguard > /dev/null 2>&1");
	cmd = szInfo;
	exec_result = common::exec(cmd, output_list, error_text);
	if (exec_result) {
		spdlog::debug("--- wireguard init [{}]", szInfo);
	} else {
		spdlog::warn("{}", error_text);
	}

	snprintf(szInfo, sizeof(szInfo),
		"ifconfig wg0 %s netmask %s > /dev/null 2>&1",
		configurations.getstr("this_vpn_ip").c_str(), configurations.getstr("this_vpn_netmask").c_str());
	cmd = szInfo;
	exec_result = common::exec(cmd, output_list, error_text);
	if (exec_result) {
		spdlog::debug("--- wireguard init [{}]", szInfo);
	} else {
		spdlog::warn("{}", error_text);
	}

	snprintf(szInfo, sizeof(szInfo), "ip link set up dev wg0");
	cmd = szInfo;
	exec_result = common::exec(cmd, output_list, error_text);
	if (exec_result) {
		spdlog::debug("--- wireguard init [{}]", szInfo);
	} else {
		spdlog::warn("{}", error_text);
	}

	//Note: you must not encrypt the /etc/wgauto/privatekey file
	snprintf(szInfo, sizeof(szInfo),
		"wg set wg0 listen-port %d private-key /etc/wgauto/server_privatekey", configurations.getint("this_endpoint_port"));
	cmd = szInfo;
	exec_result = common::exec(cmd, output_list, error_text);
	if (exec_result) {
		spdlog::debug("--- wireguard init [{}]", szInfo);
	} else {
		spdlog::warn("{}", error_text);
	}
}
#endif

/**
 * Setup wireguard configuration with the wg tool or vtysh.
 */
void WgacServer::setup_wireguard(const message_t& rmsg) {
	char szInfo[512] = {};
	char vpnip_str[32] = {};
	char epip_str[32] = {};

	snprintf(vpnip_str, sizeof(vpnip_str), "%s", inet_ntoa(rmsg.vpnIP));
	snprintf(epip_str, sizeof(epip_str), "%s", inet_ntoa(rmsg.epIP));

#ifdef VTYSH
	snprintf(szInfo, sizeof(szInfo),
			"wg peer %s allowed-ips %s/32 endpoint %s:%d persistent-keepalive 25",
			rmsg.public_key, vpnip_str, epip_str, rmsg.epPort);

	bool ok_flag = vtyshell::runCommand(szInfo);
	if (ok_flag) {
		char xbuf[256];
		sprintf(xbuf, "/usr/bin/qrwg/vtysh -e \"write\"");
		std::system(xbuf);
	}

	spdlog::info("--- wireguard rule [{}]", szInfo);
	spdlog::info("--- OK, wireguard setup is complete.");
#else
	std::string error_text;
	std::vector<std::string> output_list;
	snprintf(szInfo, sizeof(szInfo),
			"wg set wg0 peer %s allowed-ips %s/32 endpoint %s:%d persistent-keepalive 25 &",
			rmsg.public_key, vpnip_str, epip_str, rmsg.epPort);

	std::string cmd(szInfo);
	bool exec_result = common::exec(cmd, output_list, error_text);
	if (exec_result) {
		spdlog::info("--- wireguard rule [{}]", szInfo);
		spdlog::info("--- OK, wireguard setup is complete.");
	} else {
		spdlog::warn("{}", error_text);
	}
#endif
}

/**
 * Remove a wireguard configuration with the wg tool or vtysh.
 */
void WgacServer::remove_wireguard(const uint8_t* public_key) {
	char szInfo[256] = {};

#ifdef VTYSH
	sprintf(szInfo, "no wg peer %s", public_key);

	bool ok_flag = vtyshell::runCommand(szInfo);
	if (ok_flag) {
		char xbuf[256];
		sprintf(xbuf, "/usr/bin/qrwg/vtysh -e \"write\"");
		std::system(xbuf);
	}

	spdlog::info("--- wireguard rule [{}]", szInfo);
	spdlog::info("OK, wireguard rule is removed.");
#else
	std::string error_text;
	std::vector<std::string> output_list;
	snprintf(szInfo, sizeof(szInfo), "wg set wg0 peer %s remove", public_key);

	std::string cmd(szInfo);
	bool exec_result = common::exec(cmd, output_list, error_text);
	if (exec_result) {
		spdlog::info("--- wireguard rule [{}]", szInfo);
		spdlog::info("OK, wireguard rule is removed.");
	} else {
		spdlog::warn("{}", error_text);
	}
#endif
}

/**
 * Handle messages coming from each client(= peer)
 */
void WgacServer::handleClientMsg(const Client& client, const message_t& rmsg) {
	switch (rmsg.type) {
		case AUTOCONN::HELLO:
			spdlog::info(">>> HELLO message received.");
			if (add_peer_table(rmsg)) {
				message_t smsg{};  /* initialize to 0 */
				smsg.type = AUTOCONN::HELLO;
				memcpy(smsg.mac_addr, rmsg.mac_addr, 6);

				if (inet_pton(AF_INET, configurations.getstr("this_vpn_netmask").c_str(), &(smsg.vpnNetmask)) != 1) {
					spdlog::warn("inet_pton(this_vpn_netmask) failed.");
					send_NOK(client);
				} else {
					/* vpn ip allocation(for clients) routine */
					std::shared_ptr<vip_entry_t> vip = viptable.search_address_binding(rmsg);
					if (vip) {
						smsg.vpnIP.s_addr = vip->vpnIP;
						std::string s = inet_ntoa(smsg.vpnNetmask);
						spdlog::info("--- Preparing an used vpnIP({}/{}) for client.",
								inet_ntoa(smsg.vpnIP), s);
						send_HELLO(client, smsg);
					} else {
						vip = viptable.add_address_binding(rmsg);
						if (vip) {
							smsg.vpnIP.s_addr = vip->vpnIP;
							std::string s = inet_ntoa(smsg.vpnNetmask);
							spdlog::info("--- Preparing a new vpnIP({}/{}) for client.",
									inet_ntoa(smsg.vpnIP), s);
							send_HELLO(client, smsg);
						} else {
							spdlog::warn("Can't bind mac address to ip address.");
							send_NOK(client);
						}
					}
				}
			} else {
				send_NOK(client);
			}
			break;

		case AUTOCONN::PING:
			spdlog::info(">>> PING message received.");
			if (update_peer_table(rmsg)) {
				message_t smsg{};
				smsg.type = AUTOCONN::PONG;
				memcpy(smsg.mac_addr, rmsg.mac_addr, 6);
				if (inet_pton(AF_INET, configurations.getstr("this_vpn_ip").c_str(), &(smsg.vpnIP)) != 1) {
					spdlog::warn("inet_pton(this_vpn_ip) failed.");
					send_NOK(client);
				} else {
					if (inet_pton(AF_INET, configurations.getstr("this_vpn_netmask").c_str(),
								&(smsg.vpnNetmask)) != 1) {
						spdlog::warn("inet_pton(this_vpn_netmask) failed.");
						send_NOK(client);
					} else {
						memcpy(smsg.public_key, configurations.getstr("this_public_key").c_str(), WG_KEY_LEN_BASE64);
						if (inet_pton(AF_INET, configurations.getstr("this_endpoint_ip").c_str(),
									&(smsg.epIP)) != 1) {
							spdlog::warn("inet_pton(this_endpoint_ip) failed.");
							send_NOK(client);
						} else {
							smsg.epPort = configurations.getint("this_endpoint_port");
							std::string str = configurations.getstr("this_allowed_ips");
							int len = str.length();
							memset(smsg.allowed_ips, 0, sizeof(smsg.allowed_ips));
							memcpy(smsg.allowed_ips, str.c_str(), len);
							spdlog::debug("--- This Allowed_IPS ----> {}", str);
							send_PONG(client, smsg);
							setup_wireguard(rmsg);
						}
					}
				}
			} else {
				send_NOK(client);
			}
			break;

		case AUTOCONN::BYE:
			spdlog::info(">>> BYE message received.");
			if (remove_peer_table(rmsg)) {
				message_t smsg{};
				smsg.type = AUTOCONN::BYE;
				memcpy(smsg.mac_addr, rmsg.mac_addr, 6);
				memcpy(smsg.public_key, configurations.getstr("this_public_key").c_str(), WG_KEY_LEN_BASE64);
				send_BYE(client, smsg);
#if 1 /* TBD */
				if (viptable.remove_address_binding(rmsg)) {
					spdlog::info(">>> Binding address is removed.");
				}
#endif
				remove_wireguard(rmsg.public_key);
			} else {
				send_NOK(client);
			}
			break;

		default:
			spdlog::info(">>> UNKNOWN message received.");
			send_NOK(client);
			break;
	}
}

void WgacServer::handleClientDisconnected(const std::string& clientIP, const message_t& rmsg) {
}

/**
 * Bind port and start listening
 * Return tcp_ret_t
 */
pipe_ret_t WgacServer::start(unsigned short port, int maxNumOfClients, bool removeDeadClientsAutomatically) {
	if (removeDeadClientsAutomatically) {
		_clientsRemoverThread = new std::thread(&WgacServer::removeDeadClients, this);
	}
	try {
		initializeSocket();
		bindAddress(port);
		listenToClients(maxNumOfClients);
	} catch (const std::runtime_error &error) {
		return pipe_ret_t::failure(error.what());
	}
	return pipe_ret_t::success();
}

void WgacServer::initializeSocket() {
	_sockfd.set(socket(AF_INET, SOCK_STREAM, 0));
	const bool socketFailed = (_sockfd.get() == -1);
	if (socketFailed) {
		throw std::runtime_error(strerror(errno));
	}

	// set socket for reuse (otherwise might have to wait 4 minutes every time socket is closed)
	const int option = 1;
	setsockopt(_sockfd.get(), SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
}

void WgacServer::bindAddress(int port) {
	memset(&_serverAddress, 0, sizeof(_serverAddress));
	_serverAddress.sin_family = AF_INET;
	_serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
	_serverAddress.sin_port = htons(port);

	const int bindResult = bind(_sockfd.get(), (struct sockaddr *)&_serverAddress, sizeof(_serverAddress));
	const bool bindFailed = (bindResult == -1);
	if (bindFailed) {
		throw std::runtime_error(strerror(errno));
	}
}

void WgacServer::listenToClients(int maxNumOfClients) {
	const int clientsQueueSize = maxNumOfClients;
	const bool listenFailed = (listen(_sockfd.get(), clientsQueueSize) == -1);
	if (listenFailed) {
		throw std::runtime_error(strerror(errno));
	}
}

/**
 * Accept and handle new client socket. To handle multiple clients, user must
 * call this function in a loop to enable the acceptance of more than one.
 * If timeout argument equal 0, this function is executed in blocking mode.
 * If timeout argument is > 0 then this function is executed in non-blocking
 * mode (async) and will quit after timeout seconds if no client tried to connect.
 * Return accepted client IP, or throw error if failed
 */
std::string WgacServer::acceptClient(uint timeout) {
	const pipe_ret_t waitingForClient = waitForClient(timeout);
	if (!waitingForClient.isSuccessful()) {
		throw std::runtime_error(waitingForClient.message());
	}

	socklen_t socketSize  = sizeof(_clientAddress);
	const int fileDescriptor = accept(_sockfd.get(), (struct sockaddr*)&_clientAddress, &socketSize);

	const bool acceptFailed = (fileDescriptor == -1);
	if (acceptFailed) {
		throw std::runtime_error(strerror(errno));
	}

	std::shared_ptr<Client> newClient = std::make_shared<Client>(fileDescriptor);
	newClient->setIp(inet_ntoa(_clientAddress.sin_addr));
	using namespace std::placeholders;
	newClient->setEventsHandler(std::bind(&WgacServer::clientEventHandler, this, _1, _2, _3));
	newClient->startListen(); /* receive packets from client */

	std::lock_guard<std::mutex> lock(_clientsMtx);
	_clients.push_back(newClient);

	return newClient->getIp();
}

pipe_ret_t WgacServer::waitForClient(uint32_t timeout) {
	if (timeout > 0) {
		const fd_wait::Result waitResult = fd_wait::waitFor(_sockfd, timeout);
		const bool noIncomingClient = (!FD_ISSET(_sockfd.get(), &_fds));

		if (waitResult == fd_wait::Result::FAILURE) {
			return pipe_ret_t::failure(strerror(errno));
		} else if (waitResult == fd_wait::Result::TIMEOUT) {
			return pipe_ret_t::failure("Timeout waiting for client");
		} else if (noIncomingClient) {
			return pipe_ret_t::failure("File descriptor is not set");
		}
	}

	return pipe_ret_t::success();
}

/**
 * Send message to all connected clients.
 * Return true if message was sent successfully to all clients
 */
pipe_ret_t WgacServer::sendToAllClients(unsigned char* msg, size_t size) {
	std::lock_guard<std::mutex> lock(_clientsMtx);

	for (const auto client : _clients) {
		pipe_ret_t sendingResult = sendToClient(*client, msg, size);
		if (!sendingResult.isSuccessful()) {
			return sendingResult;
		}
	}

	return pipe_ret_t::success();
}

/**
 * Send message to specific client (determined by client IP address).
 * Return true if message was sent successfully
 */
pipe_ret_t WgacServer::sendToClient(const Client& client, unsigned char* msg, size_t size) {
	try {
		client.send(reinterpret_cast<const char*>(msg), size);
	} catch (const std::runtime_error &error) {
		return pipe_ret_t::failure(error.what());
	}

	return pipe_ret_t::success();
}

pipe_ret_t WgacServer::sendToClient(const std::string& clientIP, unsigned char* msg, size_t size) {
	std::lock_guard<std::mutex> lock(_clientsMtx);

	const auto clientIter = std::find_if(_clients.begin(), _clients.end(),
			[&clientIP](auto client) { return client->getIp() == clientIP; });

	if (clientIter == _clients.end()) {
		return pipe_ret_t::failure("client not found");
	}

	const Client& client = *(*clientIter);
	return sendToClient(client, msg, size);
}

/**
 * Send message to specific client (determined by client IP address) with OK or NOK string.
 */
bool WgacServer::sendMessage(const Client& client, const message_t& msg) {
	message_t smsg;
	memcpy(&smsg, &msg, sizeof(message_t));

#ifdef USE_GO_CLIENT /* for wireguard windows client */
	/* Let's convert message_t structure to C++ string */
	/* Golang syntax
	type Message struct {
		Msg_type    string  `cmd:=HELLO\n`
		Mac_addr    string  `macaddr:=00-00-00-00-00-00\n`
		VpnIP       string  `vpnip:=10.1.1.1\n`
		VpnNetmask  string  `vpnnetmask:=255.255.255.0\n`
		Public_key  string  `publickey:=01234567890123456789012345678901234567890123\n`
		EpIp        string  `epip:=192.168.1.1\n`
		EpPort      string  `epport:=51280\n`
		Allowed_ips string  `allowedips:=10.1.1.0/24,192.168.1.0\n
	}
	*/

	std::string total_s, s;
	char buffer[512];

	if (msg.type == AUTOCONN::HELLO)
		total_s = "cmd:=HELLO\n";
	else if (msg.type == AUTOCONN::PING)
		total_s = "cmd:=PING\n";
	else if (msg.type == AUTOCONN::PONG)
		total_s = "cmd:=PONG\n";
	else if (msg.type == AUTOCONN::OK)
		total_s = "cmd:=OK\n";
	else if (msg.type == AUTOCONN::NOK)
		total_s = "cmd:=NOK\n";
	else if (msg.type == AUTOCONN::BYE)
		total_s = "cmd:=BYE\n";
	else
		total_s = "cmd:=NOK\n";

	snprintf(buffer, sizeof(buffer), "macaddr:=%02X-%02X-%02X-%02X-%02X-%02X\n",
			msg.mac_addr[0], msg.mac_addr[1], msg.mac_addr[2],
			msg.mac_addr[3], msg.mac_addr[4], msg.mac_addr[5]);
	s = buffer;
	total_s += s;

	snprintf(buffer, sizeof(buffer), "vpnip:=%s\n", inet_ntoa(msg.vpnIP));
	s = buffer;
	total_s += s;

	snprintf(buffer, sizeof(buffer), "vpnnetmask:=%s\n", inet_ntoa(msg.vpnNetmask));
	s = buffer;
	total_s += s;

	std::string pubkey(reinterpret_cast<const char*>(msg.public_key));
	total_s = total_s + "publickey:=" + pubkey + "\n";

	snprintf(buffer, sizeof(buffer), "epip:=%s\n", inet_ntoa(msg.epIP));
	s = buffer;
	total_s += s;

	snprintf(buffer, sizeof(buffer), "epport:=%d\n", msg.epPort);
	s = buffer;
	total_s += s;

	std::string allowed(reinterpret_cast<const char*>(msg.allowed_ips));
	total_s = total_s + "allowedips:=" + allowed + "\n";

#if 0
	std::cout << "total_s --------> [" << total_s << "]" << std::endl;
	std::cout << "length --------> [" << total_s.length() << "]" << std::endl;
#endif

	const char* buf_ptr = total_s.c_str();

	try {
		client.send(buf_ptr, total_s.length());
	} catch (const std::runtime_error &error) {
		spdlog::info("<<< Oops message sending is failed.");
		return false;
	}
#else
	try {
		client.send(reinterpret_cast<const char *>(&smsg), sizeof(smsg));
	} catch (const std::runtime_error &error) {
		spdlog::info("<<< Oops message sending is failed.");
		return false;
	}
#endif

	return true;
}

bool WgacServer::send_HELLO(const Client& client, const message_t& smsg) {
	spdlog::info("<<< HELLO message sent to client.");
	return sendMessage(client, smsg);
}

bool WgacServer::send_OK(const Client& client, const message_t& smsg) {
	spdlog::info("<<< OK message sent to client.");
	return sendMessage(client, smsg);
}

bool WgacServer::send_NOK(const Client& client) {
	spdlog::info("<<< NOK message sent to client.");
	message_t smsg{};
	return sendMessage(client, smsg);
}

bool WgacServer::send_PONG(const Client& client, const message_t& smsg) {
	spdlog::info("<<< PONG message sent to client.");
	return sendMessage(client, smsg);
}

bool WgacServer::send_BYE(const Client& client, const message_t& smsg) {
	spdlog::info("<<< BYE message sent to client.");
	return sendMessage(client, smsg);
}

/**
 * Get a flag value to terminiate program.
 */
bool WgacServer::shouldTerminate() {
	return _flagTerminate;
}

/**
 * Set a flag value to terminiate program.
 */
void WgacServer::setTerminate(bool flag) {
	_flagTerminate = flag;
}

/**
 * Close server and clients resources.
 * Return true is successFlag, false otherwise
 */
pipe_ret_t WgacServer::close() {
	terminateDeadClientsRemover();
	{ // close clients
		std::lock_guard<std::mutex> lock(_clientsMtx);

		for (auto client : _clients) {
			try {
				client->close();
			} catch (const std::runtime_error& error) {
				return pipe_ret_t::failure(error.what());
			}
		}
		_clients.clear();
	}

	{ // close server
		const int closeServerResult = ::close(_sockfd.get());
		const bool closeServerFailed = (closeServerResult == -1);
		if (closeServerFailed) {
			return pipe_ret_t::failure(strerror(errno));
		}
	}

	return pipe_ret_t::success();
}
