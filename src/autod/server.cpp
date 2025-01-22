/*
 * Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
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
#include "inc/configuration.h"
#include "inc/common.h"
#include "spdlog/spdlog.h"

WacServer::WacServer() {
	_clients.reserve(10);
	_stopRemoveClientsTask = false;
	_flagTerminate = false;
}

WacServer::~WacServer() {
	close();
}

void WacServer::printClients() {
	std::lock_guard<std::mutex> lock(_clientsMtx);
	if (_clients.empty()) {
		std::cout << "no connected clients\n";
	}
	for (const Client *client : _clients) {
		client->print();
	}
}

/**
 * Remove dead clients (disconnected) from clients vector periodically
 */
void WacServer::removeDeadClients() {
	std::vector<Client*>::const_iterator clientToRemove;
	while (!_stopRemoveClientsTask) {
		{
			std::lock_guard<std::mutex> lock(_clientsMtx);
			do {
				clientToRemove = std::find_if(_clients.begin(), _clients.end(),
						[](Client *client) { return !client->isConnected(); });

				if (clientToRemove != _clients.end()) {
					(*clientToRemove)->close();
					delete *clientToRemove;
					_clients.erase(clientToRemove);
					spdlog::debug("### client is removed in the removeDeadClients thread.");
				}
			} while (clientToRemove != _clients.end());
		}

		sleep(2);
	}
}

void WacServer::terminateDeadClientsRemover() {
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
void WacServer::clientEventHandler(const Client& client, ClientEvent event, const message_t& msg) {
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

/*
 * Setup wireguard configuration with the wg tool or vtysh.
 */
void WacServer::setup_wireguard(const message_t& rmsg) {
	char szInfo[512] = {};
	char vpnip_str[32] = {};
	char epip_str[32] = {};

	snprintf(vpnip_str, sizeof(vpnip_str), "%s", inet_ntoa(rmsg.vpnIP));
	snprintf(epip_str, sizeof(epip_str), "%s", inet_ntoa(rmsg.epIP));

#ifdef VTYSH
	snprintf(szInfo, sizeof(szInfo),
			"wg peer %s allowed-ips %s/32 endpoint %s:%d persistent-keepalive 25",
			rmsg.public_key, vpnip_str, epip_str, rmsg.epPort);

	bool ok_flag = runCommand(szInfo);
	if (ok_flag) {
		char xbuf[256];
		sprintf(xbuf, "/usr/bin/qrwg/vtysh -e \"write\"");
		system(xbuf);
	}
#else
	snprintf(szInfo, sizeof(szInfo),
			"wg set wg0 peer %s allowed-ips %s/32 endpoint %s:%d persistent-keepalive 25 &",
			rmsg.public_key, vpnip_str, epip_str, rmsg.epPort);
	system(szInfo);
#endif

	spdlog::info("szInfo -----> [{}]", szInfo);
	spdlog::info("OK, wireguard setup is complete.");
}

/*
 * Remove a wireguard configuration with the wg tool or vtysh.
 */
void WacServer::remove_wireguard(const message_t& rmsg) {
	char szInfo[256] = {};

#ifdef VTYSH
	sprintf(szInfo, "no wg peer %s", rmsg.public_key);

	bool ok_flag = runCommand(szInfo);
	if (ok_flag) {
		char xbuf[256];
		sprintf(xbuf, "/usr/bin/qrwg/vtysh -e \"write\"");
		system(xbuf);
	}
#else
	snprintf(szInfo, sizeof(szInfo), "wg set wg0 peer %s remove", rmsg.public_key);
	system(szInfo);
#endif

	spdlog::info("szInfo -----> [{}]", szInfo);
	spdlog::info("OK, wireguard rule is removed.");
}

/*
 * Handle messages come from each client
 */
void WacServer::handleClientMsg(const Client& client, const message_t& rmsg) {
	switch (rmsg.type) {
		case AUTOCONN::HELLO:
			spdlog::info(">>> HELLO message received.");
			if (add_peer_table(rmsg)) {
				message_t smsg;
				smsg.type = AUTOCONN::HELLO;
				memcpy(smsg.mac_addr, rmsg.mac_addr, 6);

				/* TODO: vpn ip allocation routine */
				if (inet_pton(AF_INET, _autoConf.getstr("that_vpn_ip").c_str(), &(smsg.vpnIP)) != 1) {
					spdlog::warn("inet_pton(that_vpn_ip) failed.");
				}
				if (inet_pton(AF_INET, _autoConf.getstr("that_vpn_netmask").c_str(), &(smsg.vpnNetmask)) != 1) {
					spdlog::warn("inet_pton(that_vpn_netmask) failed.");
				}

				send_HELLO(client, smsg);
			} else {
				send_NOK(client);
			}
			break;

		case AUTOCONN::PING:
			spdlog::info(">>> PING message received.");
			if (update_peer_table(rmsg)) {
				message_t smsg;
				smsg.type = AUTOCONN::PONG;
				memcpy(smsg.mac_addr, rmsg.mac_addr, 6);
				if (inet_pton(AF_INET, _autoConf.getstr("this_vpn_ip").c_str(), &(smsg.vpnIP)) != 1) {
					spdlog::warn("inet_pton(this_vpn_ip) failed.");
				}
				if (inet_pton(AF_INET, _autoConf.getstr("this_vpn_netmask").c_str(), &(smsg.vpnNetmask)) != 1) {
					spdlog::warn("inet_pton(this_vpn_netmask) failed.");
				}
				memcpy(smsg.public_key, _autoConf.getstr("this_public_key").c_str(), WG_KEY_LEN_BASE64);
				if (inet_pton(AF_INET, _autoConf.getstr("this_endpoint_ip").c_str(), &(smsg.epIP)) != 1) {
					spdlog::warn("inet_pton(this_endpoint_ip) failed.");
				}
				smsg.epPort = _autoConf.getint("this_endpoint_port");
				memcpy(smsg.allowed_ips, _autoConf.getstr("this_allowed_ips").c_str(), 256);

				send_PONG(client, smsg);

				setup_wireguard(rmsg);
			} else {
				send_NOK(client);
			}
			break;

		case AUTOCONN::BYE:
			spdlog::info(">>> BYE message received.");
			if (remove_peer_table(rmsg)) {
				message_t smsg;
				smsg.type = AUTOCONN::BYE;
				memcpy(smsg.mac_addr, rmsg.mac_addr, 6);
				send_BYE(client, smsg);
				remove_wireguard(rmsg);
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

void WacServer::handleClientDisconnected(const std::string& clientIP, const message_t& rmsg) {
}

/*
 * Bind port and start listening
 * Return tcp_ret_t
 */
pipe_ret_t WacServer::start(int port, int maxNumOfClients, bool removeDeadClientsAutomatically) {
	if (removeDeadClientsAutomatically) {
		_clientsRemoverThread = new std::thread(&WacServer::removeDeadClients, this);
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

void WacServer::initializeSocket() {
	_sockfd.set(socket(AF_INET, SOCK_STREAM, 0));
	const bool socketFailed = (_sockfd.get() == -1);
	if (socketFailed) {
		throw std::runtime_error(strerror(errno));
	}

	// set socket for reuse (otherwise might have to wait 4 minutes every time socket is closed)
	const int option = 1;
	setsockopt(_sockfd.get(), SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
}

void WacServer::bindAddress(int port) {
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

void WacServer::listenToClients(int maxNumOfClients) {
	const int clientsQueueSize = maxNumOfClients;
	const bool listenFailed = (listen(_sockfd.get(), clientsQueueSize) == -1);
	if (listenFailed) {
		throw std::runtime_error(strerror(errno));
	}
}

/*
 * Accept and handle new client socket. To handle multiple clients, user must
 * call this function in a loop to enable the acceptance of more than one.
 * If timeout argument equal 0, this function is executed in blocking mode.
 * If timeout argument is > 0 then this function is executed in non-blocking
 * mode (async) and will quit after timeout seconds if no client tried to connect.
 * Return accepted client IP, or throw error if failed
 */
std::string WacServer::acceptClient(uint timeout) {
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

	auto newClient = new Client(fileDescriptor);
	newClient->setIp(inet_ntoa(_clientAddress.sin_addr));
	using namespace std::placeholders;
	newClient->setEventsHandler(std::bind(&WacServer::clientEventHandler, this, _1, _2, _3));
	newClient->startListen(); /* receive packets from client */

	std::lock_guard<std::mutex> lock(_clientsMtx);
	_clients.push_back(newClient);

	return newClient->getIp();
}

pipe_ret_t WacServer::waitForClient(uint32_t timeout) {
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

/*
 * Send message to all connected clients.
 * Return true if message was sent successfully to all clients
 */
pipe_ret_t WacServer::sendToAllClients(const char* msg, size_t size) {
	std::lock_guard<std::mutex> lock(_clientsMtx);

	for (const Client *client : _clients) {
		pipe_ret_t sendingResult = sendToClient(*client, msg, size);
		if (!sendingResult.isSuccessful()) {
			return sendingResult;
		}
	}

	return pipe_ret_t::success();
}

/*
 * Send message to specific client (determined by client IP address).
 * Return true if message was sent successfully
 */
pipe_ret_t WacServer::sendToClient(const Client& client, const char* msg, size_t size) {
	try {
		client.send(msg, size);
	} catch (const std::runtime_error &error) {
		return pipe_ret_t::failure(error.what());
	}

	return pipe_ret_t::success();
}

pipe_ret_t WacServer::sendToClient(const std::string& clientIP, const char* msg, size_t size) {
	std::lock_guard<std::mutex> lock(_clientsMtx);

	const auto clientIter = std::find_if(_clients.begin(), _clients.end(),
			[&clientIP](Client *client) { return client->getIp() == clientIP; });

	if (clientIter == _clients.end()) {
		return pipe_ret_t::failure("client not found");
	}

	const Client &client = *(*clientIter);
	return sendToClient(client, msg, size);
}

/*
 * Send message to specific client (determined by client IP address) with OK or NOK string.
 */
bool WacServer::sendMessage(const Client& client, const message_t& msg) {
	message_t smsg;
	memcpy(&smsg, &msg, sizeof(message_t));

	try {
		client.send(reinterpret_cast<char *>(&smsg), sizeof(smsg));
	} catch (const std::runtime_error &error) {
		spdlog::info("<<< Oops message sending is failed.");
		return false;
	}
	return true;
}

bool WacServer::send_HELLO(const Client& client, const message_t& smsg) {
	spdlog::info("<<< HELLO message sent to client.");
	return sendMessage(client, smsg);
}

bool WacServer::send_OK(const Client& client, const message_t& smsg) {
	spdlog::info("<<< OK message sent to client.");
	return sendMessage(client, smsg);
}

bool WacServer::send_NOK(const Client& client) {
	spdlog::info("<<< NOK message sent to client.");
	message_t smsg;
	return sendMessage(client, smsg);
}

bool WacServer::send_PONG(const Client& client, const message_t& smsg) {
	spdlog::info("<<< PONG message sent to client.");
	return sendMessage(client, smsg);
}

bool WacServer::send_BYE(const Client& client, const message_t& smsg) {
	spdlog::info("<<< BYE message sent to client.");
	return sendMessage(client, smsg);
}

/*
 * Get a flag value to terminiate program.
 */
bool WacServer::shouldTerminate() {
	return _flagTerminate;
}

/*
 * Set a flag value to terminiate program.
 */
void WacServer::setTerminate(bool flag) {
	_flagTerminate = flag;
}

/*
 * Close server and clients resources.
 * Return true is successFlag, false otherwise
 */
pipe_ret_t WacServer::close() {
	terminateDeadClientsRemover();
	{ // close clients
		std::lock_guard<std::mutex> lock(_clientsMtx);

		for (Client *client : _clients) {
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
