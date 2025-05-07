/*
 * Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
 * Copyright (c) 2019 Elhay Rauper
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <vector>
#include <map>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <functional>
#include <cstring>
#include <errno.h>
#include <iostream>
#include <mutex>
#include "client.h"
#include "server_observer.h"
#include "pipe_ret_t.h"
#include "file_descriptor.h"
#include "message.h"
#include "peer_tbl.h"
#include "configuration.h"

class WgacServer {
public:
	WgacServer();
	~WgacServer();
	pipe_ret_t start(int port, int maxNumOfClients = 5, bool removeDeadClientsAutomatically = true);
	void initializeSocket();
	void bindAddress(int port);
	void listenToClients(int maxNumOfClients);
	std::string acceptClient(uint timeout);
	pipe_ret_t sendToAllClients(const char* msg, size_t size);
	pipe_ret_t sendToClient(const std::string& clientIP, const char* msg, size_t size);

	bool sendMessage(const Client& client, const message_t& smsg);
	bool send_HELLO(const Client& client, const message_t& smsg);
	bool send_PONG(const Client& client, const message_t& smsg);
	bool send_BYE(const Client& client, const message_t& smsg);
	bool send_OK(const Client& client, const message_t& smsg);
	bool send_NOK(const Client& client);

	void setup_wireguard(const message_t& rmsg);
	void remove_wireguard(const message_t& rmsg);

	bool shouldTerminate();
	void setTerminate(bool flag);

	peer_table_t *get_peer_table(const message_t& rmsg);
	bool add_peer_table(const message_t& rmsg);
	bool update_peer_table(const message_t& rmsg);
	bool remove_peer_table(const message_t& rmsg);

	Config& getConf() { return _autoConf; };

	pipe_ret_t close();
	void printClients();

private:
	FileDescriptor _sockfd;
	struct sockaddr_in _serverAddress;
	struct sockaddr_in _clientAddress;
	fd_set _fds;
	std::vector<Client*> _clients;
	std::mutex _clientsMtx;
	std::thread* _clientsRemoverThread = nullptr;
	std::atomic<bool> _stopRemoveClientsTask;

	std::map<std::string, peer_table_t *> peers;
	Config _autoConf;

	bool _flagTerminate;

	void handleClientMsg(const Client& client, const message_t& rmsg);
	void handleClientDisconnected(const std::string&, const message_t& rmsg);

	pipe_ret_t waitForClient(uint32_t timeout);
	void clientEventHandler(const Client&, ClientEvent, const message_t& msg);
	void removeDeadClients();
	void terminateDeadClientsRemover();
	static pipe_ret_t sendToClient(const Client& client, const char* msg, size_t size);
};
