/*
 * Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
 * Copyright (c) 2019 Elhay Rauper
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <vector>
#include <queue>
#include <errno.h>
#include <thread>
#include <mutex>
#include <atomic>
#include "client_observer.h"
#include "pipe_ret_t.h"
#include "file_descriptor.h"
#include "message.h"
#include "configuration.h"

class WgacClient {
public:
	WgacClient();
	~WgacClient();
	pipe_ret_t connectTo(const std::string& address, int port);
	pipe_ret_t sendMsg(unsigned char* msg, size_t size);

	void start();
	bool handle_message_queue(message_t* pmsg);
	bool send_hello_message();
	bool send_ping_message(message_t* pmsg);
	bool send_bye_message();

	void setup_wireguard(message_t* rmsg);
	void remove_wireguard(message_t* rmsg);

	Config& getConf() { return _autoConf; };

	bool isConnected() const { return _isConnected; }
	pipe_ret_t close();

private:
	FileDescriptor _sockfd;
	std::atomic<bool> _isConnected;
	std::atomic<bool> _isClosed;
	struct sockaddr_in _server;
	std::thread* _receiveTask = nullptr;

	std::queue<message_t> _msgQueue;
	Config _autoConf;
	bool _flagTerminate = false;

	void initializeSocket();
	void startReceivingMessages();
	void setAddress(const std::string& address, int port);
	void receiveTask();
	void terminateReceiveThread();
};
