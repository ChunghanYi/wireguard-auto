/*
 * Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
 * Copyright (c) 2019 Elhay Rauper
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <string>
#include <thread>
#include <functional>
#include <mutex>
#include <atomic>

#include "pipe_ret_t.h"
#include "client_event.h"
#include "file_descriptor.h"
#include "message.h"

class Client {
	using client_event_handler_t = std::function<void(const Client&, ClientEvent, const message_t&)>;

public:
	Client(int);
	bool operator ==(const Client& other) const ;
	void setIp(const std::string& ip) { _ip = ip; }
	std::string getIp() const { return _ip; }
	void setEventsHandler(const client_event_handler_t& eventHandler) { _eventHandlerCallback = eventHandler; }
	void publishEvent(ClientEvent clientEvent, const message_t& msg);
	bool isConnected() const { return _isConnected; }
	void startListen();
	void send(unsigned char* msg, size_t msgSize) const;
	void close();
	void print() const;

private:
	FileDescriptor _sockfd;
	std::string _ip = "";
	std::atomic<bool> _isConnected;
	std::thread* _receiveThread = nullptr;
	client_event_handler_t _eventHandlerCallback;

	void setConnected(bool flag) { _isConnected = flag; }
	void receiveTask();
	void terminateReceiveThread();
};
