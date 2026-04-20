/*
 * Copyright (c) 2025-2026 Chunghan Yi <chunghan.yi@gmail.com>
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
	using client_event_handler_t = std::function<void(Client&, ClientEvent, const message_t&)>;

public:
	Client(int);
	bool operator ==(const Client& other) const ;
	void setIp(const std::string& ip) { _ip = ip; }
	std::string getIp() const { return _ip; }
	void setEventsHandler(const client_event_handler_t& eventHandler) { _eventHandlerCallback = eventHandler; }
	void publishEvent(ClientEvent clientEvent, const message_t& msg);
	bool isConnected() const { return _isConnected; }
	void setConnected(bool flag) { _isConnected = flag; }

	/* for <PREPARE> stage */
	const std::vector<unsigned char>& getPreparePublicKey() const { return _prepare_public_key; }
	void setPreparePublicKey(uint8_t* key) {
		_prepare_public_key.assign(key, key + WG_KEY_LEN);
	}

	void startListen();
	void send(const char* msg, size_t msg_len) const;
	void close();
	void print() const;

private:
	void receiveTask();
	void terminateReceiveThread();

	FileDescriptor _sockfd;
	std::string _ip = "";
	std::atomic<bool> _isConnected;
#ifdef LEGACY_CODE
	std::thread* _receiveThread = nullptr;
#else
	std::unique_ptr<std::thread> _receiveThread;
#endif
	client_event_handler_t _eventHandlerCallback;

	/* for <PREPARE> stage */
	std::vector<unsigned char> _prepare_public_key;
};
