/*
 * Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
 * Copyright (c) 2019 Elhay Rauper
 *
 * SPDX-License-Identifier: MIT
 */

#include "inc/client.h"
#include "inc/common.h"

WgacClient::WgacClient() {
	_isConnected = false;
	_isClosed = true;
}

WgacClient::~WgacClient() {
	close();
}

pipe_ret_t WgacClient::connectTo(const std::string& address, int port) {
	try {
		initializeSocket();
		setAddress(address, port);
	} catch (const std::runtime_error& error) {
		return pipe_ret_t::failure(error.what());
	}

	const int connectResult = connect(_sockfd.get(), (struct sockaddr *)&_server, sizeof(_server));
	const bool connectionFailed = (connectResult == -1);
	if (connectionFailed) {
		return pipe_ret_t::failure(strerror(errno));
	}

	startReceivingMessages();
	_isConnected = true;
	_isClosed = false;

	return pipe_ret_t::success();
}

void WgacClient::startReceivingMessages() {
	_receiveTask = new std::thread(&WgacClient::receiveTask, this);
}

void WgacClient::initializeSocket() {
	pipe_ret_t ret;

	_sockfd.set(socket(AF_INET, SOCK_STREAM, 0));
	const bool socketFailed = (_sockfd.get() == -1);
	if (socketFailed) {
		throw std::runtime_error(strerror(errno));
	}
}

void WgacClient::setAddress(const std::string& address, int port) {
	const int inetSuccess = inet_aton(address.c_str(), &_server.sin_addr);

	if (!inetSuccess) { // inet_addr failed to parse address
                        // if hostname is not in IP strings and dots format, try resolve it
		struct hostent *host;
		struct in_addr **addrList;
		if ((host = gethostbyname(address.c_str())) == nullptr) {
			throw std::runtime_error("Failed to resolve hostname");
		}
		addrList = (struct in_addr **) host->h_addr_list;
		_server.sin_addr = *addrList[0];
	}
	_server.sin_family = AF_INET;
	_server.sin_port = htons(port);
}

pipe_ret_t WgacClient::sendMsg(const char* msg, size_t size) {
	const size_t numBytesSent = send(_sockfd.get(), msg, size, 0);

	if (numBytesSent < 0) { // send failed
		return pipe_ret_t::failure(strerror(errno));
	}
	if (numBytesSent < size) { // not all bytes were sent
		char errorMsg[100];
		sprintf(errorMsg, "Only %lu bytes out of %lu was sent to client", numBytesSent, size);
		return pipe_ret_t::failure(errorMsg);
	}
	return pipe_ret_t::success();
}

/*
 * Receive server packets, and notify user
 */
void WgacClient::receiveTask() {
	while(_isConnected) {
		const fd_wait::Result waitResult = fd_wait::waitFor(_sockfd);

		if (waitResult == fd_wait::Result::FAILURE) {
			throw std::runtime_error(strerror(errno));
		} else if (waitResult == fd_wait::Result::TIMEOUT) {
			continue;
		}

		message_t rmsg;
		const size_t numOfBytesReceived = recv(_sockfd.get(), &rmsg, sizeof(rmsg), 0);

		if (numOfBytesReceived < 1) {
			std::string errorMsg;
			if (numOfBytesReceived == 0) { //server closed connection
				errorMsg = "Server closed connection";
			} else {
				errorMsg = strerror(errno);
			}
			_isConnected = false;
			return;
		} else {
			/* Let's put this message to <message queue>. */
			_msgQueue.push(rmsg);
		}
	}
}

void WgacClient::terminateReceiveThread() {
	_isConnected = false;

	if (_receiveTask) {
		_receiveTask->join();
		delete _receiveTask;
		_receiveTask = nullptr;
	}
}

pipe_ret_t WgacClient::close() {
	if (_isClosed) {
		return pipe_ret_t::failure("client is already closed");
	}
	terminateReceiveThread();

	const bool closeFailed = (::close(_sockfd.get()) == -1);
	if (closeFailed) {
		return pipe_ret_t::failure(strerror(errno));
	}
	_isClosed = true;
	return pipe_ret_t::success();
}
