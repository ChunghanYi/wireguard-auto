/*
 * Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
 * Copyright (c) 2019 Elhay Rauper
 *
 * SPDX-License-Identifier: MIT
 */

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <stdexcept>
#include <sys/socket.h>
#include <iostream>
#include "inc/client.h"
#include "inc/common.h"
#include "inc/message.h"
#include "inc/sodium_aead.h"

namespace sodium_aead
{
    extern std::vector<unsigned char> client_public_key;
    extern std::vector<unsigned char> server_secret_key;
}

Client::Client(int fileDescriptor) {
	_sockfd.set(fileDescriptor);
	setConnected(false);
}

bool Client::operator==(const Client& other) const {
	if ((this->_sockfd.get() == other._sockfd.get()) && (this->_ip == other._ip)) {
		return true;
	}
	return false;
}

void Client::startListen() {
	setConnected(true);
	_receiveThread = new std::thread(&Client::receiveTask, this);
}

#ifdef NO_AEAD_METHOD
void Client::send(const char* msg, size_t msgSize) const {
	const size_t numBytesSent = ::send(_sockfd.get(), (char *)msg, msgSize, 0);

	const bool sendFailed = (numBytesSent < 0);
	if (sendFailed) {
		throw std::runtime_error(strerror(errno));
	}

	const bool notAllBytesWereSent = (numBytesSent < msgSize);
	if (notAllBytesWereSent) {
		char errorMsg[100];
		sprintf(errorMsg, "Only %lu bytes out of %lu was sent to client", numBytesSent, msgSize);
		throw std::runtime_error(errorMsg);
	}
}

/**
 * Receive client packets, and notify user
 */
void Client::receiveTask() {
	while (isConnected()) {
		const fd_wait::Result waitResult = fd_wait::waitFor(_sockfd);

		if (waitResult == fd_wait::Result::FAILURE) {
			throw std::runtime_error(strerror(errno));
		} else if (waitResult == fd_wait::Result::TIMEOUT) {
			continue;
		}

		message_t rmsg;
		const size_t numOfBytesReceived = recv(_sockfd.get(), &rmsg, sizeof(rmsg), 0);

		if (numOfBytesReceived < 1) {
			const bool clientClosedConnection = (numOfBytesReceived == 0);
			if (clientClosedConnection) {
				rmsg.type = AUTOCONN::OK;
			} else {
				rmsg.type = AUTOCONN::NOK;
			}
			setConnected(false);
			publishEvent(ClientEvent::DISCONNECTED, rmsg);
			return;
		} else {
			publishEvent(ClientEvent::INCOMING_MSG, rmsg);
		}
	}
}
#else /* AEAD method */
void Client::send(unsigned char* msg, size_t msgSize) const {
	std::vector<unsigned char> original_message(msg, msg + msgSize);
	std::vector<unsigned char> encrypted_message = sodium_aead::encrypt_message(original_message,
			sodium_aead::client_public_key, sodium_aead::server_secret_key);

	const size_t numBytesSent = ::send(_sockfd.get(), encrypted_message.data(), encrypted_message.size(), 0);

	const bool sendFailed = (numBytesSent < 0);
	if (sendFailed) {
		throw std::runtime_error(strerror(errno));
	}

	const bool notAllBytesWereSent = (numBytesSent < encrypted_message.size());
	if (notAllBytesWereSent) {
		char errorMsg[100];
		sprintf(errorMsg, "Only %lu bytes out of %lu was sent to client", numBytesSent, encrypted_message.size());
		throw std::runtime_error(errorMsg);
	}
}

/**
 * Receive client packets, and notify user
 */
void Client::receiveTask() {
	while (isConnected()) {
		const fd_wait::Result waitResult = fd_wait::waitFor(_sockfd);

		if (waitResult == fd_wait::Result::FAILURE) {
			throw std::runtime_error(strerror(errno));
		} else if (waitResult == fd_wait::Result::TIMEOUT) {
			continue;
		}

		message_t rmsg;
		unsigned char rxbuffer[ENC_MESSAGE_SIZE];
		const size_t numOfBytesReceived = recv(_sockfd.get(), rxbuffer, sizeof(rxbuffer), 0);

		if (numOfBytesReceived < 1) {
			const bool clientClosedConnection = (numOfBytesReceived == 0);
			if (clientClosedConnection) {
				rmsg.type = AUTOCONN::OK;
			} else {
				rmsg.type = AUTOCONN::NOK;
			}
			setConnected(false);
			publishEvent(ClientEvent::DISCONNECTED, rmsg);
			return;
		} else {
			std::vector<unsigned char> encrypted_message(rxbuffer, rxbuffer + numOfBytesReceived);
			std::vector<unsigned char> decrypted_message = sodium_aead::decrypt_message(
					encrypted_message, sodium_aead::client_public_key, sodium_aead::server_secret_key);
			memcpy(&rmsg, decrypted_message.data(), sizeof(rmsg));  //TBD: w/o memcpy

			publishEvent(ClientEvent::INCOMING_MSG, rmsg);
		}
	}
}
#endif

/**
 * Send a reply message to client
 */
void Client::publishEvent(ClientEvent clientEvent, const message_t& msg) {
	_eventHandlerCallback(*this, clientEvent, msg);
}

void Client::print() const {
	const std::string connected = isConnected() ? "True" : "False";
	std::cout << "-----------------\n" <<
		"IP address: " << getIp() << std::endl <<
		"Connected?: " << connected << std::endl <<
		"Socket FD: " << _sockfd.get() << std::endl;
}

void Client::terminateReceiveThread() {
	setConnected(false);
	if (_receiveThread) {
		_receiveThread->join();
		delete _receiveThread;
		_receiveThread = nullptr;
	}
}

void Client::close() {
	terminateReceiveThread();

	const bool closeFailed = (::close(_sockfd.get()) == -1);
	if (closeFailed) {
		throw std::runtime_error(strerror(errno));
	}
}
