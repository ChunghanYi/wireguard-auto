/*
 * Copyright (c) 2025-2026 Chunghan Yi <chunghan.yi@gmail.com>
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
#include "inc/server.h"
#include "inc/client.h"
#include "inc/common.h"
#include "inc/message.h"
#include "inc/sodium_ae.h"
#ifdef USE_GO_CLIENT
#include "inc/parser.h"
#endif

//#define DEBUG

Client::Client(int fileDescriptor) {
	_sockfd.set(fileDescriptor);
	setConnected(false);
	_prepare_public_key.resize(32, 0);  /* client public key for PREPARE stage */
}

bool Client::operator==(const Client& other) const {
	if ((this->_sockfd.get() == other._sockfd.get()) && (this->_ip == other._ip)) {
		return true;
	}
	return false;
}

void Client::startListen() {
	setConnected(true);
#ifdef LEGACY_CODE
	_receiveThread = new std::thread(&Client::receiveTask, this);
#else
	auto _receiveThread = std::make_unique<std::thread>(&Client::receiveTask, this);
	_receiveThread->detach();
#endif
}

#ifdef NO_AUTHENTICATED_ENCRYPTION_METHOD
void Client::send(const char* msg, size_t msgSize) const {
	const size_t numBytesSent = ::send(_sockfd.get(), (const char *)msg, msgSize, 0);

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

#ifdef USE_GO_CLIENT /* for wireguard windows client */
		message_t rmsg;
		char rbuf[1024];
		const size_t numOfBytesReceived = recv(_sockfd.get(), rbuf, sizeof(rbuf), 0);
		parser::parse_Go_message_string(rbuf, &rmsg);
#else
		message_t rmsg;
		const size_t numOfBytesReceived = recv(_sockfd.get(), &rmsg, sizeof(rmsg), 0);
#endif

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
#else /* AE(Authenticated Encryption) method that has <PREPARE> stage additionally. */
void Client::send(const char* msg, size_t msgSize) const {
	if (!isPrepared()) { /* PREPARE stage */
#ifdef DEBUG
		std::cout << "(Client::send) isPrepared() is false !!!\n";
#endif

		const size_t numBytesSent = ::send(_sockfd.get(), (const char *)msg, msgSize, 0);
		const bool sendFailed = (numBytesSent < 0);
		if (sendFailed) {
			std::cout << "(Client::send) send failed#1.\n";
			return;
		}

		const bool notAllBytesWereSent = (numBytesSent < msgSize);
		if (notAllBytesWereSent) {
#if 0
			char errorMsg[100];
			sprintf(errorMsg, "Only %lu bytes out of %lu was sent to client", numBytesSent, msgSize);
			throw std::runtime_error(errorMsg);
#else
			std::cout << "(Client::send) send failed#2.\n";
			return;
#endif
		}
	} else { /* PING-PONG protocol stage */
#ifdef DEBUG
		std::cout << "(Client::send) isPrepared() is true !!!\n";
#endif
		std::vector<unsigned char> original_message(msg, msg + msgSize);
		std::vector<unsigned char> encrypted_message = sodium_ae::encrypt_message(original_message,
				getPreparePublicKey(), wgacsPtr->getPrepareSecretKey());

		const size_t numBytesSent = ::send(_sockfd.get(), encrypted_message.data(), encrypted_message.size(), 0);

		const bool sendFailed = (numBytesSent < 0);
		if (sendFailed) {
			std::cout << "(Client::send) send failed#3.\n";
			return;
		}

		const bool notAllBytesWereSent = (numBytesSent < encrypted_message.size());
		if (notAllBytesWereSent) {
#if 0
			char errorMsg[100];
			sprintf(errorMsg, "Only %lu bytes out of %lu was sent to client", numBytesSent, encrypted_message.size());
			throw std::runtime_error(errorMsg);
#else
			std::cout << "(Client::send) send failed#4.\n";
			return;
#endif
		}
	}
}

/**
 * Receive client packets, and notify user
 */
void Client::receiveTask() {
	while (isConnected()) {
		const fd_wait::Result waitResult = fd_wait::waitFor(_sockfd);

		if (waitResult == fd_wait::Result::FAILURE) {
			setConnected(false);
			return;
		} else if (waitResult == fd_wait::Result::TIMEOUT) {
			continue;
		}

		if (!isPrepared()) { /* PREPARE stage */
#ifdef DEBUG
			std::cout << "(Client::receiveTask) isPrepared() is false !!!\n";
#endif

#ifdef USE_GO_CLIENT /* for wireguard windows client */
			message_t rmsg;
			char rbuf[1024];
			const size_t numOfBytesReceived = recv(_sockfd.get(), rbuf, sizeof(rbuf), 0);
			parser::parse_Go_message_string(rbuf, &rmsg);
#else
			message_t rmsg;
			const size_t numOfBytesReceived = recv(_sockfd.get(), &rmsg, sizeof(rmsg), 0);
#endif
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
		} else { /* PING-PONG protocol stage */
#ifdef DEBUG
			std::cout << "(Client::receiveTask) isPrepared() is true !!!\n";
#endif
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
				bool decrypt_failure = false;
				std::vector<unsigned char> encrypted_message(rxbuffer, rxbuffer + numOfBytesReceived);
				std::vector<unsigned char> decrypted_message = sodium_ae::decrypt_message(
						encrypted_message, getPreparePublicKey(), wgacsPtr->getPrepareSecretKey(),
						decrypt_failure);
				if (!decrypt_failure) {
					memcpy(&rmsg, decrypted_message.data(), sizeof(rmsg));  //TBD: w/o memcpy
					publishEvent(ClientEvent::INCOMING_MSG, rmsg);
				} else {
					message_t smsg{};
					smsg.type = AUTOCONN::BYE;
					memcpy(smsg.mac_addr, rmsg.mac_addr, 6);
					memcpy(smsg.public_key,
							wgacsPtr->getConfig().getstr("this_public_key").c_str(), WG_KEY_LEN_BASE64);
					wgacsPtr->send_BYE(*this, smsg);

					setConnected(false);
				}
			}
		}
	}
}
#endif

/**
 * Send a reply message to client
 */
void Client::publishEvent(ClientEvent clientEvent, const message_t& msg) {
	/*
	 * client.h:
	 *   using client_event_handler_t = std::function<void(const Client&, ClientEvent, const message_t&)>;
	 *   void setEventsHandler(const client_event_handler_t& eventHandler) { _eventHandlerCallback = eventHandler; }
	 * ------------
	 * server.cpp:
	 *   newClient->setEventsHandler(std::bind(&WgacServer::clientEventHandler, this, _1, _2, _3));
	 * ------------
	 *
	 * _eventHandlerCallback == clientEventHandler
	 */
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
#ifdef LEGACY_CODE
	if (_receiveThread) {
		_receiveThread->join();
		delete _receiveThread;
		_receiveThread = nullptr;
	}
#endif
}

void Client::close() {
	terminateReceiveThread();

	const bool closeFailed = (::close(_sockfd.get()) == -1);
	if (closeFailed) {
#if 0
		throw std::runtime_error(strerror(errno));
#endif
	}
}
