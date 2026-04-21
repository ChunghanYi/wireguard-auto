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
#include <sodium.h>
#include "inc/parser.h"
#include "spdlog/spdlog.h"

//#define DEBUG

bool send_all(int sock, const uint8_t* data, size_t len) {
	size_t sent = 0;
	while (sent < len) {
		ssize_t res = ::send(sock, data + sent, len - sent, 0);
		if (res <= 0) return false;
		sent += res;
	}
	return true;
}

bool recv_all(int sock, uint8_t* data, size_t len) {
	size_t received = 0;
	while (received < len) {
		ssize_t res = ::recv(sock, data + received, len - received, 0);
		if (res <= 0) return false;
		received += res;
	}
	return true;
}

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

#ifdef AUTHENTICATED_ENCRYPTION //======================================================================
//Authenticated encryption routines
/**
 * Send a message to client
 */
void Client::send(const char* msg, size_t msg_len) const {
	std::vector<unsigned char> original_message(msg, msg + msg_len);
	std::vector<unsigned char> encrypted_message = sodium_ae::encrypt_message(original_message,
			getPreparePublicKey(), wgacsPtr->getPrepareSecretKey());

	const size_t sent_bytes = ::send(_sockfd.get(), encrypted_message.data(), encrypted_message.size(), 0);
	if (sent_bytes < 0 || sent_bytes < encrypted_message.size()) {
		spdlog::error("sent_bytes < 0 || sent_bytes < encrypted_message.size() !!!");
		return;
	}
}

/**
 * Thread routine: Receive a message from client
 */
void Client::receiveTask() {
	//step#1: Let's exchange public key
	uint8_t client_pk_base64[WG_KEY_LEN_BASE64] {};
	if (!recv_all(_sockfd.get(), client_pk_base64, sizeof(client_pk_base64)-1)) {
		std::cerr << "Client public key reception failed" << std::endl;
		setConnected(false);
		return;
	}
	//std::cout << "client_pk_base64 --> " << client_pk_base64 << std::endl;

	uint8_t client_pk[crypto_box_PUBLICKEYBYTES] {};
	if (!key_from_base64(client_pk, reinterpret_cast<const char*>(client_pk_base64))) {
		std::cerr << "Public key is not the correct length or format" << std::endl;
		setConnected(false);
		return;
	} else {
		setPreparePublicKey(client_pk);

		uint8_t server_pk_base64[WG_KEY_LEN_BASE64] {};
		std::memcpy(server_pk_base64,
				wgacsPtr->getConfig().getstr("this_public_key").c_str(), WG_KEY_LEN_BASE64);

		if (!send_all(_sockfd.get(), server_pk_base64, sizeof(server_pk_base64)-1)) {
			std::cerr << "Server public key transmission failed" << std::endl;
			setConnected(false);
			return;
		}
		//std::cout << "server_pk_base64 --> " << server_pk_base64 << std::endl;
	}

	/* step#2: PING-PONG Protocol */
	while (isConnected()) {
		const fd_wait::Result waitResult = fd_wait::waitFor(_sockfd);

		if (waitResult == fd_wait::Result::FAILURE) {
			setConnected(false);
			return;
		} else if (waitResult == fd_wait::Result::TIMEOUT) {
			continue;
		}

		message_t rmsg {};
		unsigned char recv_buf[1024] {};
		const size_t received_bytes = recv(_sockfd.get(), recv_buf, sizeof(recv_buf), 0);

		if (received_bytes < 1) {
			const bool clientClosedConnection = (received_bytes == 0);
			if (clientClosedConnection) {
				rmsg.type = AUTOCONN::OK;
			} else {
				rmsg.type = AUTOCONN::NOK;
			}
			setConnected(false);
			publishEvent(ClientEvent::DISCONNECTED, rmsg);
			return;
		}

		bool decrypt_failure = false;
		std::vector<unsigned char> encrypted_message(recv_buf, recv_buf + received_bytes);
		std::vector<unsigned char> decrypted_message = sodium_ae::decrypt_message(
				encrypted_message, getPreparePublicKey(), wgacsPtr->getPrepareSecretKey(),
				decrypt_failure);
		if (!decrypt_failure) {
			char recv_buf[1024] {};
			memcpy(recv_buf, reinterpret_cast<char*>(decrypted_message.data()),
					decrypted_message.size() * sizeof(unsigned char)); 
			if (!parser::parse_new_message_string(recv_buf, &rmsg)) {
				spdlog::error("Failed to parse message string");
				return;
			}

			publishEvent(ClientEvent::INCOMING_MSG, rmsg);
		} else {
			message_t smsg{};
			smsg.type = AUTOCONN::BYE;
			std::memcpy(smsg.mac_addr, rmsg.mac_addr, 6);
			std::memcpy(smsg.public_key,
					wgacsPtr->getConfig().getstr("this_public_key").c_str(), WG_KEY_LEN_BASE64);
			wgacsPtr->send_BYE(*this, smsg);

			setConnected(false);
		}
	}
}
#else //=================================================================================
//No authenticated encryption routines
/**
 * Send a message to client
 */
void Client::send(const char* msg, size_t msg_len) const {
	const size_t sent_bytes = ::send(_sockfd.get(), (const char *)msg, msg_len, 0);

	if (sent_bytes < 0) {
		throw std::runtime_error(strerror(errno));
	}

	if (sent_bytes < msg_len) {
		char errorMsg[100];
		sprintf(errorMsg, "Only %lu bytes out of %lu was sent to client", sent_bytes, msg_len);
		throw std::runtime_error(errorMsg);
	}
}

/**
 * Thread routine: Receive a message from client
 */
void Client::receiveTask() {
	while (isConnected()) {
		const fd_wait::Result waitResult = fd_wait::waitFor(_sockfd);

		if (waitResult == fd_wait::Result::FAILURE) {
			throw std::runtime_error(strerror(errno));
		} else if (waitResult == fd_wait::Result::TIMEOUT) {
			continue;
		}

		message_t rmsg {};
		char recv_buf[1024] {};
		const size_t received_bytes = recv(_sockfd.get(), recv_buf, sizeof(recv_buf), 0);
		if (!parser::parse_new_message_string(recv_buf, &rmsg)) {
			spdlog::error("Failed to parse message string");
			return;
		}

		if (received_bytes < 1) {
			const bool clientClosedConnection = (received_bytes == 0);
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
#endif //=================================================================================

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
