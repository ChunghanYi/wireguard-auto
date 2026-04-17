/*
 * Copyright (c) 2025-2026 Chunghan Yi <chunghan.yi@gmail.com>
 * Copyright (c) 2019 Elhay Rauper
 *
 * SPDX-License-Identifier: MIT
 */

#include <cstring>	//for std::memcpy
#include "inc/client.h"
#include "inc/message.h"
#include "inc/common.h"
#include "inc/sodium_ae.h"
#ifdef USE_GO_CLIENT
#include "inc/parser.h"
#endif

//#define DEBUG

WgacClient::WgacClient() {
	_isConnected = false;
	_isClosed = true;
	_prepare_secret_key.resize(32, 0); /* client private key for PREPARE stage */
	_prepare_public_key.resize(32, 0);  /* server public key for PREPARE stage */
}

WgacClient::~WgacClient() {
	close();
}

pipe_ret_t WgacClient::connectTo(const std::string& address, unsigned short port) {
	try {
		initializeSocket();
		setAddress(address, port);
	} catch (const std::runtime_error& error) {
		return pipe_ret_t::failure(error.what());
	}

	const int connectResult = connect(_sockfd.get(), (struct sockaddr*)&_server, sizeof(_server));
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
#ifdef DEBUG
		std::cout << "(WgacClient::initializeSocket() socket failed !!!\n";
#endif
		throw std::runtime_error(strerror(errno));
	}
}

void WgacClient::setAddress(const std::string& address, unsigned short port) {
	const int inetSuccess = inet_aton(address.c_str(), &_server.sin_addr);

	if (!inetSuccess) { // inet_addr failed to parse address
                        // if hostname is not in IP strings and dots format, try resolve it
		struct hostent* host;
		struct in_addr** addrList;
		if ((host = gethostbyname(address.c_str())) == nullptr) {
#ifdef DEBUG
			std::cout << "(WgacClient::setAddress() gethostbyname !!!\n";
#endif
			throw std::runtime_error("Failed to resolve hostname");
		}
		addrList = (struct in_addr**) host->h_addr_list;
		_server.sin_addr = *addrList[0];
	}
	_server.sin_family = AF_INET;
	_server.sin_port = htons(port);
}

#ifdef USE_GO_CLIENT
// Let's convert message_t structure to string
/* Golang client syntax
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
std::string convert_message2string(unsigned char* msg, size_t size) {
	message_t* smsg = reinterpret_cast<message_t*>(msg);
	std::string total_s {}, s {};
	char buffer[512] {};

	if (smsg->type == AUTOCONN::PREPARE)
		total_s = "cmd:=PREPARE\n";
	else if (smsg->type == AUTOCONN::HELLO)
		total_s = "cmd:=HELLO\n";
	else if (smsg->type == AUTOCONN::PING)
		total_s = "cmd:=PING\n";
	else if (smsg->type == AUTOCONN::PONG)
		total_s = "cmd:=PONG\n";
	else if (smsg->type == AUTOCONN::OK)
		total_s = "cmd:=OK\n";
	else if (smsg->type == AUTOCONN::NOK)
		total_s = "cmd:=NOK\n";
	else if (smsg->type == AUTOCONN::BYE)
		total_s = "cmd:=BYE\n";
	else
		total_s = "cmd:=NOK\n";

	snprintf(buffer, sizeof(buffer), "macaddr:=%02X-%02X-%02X-%02X-%02X-%02X\n",
			smsg->mac_addr[0], smsg->mac_addr[1], smsg->mac_addr[2],
			smsg->mac_addr[3], smsg->mac_addr[4], smsg->mac_addr[5]);
	s = buffer;
	total_s += s;

	snprintf(buffer, sizeof(buffer), "vpnip:=%s\n", inet_ntoa(smsg->vpnIP));
	s = buffer;
	total_s += s;

	snprintf(buffer, sizeof(buffer), "vpnnetmask:=%s\n", inet_ntoa(smsg->vpnNetmask));
	s = buffer;
	total_s += s;

	std::string pubkey(reinterpret_cast<const char*>(smsg->public_key));
	total_s = total_s + "publickey:=" + pubkey + "\n";

	snprintf(buffer, sizeof(buffer), "epip:=%s\n", inet_ntoa(smsg->epIP));
	s = buffer;
	total_s += s;

	snprintf(buffer, sizeof(buffer), "epport:=%d\n", smsg->epPort);
	s = buffer;
	total_s += s;

	std::string allowed(reinterpret_cast<const char*>(smsg->allowed_ips));
	total_s = total_s + "allowedips:=" + allowed + "\n";

#ifdef DEBUG
	std::cout << "total_s --------> [" << total_s << "]" << std::endl;
	std::cout << "length --------> [" << total_s.length() << "]" << std::endl;
#endif
	return total_s;
}
#endif

#ifdef NO_AUTHENTICATED_ENCRYPTION_METHOD
pipe_ret_t WgacClient::sendMsg(unsigned char* msg, size_t size) {
#ifdef USE_GO_CLIENT
	std::string total_s = convert_message2string(msg, size);

	const char* buf_ptr = total_s.c_str();
	try {
		const size_t numBytesSent = ::send(_sockfd.get(), buf_ptr, total_s.length(), 0);
	} catch (const std::runtime_error &error) {
		return pipe_ret_t::failure(">>> Oops message sending is failed.");
	}
#else
	const size_t numBytesSent = send(_sockfd.get(), msg, size, 0);

	if (numBytesSent < 0) { // send failed
		return pipe_ret_t::failure(strerror(errno));
	}
	if (numBytesSent < size) { // not all bytes were sent
		char errorMsg[100];
		sprintf(errorMsg, "Only %lu bytes out of %lu was sent to client", numBytesSent, size);
		return pipe_ret_t::failure(errorMsg);
	}
#endif
	return pipe_ret_t::success();
}

/*
 * Receive server packets, and notify user
 */
void WgacClient::receiveTask() {
	while(_isConnected) {
		const fd_wait::Result waitResult = fd_wait::waitFor(_sockfd);

		if (waitResult == fd_wait::Result::FAILURE) {
#ifdef DEBUG
			std::cout << "(WgacClient::receiveTask() fd_wait::Result::FAILURE !!!\n";
#endif
			_isConnected = false;
			return;
		} else if (waitResult == fd_wait::Result::TIMEOUT) {
			continue;
		}

#ifdef USE_GO_CLIENT
		message_t rmsg {};
		char rbuf[1024] {};
		const size_t numOfBytesReceived = recv(_sockfd.get(), rbuf, sizeof(rbuf), 0);
		if (!parser::parse_Go_message_string(rbuf, &rmsg)) {
#ifdef DEBUG
			std::cout << "(WgacClient::receiveTask()) parse_Go_message_string() is false !!!\n";
#endif
			return;
		}
#else
		message_t rmsg {};
		const size_t numOfBytesReceived = recv(_sockfd.get(), &rmsg, sizeof(rmsg), 0);
#endif

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
#else /* AE(Authenticated Encryption) method that has <PREPARE> stage additionally. */
pipe_ret_t WgacClient::sendMsg(unsigned char* msg, size_t size) {
	if (!isPrepared()) { /* PREPARE stage */
#ifdef DEBUG
		std::cout << "(WgacClient::sendMsg) isPrepared() is false !!!\n";
#endif
#ifdef USE_GO_CLIENT
		std::string total_s = convert_message2string(msg, size);
		const char* buf_ptr = total_s.c_str();
		try {
			const size_t numBytesSent = ::send(_sockfd.get(), buf_ptr, total_s.length(), 0);
		} catch (const std::runtime_error &error) {
			return pipe_ret_t::failure(">>> Oops message sending is failed.");
		}
#else
		const size_t numBytesSent = send(_sockfd.get(), msg, size, 0);
		if (numBytesSent < 0) { // send failed
			return pipe_ret_t::failure(strerror(errno));
		}
		if (numBytesSent < size) { // not all bytes were sent
			char errorMsg[100];
			sprintf(errorMsg, "Only %lu bytes out of %lu was sent to client", numBytesSent, size);
			return pipe_ret_t::failure(errorMsg);
		}
#endif
	} else { /* PING-PONG protocol stage */
#ifdef DEBUG
		std::cout << "(WgacClient::sendMsg) isPrepared() is true !!!\n";
#endif
#ifdef USE_GO_CLIENT
		std::string total_s = convert_message2string(msg, size);
		const char* buf_ptr = total_s.c_str();
		std::vector<unsigned char> original_message(buf_ptr, buf_ptr + total_s.length());
		std::vector<unsigned char> encrypted_message = sodium_ae::encrypt_message(original_message,
				getPreparePublicKey(), getPrepareSecretKey());
#else
		std::vector<unsigned char> original_message(msg, msg + size);
		std::vector<unsigned char> encrypted_message = sodium_ae::encrypt_message(original_message,
				getPreparePublicKey(), getPrepareSecretKey());
#endif

		const size_t numBytesSent = send(_sockfd.get(), encrypted_message.data(), encrypted_message.size(), 0);

		if (numBytesSent < 0) { // send failed
			return pipe_ret_t::failure(strerror(errno));
		}
		if (numBytesSent < encrypted_message.size()) { // not all bytes were sent
			char errorMsg[100];
			sprintf(errorMsg, "Only %lu bytes out of %lu was sent to client", numBytesSent, encrypted_message.size());
			return pipe_ret_t::failure(errorMsg);
		}
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
#ifdef DEBUG
			std::cout << "(WgacClient::receiveTask() fd_wait::Result::FAILURE !!!\n";
#endif
			_isConnected = false;
			return;
		} else if (waitResult == fd_wait::Result::TIMEOUT) {
			continue;
		}

		if (!isPrepared()) { /* PREPARE stage */
#ifdef DEBUG
			std::cout << "(WgacClient::receiveTask) isPrepared() is false !!!\n";
#endif
#ifdef USE_GO_CLIENT
			message_t rmsg {};
			char rbuf[1024] {};
			const size_t numOfBytesReceived = recv(_sockfd.get(), rbuf, sizeof(rbuf), 0);
			if (!parser::parse_Go_message_string(rbuf, &rmsg)) {
#ifdef DEBUG
				std::cout << "(WgacClient::receiveTask) parse_Go_message_string() is false !!!\n";
#endif
				return;
			}
#else
			message_t rmsg {};
			const size_t numOfBytesReceived = recv(_sockfd.get(), &rmsg, sizeof(rmsg), 0);
#endif

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
		} else { /* PING-PONG protocol stage */
#ifdef DEBUG
			std::cout << "(WgacClient::receiveTask) isPrepared() is true !!!\n";
#endif
			message_t rmsg {};
			unsigned char rxbuffer[ENC_MESSAGE_SIZE] {};
			const size_t numOfBytesReceived = recv(_sockfd.get(), rxbuffer, sizeof(rxbuffer), 0);

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
				std::vector<unsigned char> encrypted_message(rxbuffer, rxbuffer + numOfBytesReceived);
				bool decrypt_failure = false;
				std::vector<unsigned char> decrypted_message = sodium_ae::decrypt_message(
						encrypted_message, getPreparePublicKey(), getPrepareSecretKey(),
						decrypt_failure);
				if (!decrypt_failure) {
#ifdef USE_GO_CLIENT
					if (!parser::parse_Go_message_string(decrypted_message.data(), &rmsg)) {
#ifdef DEBUG
						std::cout << "(WgacClient::receiveTask) parse_Go_message_string() is false !!!\n";
#endif
						return;
					}
#else
					std::memcpy(&rmsg, decrypted_message.data(), sizeof(rmsg));	//TBD: w/o memcpy
#endif
					/* Let's put this message to <message queue>. */
					_msgQueue.push(rmsg);
				}
			}
		}
	}
}
#endif

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

void WgacClient::setRestart(bool flag) {
	_flagTerminate = flag;
}

bool WgacClient::shouldRestart() {
	return _flagTerminate;
}
