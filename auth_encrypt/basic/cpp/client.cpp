/* SPDX-License-Identifier: MIT
 *
 * Authenticated Encryption/Decryption examples using libsodium library
 * Key exchange: X25519, Encryption: XSalsa20, Authentication: Poly1305
 */

#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sodium.h>

bool send_all(int sock, const uint8_t* data, size_t len) {
	size_t sent = 0;
	while (sent < len) {
		ssize_t res = send(sock, data + sent, len - sent, 0);
		if (res <= 0) return false;
		sent += res;
	}
	return true;
}

bool recv_all(int sock, uint8_t* data, size_t len) {
	size_t received = 0;
	while (received < len) {
		ssize_t res = recv(sock, data + received, len - received, 0);
		if (res <= 0) return false;
		received += res;
	}
	return true;
}

int main() {
	if (sodium_init() < 0) {
		std::cerr << "libsodium 초기화 실패" << std::endl;
		return 1;
	}

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	sockaddr_in server_addr{};
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(51822);
	inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

	if (connect(sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) == -1) {
		std::cerr << "서버 연결 실패. 서버가 실행 중인지 확인하세요." << std::endl;
		return 1;
	}

	// 1. 클라이언트의 X25519 키쌍 생성
	uint8_t client_pk[crypto_box_PUBLICKEYBYTES];
	uint8_t client_sk[crypto_box_SECRETKEYBYTES];
	crypto_box_keypair(client_pk, client_sk);

	// 2. 클라이언트 공개키 서버로 전송
	send_all(sock, client_pk, sizeof(client_pk));

	// 3. 서버의 공개키 수신
	uint8_t server_pk[crypto_box_PUBLICKEYBYTES];
	if (!recv_all(sock, server_pk, sizeof(server_pk))) {
		std::cerr << "서버 공개키 수신 실패" << std::endl;
		close(sock);
		return 1;
	}

	// 4. 전송할 메시지 준비
	std::string message = "안녕하세요! C++ 클라이언트가 보낸 비밀 메시지입니다.";
	const uint8_t* msg_bytes = reinterpret_cast<const uint8_t*>(message.data());
	size_t msg_len = message.size();

	// 5. Nonce(24 Bytes) 생성
	uint8_t nonce[crypto_box_NONCEBYTES];
	randombytes_buf(nonce, sizeof(nonce));

	// 6. 메시지 암호화 (MAC 16 Bytes 자동 포함됨)
	size_t ciphertext_len = msg_len + crypto_box_MACBYTES;
	std::vector<uint8_t> ciphertext(ciphertext_len);

	crypto_box_easy(ciphertext.data(), msg_bytes, msg_len, nonce, server_pk, client_sk);

	// 7. Payload 구성 (Length + Nonce + Ciphertext를 하나의 버퍼로 병합)
	uint32_t payload_len = sizeof(nonce) + ciphertext_len;
	uint32_t net_len = htonl(payload_len); // Big Endian으로 변환

	std::vector<uint8_t> send_buf(4 + payload_len);
	memcpy(send_buf.data(), &net_len, 4);
	memcpy(send_buf.data() + 4, nonce, sizeof(nonce));
	memcpy(send_buf.data() + 4 + sizeof(nonce), ciphertext.data(), ciphertext_len);

	// 1번의 send_all로 전송 처리
	send_all(sock, send_buf.data(), send_buf.size());

	std::cout << "🔒 암호화된 메시지 전송 성공!" << std::endl;

	// 8. 서버로부터 응답 수신 (1번의 recv로 처리)
	uint8_t recv_buf[4096];
	ssize_t received_bytes = recv(sock, recv_buf, sizeof(recv_buf), 0);

	if (received_bytes >= 4 + crypto_box_NONCEBYTES + crypto_box_MACBYTES) {
		uint32_t resp_payload_len = ntohl(*reinterpret_cast<uint32_t*>(recv_buf));

		if (received_bytes >= 4 + resp_payload_len) {
			// Nonce와 암호문 분리
			uint8_t* resp_nonce = recv_buf + 4;
			uint8_t* resp_ciphertext = recv_buf + 4 + crypto_box_NONCEBYTES;
			size_t resp_ciphertext_len = resp_payload_len - crypto_box_NONCEBYTES;

			std::vector<uint8_t> resp_decrypted(resp_ciphertext_len - crypto_box_MACBYTES);

			// 9. 서버 응답 복호화 (클라이언트 Secret Key + 서버 Public Key 사용)
			if (crypto_box_open_easy(resp_decrypted.data(), resp_ciphertext, resp_ciphertext_len, resp_nonce, server_pk, client_sk) != 0) {
				std::cerr << "❌ 서버 응답 복호화 실패!" << std::endl;
			} else {
				std::string resp_msg(reinterpret_cast<char*>(resp_decrypted.data()), resp_decrypted.size());
				std::cout << "🔓 서버로부터의 응답: " << resp_msg << std::endl;
			}
		} else {
			std::cerr << "TCP 단편화로 인해 응답을 한 번에 수신하지 못했습니다." << std::endl;
		}
	} else {
		std::cerr << "서버 응답 페이로드 크기가 너무 작습니다." << std::endl;
	}

	close(sock);
	return 0;
}
