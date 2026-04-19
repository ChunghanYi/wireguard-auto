/* SPDX-License-Identifier: MIT
 *
 * Authenticated Encryption/Decryption examples using libsodium library
 * Key exchange: X25519, Encryption: XSalsa20, Authentication: Poly1305
 */

#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sodium.h>

// 정확한 바이트 수만큼 데이터를 전송하는 헬퍼 함수
bool send_all(int sock, const uint8_t* data, size_t len) {
	size_t sent = 0;
	while (sent < len) {
		ssize_t res = send(sock, data + sent, len - sent, 0);
		if (res <= 0) return false;
		sent += res;
	}
	return true;
}

// 정확한 바이트 수만큼 데이터를 수신하는 헬퍼 함수
bool recv_all(int sock, uint8_t* data, size_t len) {
	size_t received = 0;
	while (received < len) {
		ssize_t res = recv(sock, data + received, len - received, 0);
		if (res <= 0) return false;
		received += res;
	}
	return true;
}

// 클라이언트 연결을 처리하는 스레드 함수
void handle_client(int client_sock) {
	std::cout << "[Thread] 새로운 클라이언트 연결 처리 시작" << std::endl;

	// 1. 클라이언트의 X25519 공개키 수신
	uint8_t client_pk[crypto_box_PUBLICKEYBYTES];
	if (!recv_all(client_sock, client_pk, sizeof(client_pk))) {
		std::cerr << "[Thread] 클라이언트 공개키 수신 실패" << std::endl;
		close(client_sock);
		return;
	}
	std::cout << "[Thread] 클라이언트 공개키 수신 완료" << std::endl;

	// 2. 서버의 X25519 키쌍 생성
	uint8_t server_pk[crypto_box_PUBLICKEYBYTES];
	uint8_t server_sk[crypto_box_SECRETKEYBYTES];
	crypto_box_keypair(server_pk, server_sk);

	// 3. 서버의 공개키를 클라이언트에게 전송 (평문)
	if (!send_all(client_sock, server_pk, sizeof(server_pk))) {
		std::cerr << "[Thread] 서버 공개키 전송 실패" << std::endl;
		close(client_sock);
		return;
	}
	std::cout << "[Thread] 서버 공개키 전송 완료" << std::endl;

	// 4. 데이터 수신 (1번의 recv 호출로 길이 + Nonce + 암호문을 한 번에 수신)
	uint8_t recv_buf[4096]; // 최대 4KB 수신 가정
	ssize_t received_bytes = recv(client_sock, recv_buf, sizeof(recv_buf), 0);

	if (received_bytes < 4 + crypto_box_NONCEBYTES + crypto_box_MACBYTES) {
		std::cerr << "[Thread] 잘못된 페이로드 크기 또는 수신 실패" << std::endl;
		close(client_sock);
		return;
	}

	uint32_t net_len = *reinterpret_cast<uint32_t*>(recv_buf);
	uint32_t payload_len = ntohl(net_len);

	if (received_bytes < 4 + payload_len) {
		std::cerr << "[Thread] TCP 단편화로 인해 전체 데이터를 한 번에 수신하지 못했습니다." << std::endl;
		close(client_sock);
		return;
	}

	// 포인터 및 길이 계산
	uint8_t* nonce = recv_buf + 4;
	uint8_t* ciphertext = recv_buf + 4 + crypto_box_NONCEBYTES;
	size_t ciphertext_len = payload_len - crypto_box_NONCEBYTES;

	// 복호화 버퍼 할당
	std::vector<uint8_t> decrypted(ciphertext_len - crypto_box_MACBYTES);

	// 6. Authenticated Decryption 수행
	if (crypto_box_open_easy(decrypted.data(), ciphertext, ciphertext_len, nonce, client_pk, server_sk) != 0) {
		std::cerr << "[Thread] ❌ 복호화 실패! (데이터가 위조되었거나 키가 일치하지 않음)" << std::endl;
	} else {
		std::string msg(reinterpret_cast<char*>(decrypted.data()), decrypted.size());
		std::cout << "[Thread] 🔓 복호화된 메시지: " << msg << std::endl;
	}

	// 7. 서버에서 클라이언트로 암호화된 응답 전송
	std::string response = "서버에서 보내는 암호화된 응답입니다! (수신 완료)";
	uint8_t resp_nonce[crypto_box_NONCEBYTES];
	randombytes_buf(resp_nonce, sizeof(resp_nonce)); // 새로운 Nonce 생성

	size_t resp_ciphertext_len = response.size() + crypto_box_MACBYTES;
	std::vector<uint8_t> resp_ciphertext(resp_ciphertext_len);

	// 응답 메시지 암호화 (서버 Secret Key + 클라이언트 Public Key 사용)
	crypto_box_easy(resp_ciphertext.data(), reinterpret_cast<const uint8_t*>(response.data()), response.size(), resp_nonce, client_pk, server_sk);

	// Payload 구성 및 전송 (Length + Nonce + Ciphertext를 하나의 버퍼로 병합)
	uint32_t resp_payload_len = sizeof(resp_nonce) + resp_ciphertext_len;
	uint32_t net_resp_len = htonl(resp_payload_len);

	std::vector<uint8_t> send_buf(4 + resp_payload_len);
	memcpy(send_buf.data(), &net_resp_len, 4);
	memcpy(send_buf.data() + 4, resp_nonce, sizeof(resp_nonce));
	memcpy(send_buf.data() + 4 + sizeof(resp_nonce), resp_ciphertext.data(), resp_ciphertext_len);

	// 1번의 send_all로 전송 처리
	if (send_all(client_sock, send_buf.data(), send_buf.size())) {
		std::cout << "[Thread] 🔒 서버 응답 전송 완료" << std::endl;
	} else {
		std::cerr << "[Thread] 서버 응답 전송 실패" << std::endl;
	}

	close(client_sock);
	std::cout << "[Thread] 클라이언트 연결 종료" << std::endl;
}

int main() {
	// libsodium 초기화 (필수)
	if (sodium_init() < 0) {
		std::cerr << "libsodium 초기화 실패" << std::endl;
		return 1;
	}

	int server_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (server_sock == -1) {
		std::cerr << "소켓 생성 실패" << std::endl;
		return 1;
	}

	int opt = 1;
	setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	sockaddr_in server_addr{};
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(51822); // 요구사항: 포트 51822

	if (bind(server_sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) == -1) {
		std::cerr << "Bind 실패 (포트가 이미 사용중일 수 있습니다)" << std::endl;
		return 1;
	}

	if (listen(server_sock, 10) == -1) {
		std::cerr << "Listen 실패" << std::endl;
		return 1;
	}

	std::cout << "🚀 서버가 포트 51822에서 대기 중입니다..." << std::endl;

	while (true) {
		sockaddr_in client_addr{};
		socklen_t client_len = sizeof(client_addr);
		int client_sock = accept(server_sock, reinterpret_cast<sockaddr*>(&client_addr), &client_len);

		if (client_sock == -1) {
			std::cerr << "Accept 실패" << std::endl;
			continue;
		}

		// 새 스레드를 생성하여 클라이언트 연결(connection) 위임 (detach하여 독립 실행)
		std::thread(handle_client, client_sock).detach();
	}

	close(server_sock);
	return 0;
}
