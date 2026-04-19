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

class AuthServer {
private:
	uint16_t port;
	int server_sock;

	bool send_all(int sock, const uint8_t* data, size_t len) {
		size_t sent = 0;
		while (sent < len) {
			ssize_t res = send(sock, data + sent, len - sent, 0);
			if (res <= 0) return false;
			sent += res;
		}
		return true;
	}

	void handle_client(int client_sock) {
		std::cout << "[Thread] 새로운 클라이언트 연결 처리 시작" << std::endl;

		// 1. 클라이언트 공개키 수신
		uint8_t client_pk[crypto_box_PUBLICKEYBYTES];
		if (recv(client_sock, client_pk, sizeof(client_pk), MSG_WAITALL) <= 0) {
			close(client_sock);
			return;
		}

		// 2. 서버 키쌍 생성 및 공개키 전송
		uint8_t server_pk[crypto_box_PUBLICKEYBYTES];
		uint8_t server_sk[crypto_box_SECRETKEYBYTES];
		crypto_box_keypair(server_pk, server_sk);
		send_all(client_sock, server_pk, sizeof(server_pk));

		// 3. 데이터 수신
		uint8_t recv_buf[4096];
		ssize_t n = recv(client_sock, recv_buf, sizeof(recv_buf), 0);
		if (n >= 4 + crypto_box_NONCEBYTES + crypto_box_MACBYTES) {
			uint32_t payload_len = ntohl(*reinterpret_cast<uint32_t*>(recv_buf));
			if (n >= 4 + payload_len) {
				uint8_t* nonce = recv_buf + 4;
				uint8_t* ciphertext = recv_buf + 4 + crypto_box_NONCEBYTES;
				size_t ciphertext_len = payload_len - crypto_box_NONCEBYTES;

				std::vector<uint8_t> decrypted(ciphertext_len - crypto_box_MACBYTES);
				if (crypto_box_open_easy(decrypted.data(), ciphertext, ciphertext_len, nonce, client_pk, server_sk) == 0) {
					std::string msg(reinterpret_cast<char*>(decrypted.data()), decrypted.size());
					std::cout << "[Thread] 🔓 복호화된 메시지: " << msg << std::endl;

					// 4. 응답 전송
					std::string response = "서버에서 보내는 암호화된 응답입니다! (수신 완료, C++ Server)";
					uint8_t resp_nonce[crypto_box_NONCEBYTES];
					randombytes_buf(resp_nonce, sizeof(resp_nonce));

					size_t resp_ciphertext_len = response.size() + crypto_box_MACBYTES;
					std::vector<uint8_t> resp_ciphertext(resp_ciphertext_len);
					crypto_box_easy(resp_ciphertext.data(), reinterpret_cast<const uint8_t*>(response.data()), response.size(), resp_nonce, client_pk, server_sk);

					uint32_t net_resp_len = htonl(sizeof(resp_nonce) + resp_ciphertext_len);
					std::vector<uint8_t> send_buf(4 + sizeof(resp_nonce) + resp_ciphertext_len);
					memcpy(send_buf.data(), &net_resp_len, 4);
					memcpy(send_buf.data() + 4, resp_nonce, sizeof(resp_nonce));
					memcpy(send_buf.data() + 4 + sizeof(resp_nonce), resp_ciphertext.data(), resp_ciphertext_len);

					send_all(client_sock, send_buf.data(), send_buf.size());
				}
			}
		}
		close(client_sock);
		std::cout << "[Thread] 클라이언트 연결 종료\n";
	}

public:
	AuthServer(uint16_t port) : port(port), server_sock(-1) {}

	~AuthServer() {
		if (server_sock != -1) close(server_sock);
	}

	void start() {
		server_sock = socket(AF_INET, SOCK_STREAM, 0);
		int opt = 1;
		setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = htons(port);

		bind(server_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
		listen(server_sock, 10);

		std::cout << "🚀 C++ 서버가 포트 " << port << "에서 대기 중입니다..." << std::endl;

		while (true) {
			int client_sock = accept(server_sock, nullptr, nullptr);
			if (client_sock != -1) {
				// 스레드에 멤버 함수 위임
				std::thread(&AuthServer::handle_client, this, client_sock).detach();
			}
		}
	}
};

int main() {
	if (sodium_init() < 0) return 1;
	AuthServer server(51822);
	server.start();
	return 0;
}
