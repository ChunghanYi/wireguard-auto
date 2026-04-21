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
#include <getopt.h>

class AuthClient {
private:
    int sock;
    uint8_t client_pk[crypto_box_PUBLICKEYBYTES];
    uint8_t client_sk[crypto_box_SECRETKEYBYTES];
    uint8_t server_pk[crypto_box_PUBLICKEYBYTES];

    bool send_all(const uint8_t* data, size_t len) {
        size_t sent = 0;
        while (sent < len) {
            ssize_t res = send(sock, data + sent, len - sent, 0);
            if (res <= 0) return false;
            sent += res;
        }
        return true;
    }

public:
    AuthClient() : sock(-1) {
        crypto_box_keypair(client_pk, client_sk);
    }

    ~AuthClient() {
        if (sock != -1) close(sock);
    }

    bool connect_server(const std::string& ip, uint16_t port) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr);

        if (connect(sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) == -1) {
            return false;
        }

        // 1. 클라이언트 공개키 Base64 인코딩 후 전송
        char client_pk_b64[45];
        sodium_bin2base64(client_pk_b64, sizeof(client_pk_b64), client_pk, sizeof(client_pk), sodium_base64_VARIANT_ORIGINAL);
        send_all(reinterpret_cast<const uint8_t*>(client_pk_b64), 44);

        // 2. 서버 공개키 수신 (Base64) 및 디코딩
        char server_pk_b64[45];
        if (recv(sock, server_pk_b64, 44, MSG_WAITALL) <= 0) return false;
        server_pk_b64[44] = '\0';
        
        if (sodium_base642bin(server_pk, sizeof(server_pk), server_pk_b64, 44, nullptr, nullptr, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0) {
            return false;
        }
        
        return true;
    }

    void send_message_and_receive(const std::string& message) {
        // 암호화 및 송신
        uint8_t nonce[crypto_box_NONCEBYTES];
        randombytes_buf(nonce, sizeof(nonce));

        size_t ciphertext_len = message.size() + crypto_box_MACBYTES;
        std::vector<uint8_t> ciphertext(ciphertext_len);
        crypto_box_easy(ciphertext.data(), reinterpret_cast<const uint8_t*>(message.data()), message.size(), nonce, server_pk, client_sk);

        uint32_t payload_len = sizeof(nonce) + ciphertext_len;
        uint32_t net_len = htonl(payload_len);

        std::vector<uint8_t> send_buf(4 + payload_len);
        memcpy(send_buf.data(), &net_len, 4);
        memcpy(send_buf.data() + 4, nonce, sizeof(nonce));
        memcpy(send_buf.data() + 4 + sizeof(nonce), ciphertext.data(), ciphertext_len);

        send_all(send_buf.data(), send_buf.size());
        std::cout << "🔒 암호화된 메시지 전송 성공!" << std::endl;

        // 수신 및 복호화
        uint8_t recv_buf[4096];
        ssize_t n = recv(sock, recv_buf, sizeof(recv_buf), 0);
        if (n >= 4 + crypto_box_NONCEBYTES + crypto_box_MACBYTES) {
            uint32_t resp_payload_len = ntohl(*reinterpret_cast<uint32_t*>(recv_buf));
            if (n >= 4 + resp_payload_len) {
                uint8_t* resp_nonce = recv_buf + 4;
                uint8_t* resp_ciphertext = recv_buf + 4 + crypto_box_NONCEBYTES;
                size_t resp_ciphertext_len = resp_payload_len - crypto_box_NONCEBYTES;

                std::vector<uint8_t> resp_decrypted(resp_ciphertext_len - crypto_box_MACBYTES);
                if (crypto_box_open_easy(resp_decrypted.data(), resp_ciphertext, resp_ciphertext_len, resp_nonce, server_pk, client_sk) == 0) {
                    std::string resp_msg(reinterpret_cast<char*>(resp_decrypted.data()), resp_decrypted.size());
                    std::cout << "🔓 서버로부터의 응답: " << resp_msg << std::endl;
                }
            }
        }
    }
};

int main(int argc, char* argv[]) {
    std::string ip = "127.0.0.1";
    uint16_t port = 51822;
    bool daemon_mode = false;

    int opt;
    while ((opt = getopt(argc, argv, "i:p:d")) != -1) {
        switch (opt) {
            case 'i': ip = optarg; break;
            case 'p': port = std::stoi(optarg); break;
            case 'd': daemon_mode = true; break;
            default:
                std::cerr << "Usage: " << argv[0] << " [-i ip] [-p port] [-d]" << std::endl;
                return 1;
        }
    }

    if (daemon_mode) {
        if (daemon(0, 0) == -1) {
            std::cerr << "데몬화 실패" << std::endl;
            return 1;
        }
    }

    if (sodium_init() < 0) return 1;

    AuthClient client;
    if (client.connect_server(ip, port)) {
        client.send_message_and_receive("안녕하세요! C++ 클래스 클라이언트가 보낸 비밀 메시지입니다.");
    } else {
        std::cerr << "❌ 서버 연결 또는 키 교환 실패" << std::endl;
    }
    return 0;
}
