/* SPDX-License-Identifier: MIT
 *
 * Authenticated Encryption/Decryption using libsodium library
 * Algorithms: Curve25519, ChaCha20-Poly1305
 */

#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sodium.h>

// IETF 규격 ChaCha20-Poly1305의 Nonce 크기는 12 Bytes 입니다.
#define NONCE_SIZE 12
#define KEY_SIZE 32
#define B64_KEY_SIZE 44

class AuthClient {
private:
    int sock;
    uint8_t client_pk[KEY_SIZE];
    uint8_t client_sk[KEY_SIZE];
    uint8_t server_pk[KEY_SIZE];
    uint8_t aead_key[KEY_SIZE];

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
        // Curve25519 (X25519) 키쌍 생성
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
        char client_pk_b64[B64_KEY_SIZE + 1];
        sodium_bin2base64(client_pk_b64, sizeof(client_pk_b64), client_pk, KEY_SIZE, sodium_base64_VARIANT_ORIGINAL);
        send_all(reinterpret_cast<const uint8_t*>(client_pk_b64), B64_KEY_SIZE);

        // 2. 서버 공개키 수신 (Base64) 및 디코딩
        char server_pk_b64[B64_KEY_SIZE + 1];
        if (recv(sock, server_pk_b64, B64_KEY_SIZE, MSG_WAITALL) <= 0) return false;
        server_pk_b64[B64_KEY_SIZE] = '\0';
        
        if (sodium_base642bin(server_pk, KEY_SIZE, server_pk_b64, B64_KEY_SIZE, nullptr, nullptr, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0) {
            return false;
        }

        // 3. Shared Secret 계산 (X25519)
        uint8_t shared_secret[KEY_SIZE];
        if (crypto_scalarmult(shared_secret, client_sk, server_pk) != 0) {
            std::cerr << "Shared Secret 계산 실패" << std::endl;
            return false;
        }

        // 4. SHA256 KDF를 통해 최종 AEAD Key 파생 (커널의 hash 처리와 맞춤)
        crypto_hash_sha256(aead_key, shared_secret, KEY_SIZE);
        
        return true;
    }

    void send_message_and_receive(const std::string& message) {
        // 5. 메시지 암호화 (ChaCha20-Poly1305 IETF)
        uint8_t nonce[NONCE_SIZE];
        randombytes_buf(nonce, NONCE_SIZE);

        unsigned long long ciphertext_len;
        std::vector<uint8_t> ciphertext(message.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
        
        crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext.data(), &ciphertext_len,
            reinterpret_cast<const uint8_t*>(message.data()), message.size(),
            nullptr, 0, nullptr, nonce, aead_key
        );

        // 페이로드 직렬화 및 전송 [4 bytes length] + [12 bytes nonce] + [ciphertext(include 16 bytes MAC)]
        uint32_t payload_len = NONCE_SIZE + ciphertext_len;
        uint32_t net_len = htonl(payload_len);

        std::vector<uint8_t> send_buf(4 + payload_len);
        memcpy(send_buf.data(), &net_len, 4);
        memcpy(send_buf.data() + 4, nonce, NONCE_SIZE);
        memcpy(send_buf.data() + 4 + NONCE_SIZE, ciphertext.data(), ciphertext_len);

        send_all(send_buf.data(), send_buf.size());
        std::cout << "🔒 암호화된 메시지 전송 성공 (ChaCha20-Poly1305)!" << std::endl;

        // 6. 커널 서버로부터 응답 수신
        uint8_t recv_buf[4096];
        ssize_t n = recv(sock, recv_buf, sizeof(recv_buf), 0);
        if (n >= 4 + NONCE_SIZE + crypto_aead_chacha20poly1305_ietf_ABYTES) {
            uint32_t resp_payload_len = ntohl(*reinterpret_cast<uint32_t*>(recv_buf));
            if (n >= 4 + resp_payload_len) {
                uint8_t* resp_nonce = recv_buf + 4;
                uint8_t* resp_ciphertext = recv_buf + 4 + NONCE_SIZE;
                size_t resp_ciphertext_len = resp_payload_len - NONCE_SIZE;

                std::vector<uint8_t> resp_decrypted(resp_ciphertext_len - crypto_aead_chacha20poly1305_ietf_ABYTES);
                unsigned long long decrypted_len;

                // 7. 복호화
                if (crypto_aead_chacha20poly1305_ietf_decrypt(
                    resp_decrypted.data(), &decrypted_len,
                    nullptr,
                    resp_ciphertext, resp_ciphertext_len,
                    nullptr, 0, resp_nonce, aead_key) == 0) {
                        
                    std::string resp_msg(reinterpret_cast<char*>(resp_decrypted.data()), decrypted_len);
                    std::cout << "🔓 서버 응답: " << resp_msg << std::endl;
                } else {
                    std::cerr << "❌ 복호화 실패" << std::endl;
                }
            }
        }
    }
};

int main() {
    if (sodium_init() < 0) return 1;

    AuthClient client;
    if (client.connect_server("127.0.0.1", 51822)) {
        client.send_message_and_receive("User-space C Client에서 Kernel 모듈로 보내는 메시지입니다.");
    } else {
        std::cerr << "❌ 커널 서버 연결 또는 키 교환 실패" << std::endl;
    }
    return 0;
}
