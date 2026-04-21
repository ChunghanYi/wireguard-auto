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
#include <getopt.h>

class AuthServer {
private:
    uint16_t port;
    int server_sock;

    // 패킷 송신용 헬퍼 함수
    bool send_all(int sock, const uint8_t* data, size_t len) {
        size_t sent = 0;
        while (sent < len) {
            ssize_t res = send(sock, data + sent, len - sent, 0);
            if (res <= 0) return false;
            sent += res;
        }
        return true;
    }

    // 클라이언트 연결을 처리하는 스레드 함수
    void handle_client(int client_sock) {
        std::cout << "[Thread] 새로운 클라이언트 연결 처리 시작" << std::endl;

        // 1. 클라이언트 공개키 수신 (Base64 형식의 44 bytes 문자열 수신)
        char client_pk_b64[45]; // 44 bytes + null terminator
        if (recv(client_sock, client_pk_b64, 44, MSG_WAITALL) <= 0) {
            close(client_sock);
            return;
        }
        client_pk_b64[44] = '\0';
        
        // Base64 -> Binary 디코딩
        uint8_t client_pk[crypto_box_PUBLICKEYBYTES];
        if (sodium_base642bin(client_pk, sizeof(client_pk), client_pk_b64, 44, nullptr, nullptr, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0) {
            std::cerr << "Base64 디코딩 실패" << std::endl;
            close(client_sock);
            return;
        }

        // 2. 서버 키쌍 생성
        uint8_t server_pk[crypto_box_PUBLICKEYBYTES];
        uint8_t server_sk[crypto_box_SECRETKEYBYTES];
        crypto_box_keypair(server_pk, server_sk);
        
        // 서버 공개키 Binary -> Base64 인코딩 후 전송
        char server_pk_b64[45];
        sodium_bin2base64(server_pk_b64, sizeof(server_pk_b64), server_pk, sizeof(server_pk), sodium_base64_VARIANT_ORIGINAL);
        send_all(client_sock, reinterpret_cast<const uint8_t*>(server_pk_b64), 44);

        // 3. 데이터 수신 (1번의 recv 호출로 Length + Nonce + Ciphertext 병합 수신)
        uint8_t recv_buf[4096];
        ssize_t n = recv(client_sock, recv_buf, sizeof(recv_buf), 0);
        if (n >= 4 + crypto_box_NONCEBYTES + crypto_box_MACBYTES) {
            // 첫 4바이트 길이 추출 (Big Endian)
            uint32_t payload_len = ntohl(*reinterpret_cast<uint32_t*>(recv_buf));
            
            if (n >= 4 + payload_len) {
                // Nonce와 암호문 분리
                uint8_t* nonce = recv_buf + 4;
                uint8_t* ciphertext = recv_buf + 4 + crypto_box_NONCEBYTES;
                size_t ciphertext_len = payload_len - crypto_box_NONCEBYTES;

                // Authenticated Decryption
                std::vector<uint8_t> decrypted(ciphertext_len - crypto_box_MACBYTES);
                if (crypto_box_open_easy(decrypted.data(), ciphertext, ciphertext_len, nonce, client_pk, server_sk) == 0) {
                    std::string msg(reinterpret_cast<char*>(decrypted.data()), decrypted.size());
                    std::cout << "[Thread] 🔓 복호화된 메시지: " << msg << std::endl;

                    // 4. 응답 암호화 및 전송
                    std::string response = "서버에서 보내는 암호화된 응답입니다! (수신 완료, C++ Server)";
                    uint8_t resp_nonce[crypto_box_NONCEBYTES];
                    randombytes_buf(resp_nonce, sizeof(resp_nonce));

                    size_t resp_ciphertext_len = response.size() + crypto_box_MACBYTES;
                    std::vector<uint8_t> resp_ciphertext(resp_ciphertext_len);
                    crypto_box_easy(resp_ciphertext.data(), reinterpret_cast<const uint8_t*>(response.data()), response.size(), resp_nonce, client_pk, server_sk);

                    // Length + Nonce + Ciphertext 병합
                    uint32_t net_resp_len = htonl(sizeof(resp_nonce) + resp_ciphertext_len);
                    std::vector<uint8_t> send_buf(4 + sizeof(resp_nonce) + resp_ciphertext_len);
                    memcpy(send_buf.data(), &net_resp_len, 4);
                    memcpy(send_buf.data() + 4, resp_nonce, sizeof(resp_nonce));
                    memcpy(send_buf.data() + 4 + sizeof(resp_nonce), resp_ciphertext.data(), resp_ciphertext_len);

                    send_all(client_sock, send_buf.data(), send_buf.size());
                    std::cout << "[Thread] 🔒 서버 응답 전송 완료" << std::endl;
                } else {
                    std::cerr << "[Thread] ❌ 복호화 실패 (키 불일치 또는 위변조)" << std::endl;
                }
            } else {
                std::cerr << "[Thread] ⚠️ TCP 단편화로 인해 전체 데이터를 한 번에 수신하지 못했습니다." << std::endl;
            }
        }
        
        close(client_sock);
        std::cout << "[Thread] 클라이언트 연결 종료\n" << std::endl;
    }

public:
    AuthServer(uint16_t port) : port(port), server_sock(-1) {}

    ~AuthServer() {
        if (server_sock != -1) close(server_sock);
    }

    void start(int max_clients) {
        server_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (server_sock == -1) {
            std::cerr << "소켓 생성 실패" << std::endl;
            return;
        }

        int opt = 1;
        setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(server_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == -1) {
            std::cerr << "Bind 실패 (포트가 이미 사용 중일 수 있습니다)" << std::endl;
            return;
        }
        
        // 인자로 받은 max_clients를 listen의 backlog 큐 크기로 설정
        if (listen(server_sock, max_clients) == -1) {
            std::cerr << "Listen 실패" << std::endl;
            return;
        }

        std::cout << "🚀 C++ 서버가 포트 " << port << "에서 대기 중입니다... (Max backlog: " << max_clients << ")" << std::endl;

        while (true) {
            int client_sock = accept(server_sock, nullptr, nullptr);
            if (client_sock != -1) {
                // 스레드에 멤버 함수 위임 (독립 실행)
                std::thread(&AuthServer::handle_client, this, client_sock).detach();
            }
        }
    }
};

int main(int argc, char* argv[]) {
    // 기본 파라미터 값 설정
    uint16_t port = 51822;
    bool daemon_mode = false;
    int max_clients = 10;

    int opt;
    // getopt를 통한 명령행 인자 파싱 (-p: port, -d: daemon, -m: max clients)
    while ((opt = getopt(argc, argv, "p:dm:")) != -1) {
        switch (opt) {
            case 'p': port = std::stoi(optarg); break;
            case 'd': daemon_mode = true; break;
            case 'm': max_clients = std::stoi(optarg); break;
            default:
                std::cerr << "Usage: " << argv[0] << " [-p port] [-d] [-m max_clients]" << std::endl;
                return 1;
        }
    }

    // 데몬 모드 실행 여부 확인
    if (daemon_mode) {
        // daemon(nochdir, noclose) -> 0, 0을 주면 워킹 디렉토리를 '/'로 바꾸고, 표준 입출력을 /dev/null로 보냅니다.
        if (daemon(0, 0) == -1) {
            std::cerr << "데몬화 실패" << std::endl;
            return 1;
        }
    }

    // libsodium 라이브러리 초기화
    if (sodium_init() < 0) {
        std::cerr << "libsodium 초기화 실패" << std::endl;
        return 1;
    }

    // 서버 시작
    AuthServer server(port);
    server.start(max_clients);
    
    return 0;
}
