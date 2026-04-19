"""
   SPDX-License-Identifier: MIT

   Authenticated Encryption/Decryption examples using libsodium library
   Key exchange: X25519, Encryption: XSalsa20, Authentication: Poly1305
"""

import socket
import struct
import threading
import sys
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box

# 상수 정의
LENGTH_SIZE = 4      # 데이터 길이를 나타내는 헤더의 크기 (4 bytes)
NONCE_SIZE = 24      # X25519 Nonce 크기 (24 bytes)
KEY_SIZE = 32        # X25519 공개키 크기 (32 bytes)
BUFFER_SIZE = 4096   # 수신 버퍼 크기
MAC_SIZE = 16        # Poly1305 MAC 크기 (16 bytes)

def recvall(sock, n):
    """정확히 n 바이트를 수신하기 위한 헬퍼 함수 (키 교환용)"""
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def handle_client(conn, addr):
    """개별 클라이언트 연결을 처리하는 스레드 함수"""
    print(f"[Thread-{addr[1]}] 새로운 클라이언트 연결 처리 시작 ({addr[0]})")
    
    try:
        # 1. 클라이언트의 X25519 공개키 수신
        client_pubkey_bytes = recvall(conn, KEY_SIZE)
        if not client_pubkey_bytes:
            print(f"[Thread-{addr[1]}] ❌ 클라이언트 공개키 수신 실패")
            return
            
        print(f"[Thread-{addr[1]}] 클라이언트 공개키 수신 완료")
        client_public_key = PublicKey(client_pubkey_bytes)

        # 2. 서버의 X25519 키쌍 생성
        server_private_key = PrivateKey.generate()
        server_public_key = server_private_key.public_key

        # 3. 서버의 공개키를 클라이언트에게 전송 (평문)
        conn.sendall(bytes(server_public_key))
        print(f"[Thread-{addr[1]}] 서버 공개키 전송 완료")

        # 4. Box 객체 생성 (서버 비밀키 + 클라이언트 공개키 결합)
        box = Box(server_private_key, client_public_key)

        # 5. 데이터 수신 (1번의 recv 호출로 길이 + Nonce + 암호문을 한 번에 수신)
        recv_buf = conn.recv(BUFFER_SIZE)
        
        if len(recv_buf) < LENGTH_SIZE + NONCE_SIZE + MAC_SIZE:
            print(f"[Thread-{addr[1]}] ❌ 잘못된 페이로드 크기 또는 수신 실패")
            return

        # 첫 4바이트에서 길이 추출 (Big Endian)
        payload_len = struct.unpack(">I", recv_buf[:LENGTH_SIZE])[0]

        if len(recv_buf) >= LENGTH_SIZE + payload_len:
            # Payload(Nonce + Ciphertext) 분리
            payload = recv_buf[LENGTH_SIZE : LENGTH_SIZE + payload_len]

            try:
                # 6. Authenticated Decryption 수행
                # PyNaCl의 decrypt는 데이터의 앞 24바이트를 자동으로 Nonce로 인식하고 복호화합니다.
                decrypted_msg = box.decrypt(payload)
                print(f"[Thread-{addr[1]}] 🔓 복호화된 메시지: {decrypted_msg.decode('utf-8')}")
                
                # 7. 서버에서 클라이언트로 암호화된 응답 전송
                response_msg = "서버에서 보내는 암호화된 응답입니다! (수신 완료)".encode('utf-8')
                nonce = nacl.utils.random(NONCE_SIZE)
                
                # 응답 메시지 암호화
                encrypted_response = box.encrypt(response_msg, nonce)
                resp_payload = bytes(encrypted_response)
                
                # Payload 구성 및 전송 (Length + (Nonce + Ciphertext)를 하나의 버퍼로 병합)
                resp_payload_len = len(resp_payload)
                send_buf = struct.pack(">I", resp_payload_len) + resp_payload
                
                # 1번의 sendall로 전송 처리
                conn.sendall(send_buf)
                print(f"[Thread-{addr[1]}] 🔒 서버 응답 전송 완료")

            except Exception as e:
                print(f"[Thread-{addr[1]}] ❌ 복호화 실패! (데이터 위조 또는 키 불일치) : {e}")
        else:
            print(f"[Thread-{addr[1]}] ⚠️ TCP 단편화로 인해 전체 데이터를 한 번에 수신하지 못했습니다.")

    except Exception as e:
        print(f"[Thread-{addr[1]}] ❌ 연결 처리 중 오류 발생: {e}")
    finally:
        conn.close()
        print(f"[Thread-{addr[1]}] 클라이언트 연결 종료\n")


def main():
    host = '0.0.0.0' # 모든 인터페이스에서 대기
    port = 51822

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_sock.bind((host, port))
        server_sock.listen(10)
        print(f"🚀 Python 서버가 포트 {port}에서 대기 중입니다...")
    except Exception as e:
        print(f"❌ 서버 바인딩 실패: {e}")
        sys.exit(1)

    try:
        while True:
            # 클라이언트 연결 대기
            conn, addr = server_sock.accept()
            
            # 새 스레드를 생성하여 클라이언트 연결 위임
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.daemon = True # 메인 스레드 종료 시 같이 종료되도록 설정
            client_thread.start()
            
    except KeyboardInterrupt:
        print("\n🛑 서버를 종료합니다.")
    finally:
        server_sock.close()

if __name__ == "__main__":
    main()
