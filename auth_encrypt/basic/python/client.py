"""
   SPDX-License-Identifier: MIT

   Authenticated Encryption/Decryption examples using libsodium library
   Key exchange: X25519, Encryption: XSalsa20, Authentication: Poly1305
"""

import socket
import struct
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

def main():
    # TCP로 C++ 서버에 연결
    host = '127.0.0.1'
    port = 51822
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
    except ConnectionRefusedError:
        print("❌ 서버 연결 실패. 서버가 실행 중인지 확인하세요.")
        sys.exit(1)

    try:
        # 1. 클라이언트용 X25519 키쌍 생성
        client_private_key = PrivateKey.generate()
        client_public_key = client_private_key.public_key

        # 2. 클라이언트 공개키 서버로 전송 (32 bytes)
        sock.sendall(bytes(client_public_key))

        # 3. 서버의 공개키 수신 (32 bytes)
        server_pubkey_bytes = recvall(sock, KEY_SIZE)
        if not server_pubkey_bytes:
            print("❌ 서버 공개키 수신 실패")
            return
            
        server_public_key = PublicKey(server_pubkey_bytes)

        # 4. Box 객체 생성 (나의 비밀키 + 상대방의 공개키 결합)
        box = Box(client_private_key, server_public_key)

        # 5. 암호화할 메시지와 Nonce 준비
        msg = "안녕하세요! Python 클라이언트가 보낸 비밀 메시지입니다.".encode('utf-8')
        nonce = nacl.utils.random(NONCE_SIZE)

        # 6. Authenticated Encryption 수행 (MAC 자동 포함)
        # PyNaCl의 encrypt 함수는 기본적으로 결과물에 [Nonce(24) + Ciphertext] 형태로 합쳐서 반환합니다.
        encrypted_message = box.encrypt(msg, nonce)
        payload = bytes(encrypted_message)

        # 7. 데이터 전송 포맷 맞추기: Length(4 bytes, Big Endian) + (Nonce + 암호문)
        # 1번의 sendall로 전송 처리
        payload_len = len(payload)
        send_buf = struct.pack(">I", payload_len) + payload
        sock.sendall(send_buf)

        print("🔒 암호화된 메시지 전송 성공 (Python)!")

        # 8. 서버로부터의 응답 수신 (1번의 recv로 처리)
        recv_buf = sock.recv(BUFFER_SIZE)
        
        if not recv_buf:
            print("❌ 서버로부터 응답이 없습니다.")
            return

        if len(recv_buf) >= LENGTH_SIZE + NONCE_SIZE + MAC_SIZE:
            # 첫 4바이트에서 길이 추출 (Big Endian)
            resp_payload_len = struct.unpack(">I", recv_buf[:LENGTH_SIZE])[0]

            if len(recv_buf) >= LENGTH_SIZE + resp_payload_len:
                # Payload(Nonce + Ciphertext) 분리
                resp_payload = recv_buf[LENGTH_SIZE : LENGTH_SIZE + resp_payload_len]

                try:
                    # 9. 복호화 수행
                    # PyNaCl의 decrypt는 데이터의 앞 24바이트를 자동으로 Nonce로 인식하고 복호화합니다.
                    decrypted_msg = box.decrypt(resp_payload)
                    print(f"🔓 서버로부터의 응답: {decrypted_msg.decode('utf-8')}")
                except Exception as e:
                    print(f"❌ 서버 응답 복호화 실패! (데이터 위조 또는 키 불일치) : {e}")
            else:
                print("⚠️ TCP 단편화로 인해 응답을 한 번에 수신하지 못했습니다.")
        else:
            print("❌ 수신된 페이로드 크기가 너무 작습니다.")

    finally:
        sock.close()

if __name__ == "__main__":
    main()
