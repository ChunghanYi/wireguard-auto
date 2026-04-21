"""
   SPDX-License-Identifier: MIT

   Authenticated Encryption/Decryption examples using libsodium library
   Key exchange: X25519, Encryption: XSalsa20, Authentication: Poly1305
"""

import socket
import struct
import threading
import base64
import argparse
import sys
import os
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box

class AuthServer:
    LENGTH_SIZE = 4
    NONCE_SIZE = 24
    KEY_SIZE = 32
    B64_KEY_SIZE = 44
    BUFFER_SIZE = 4096

    def __init__(self, host='0.0.0.0', port=51822):
        self.host = host
        self.port = port

    def _recvall(self, sock, n):
        data = bytearray()
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet: return None
            data.extend(packet)
        return bytes(data)

    def _handle_client(self, conn, addr):
        try:
            # 1. 클라이언트 공개키 수신 (Base64)
            client_pubkey_b64 = self._recvall(conn, self.B64_KEY_SIZE)
            if not client_pubkey_b64: return
            client_pubkey_bytes = base64.b64decode(client_pubkey_b64)
            client_public_key = PublicKey(client_pubkey_bytes)

            # 2. 서버 키쌍 생성 및 공개키 전송 (Base64)
            server_private_key = PrivateKey.generate()
            server_pubkey_b64 = base64.b64encode(bytes(server_private_key.public_key))
            conn.sendall(server_pubkey_b64)

            box = Box(server_private_key, client_public_key)

            # 3. 데이터 수신 및 복호화
            recv_buf = conn.recv(self.BUFFER_SIZE)
            if len(recv_buf) < self.LENGTH_SIZE + self.NONCE_SIZE: return

            payload_len = struct.unpack(">I", recv_buf[:self.LENGTH_SIZE])[0]
            if len(recv_buf) >= self.LENGTH_SIZE + payload_len:
                payload = recv_buf[self.LENGTH_SIZE : self.LENGTH_SIZE + payload_len]
                decrypted_msg = box.decrypt(payload)
                print(f"[Client {addr}] 🔓 {decrypted_msg.decode('utf-8')}")

                # 4. 응답 전송
                resp_msg = "서버에서 보내는 암호화된 응답입니다! (Python Server)".encode('utf-8')
                encrypted_resp = box.encrypt(resp_msg, nacl.utils.random(self.NONCE_SIZE))

                send_buf = struct.pack(">I", len(encrypted_resp)) + bytes(encrypted_resp)
                conn.sendall(send_buf)

        except Exception as e:
            print(f"[Client {addr}] ❌ 오류: {e}")
        finally:
            conn.close()

    def start(self, max_clients):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, self.port))
        server_sock.listen(max_clients)
        print(f"🚀 Python 서버가 포트 {self.port}에서 대기 중입니다... (Max: {max_clients})")

        try:
            while True:
                conn, addr = server_sock.accept()
                threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("\n🛑 서버 종료")
        finally:
            server_sock.close()

def daemonize():
    if os.fork() > 0: sys.exit()
    os.setsid()
    if os.fork() > 0: sys.exit()
    sys.stdout.flush()
    sys.stderr.flush()
    with open(os.devnull, 'r') as f: os.dup2(f.fileno(), sys.stdin.fileno())
    with open(os.devnull, 'a+') as f: os.dup2(f.fileno(), sys.stdout.fileno())
    with open(os.devnull, 'a+') as f: os.dup2(f.fileno(), sys.stderr.fileno())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Auth Encrypt Python Server")
    parser.add_argument('-p', '--port', type=int, default=51822, help='Server port')
    parser.add_argument('-d', '--daemon', action='store_true', help='Run in daemon mode')
    parser.add_argument('-m', '--max-clients', type=int, default=10, help='Max client connections')
    args = parser.parse_args()

    if args.daemon:
        daemonize()

    server = AuthServer(host='0.0.0.0', port=args.port)
    server.start(max_clients=args.max_clients)
