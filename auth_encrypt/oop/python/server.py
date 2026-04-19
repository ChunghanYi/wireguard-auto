"""
   SPDX-License-Identifier: MIT

   Authenticated Encryption/Decryption examples using libsodium library
   Key exchange: X25519, Encryption: XSalsa20, Authentication: Poly1305
"""

import socket
import struct
import threading
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box

class AuthServer:
    LENGTH_SIZE = 4
    NONCE_SIZE = 24
    KEY_SIZE = 32
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
            client_pubkey_bytes = self._recvall(conn, self.KEY_SIZE)
            if not client_pubkey_bytes: return
            client_public_key = PublicKey(client_pubkey_bytes)

            server_private_key = PrivateKey.generate()
            conn.sendall(bytes(server_private_key.public_key))

            box = Box(server_private_key, client_public_key)

            recv_buf = conn.recv(self.BUFFER_SIZE)
            if len(recv_buf) < self.LENGTH_SIZE + self.NONCE_SIZE: return

            payload_len = struct.unpack(">I", recv_buf[:self.LENGTH_SIZE])[0]
            if len(recv_buf) >= self.LENGTH_SIZE + payload_len:
                payload = recv_buf[self.LENGTH_SIZE : self.LENGTH_SIZE + payload_len]
                decrypted_msg = box.decrypt(payload)
                print(f"[Client {addr}] 🔓 {decrypted_msg.decode('utf-8')}")
                
                resp_msg = "서버에서 보내는 암호화된 응답입니다! (Python Server)".encode('utf-8')
                encrypted_resp = box.encrypt(resp_msg, nacl.utils.random(self.NONCE_SIZE))
                
                send_buf = struct.pack(">I", len(encrypted_resp)) + bytes(encrypted_resp)
                conn.sendall(send_buf)

        except Exception as e:
            print(f"[Client {addr}] ❌ 오류: {e}")
        finally:
            conn.close()

    def start(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, self.port))
        server_sock.listen(10)
        print(f"🚀 Python 서버가 포트 {self.port}에서 대기 중입니다...")

        try:
            while True:
                conn, addr = server_sock.accept()
                threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("\n🛑 서버 종료")
        finally:
            server_sock.close()

if __name__ == "__main__":
    server = AuthServer()
    server.start()
