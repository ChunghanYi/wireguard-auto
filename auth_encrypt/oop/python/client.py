"""
   SPDX-License-Identifier: MIT

   Authenticated Encryption/Decryption examples using libsodium library
   Key exchange: X25519, Encryption: XSalsa20, Authentication: Poly1305
"""

import socket
import struct
import os
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box

class AuthClient:
    LENGTH_SIZE = 4
    NONCE_SIZE = 24
    KEY_SIZE = 32
    BUFFER_SIZE = 4096

    def __init__(self, host='127.0.0.1', port=51822):
        self.host = host
        self.port = port
        self.sock = None
        self.box = None
        self.private_key = PrivateKey.generate()

    def connect_and_exchange(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))

        self.sock.sendall(bytes(self.private_key.public_key))
        
        server_pubkey_bytes = self.sock.recv(self.KEY_SIZE)
        server_public_key = PublicKey(server_pubkey_bytes)
        
        self.box = Box(self.private_key, server_public_key)

    def send_and_receive(self, message):
        if not self.box: raise Exception("키 교환이 완료되지 않았습니다.")

        msg_bytes = message.encode('utf-8')
        nonce = nacl.utils.random(self.NONCE_SIZE)
        encrypted_message = self.box.encrypt(msg_bytes, nonce)
        
        send_buf = struct.pack(">I", len(encrypted_message)) + bytes(encrypted_message)
        self.sock.sendall(send_buf)
        print("🔒 암호화된 메시지 전송 성공 (Python)!")

        recv_buf = self.sock.recv(self.BUFFER_SIZE)
        if len(recv_buf) >= self.LENGTH_SIZE + self.NONCE_SIZE:
            payload_len = struct.unpack(">I", recv_buf[:self.LENGTH_SIZE])[0]
            payload = recv_buf[self.LENGTH_SIZE : self.LENGTH_SIZE + payload_len]
            decrypted_msg = self.box.decrypt(payload)
            print(f"🔓 서버로부터의 응답: {decrypted_msg.decode('utf-8')}")

    def close(self):
        if self.sock: self.sock.close()

if __name__ == "__main__":
    client = AuthClient()
    try:
        client.connect_and_exchange()
        client.send_and_receive("안녕하세요! Python 클래스 클라이언트가 보낸 비밀 메시지입니다.")
    except Exception as e:
        print(f"❌ 오류 발생: {e}")
    finally:
        client.close()
