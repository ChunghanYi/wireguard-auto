"""
   SPDX-License-Identifier: MIT

   Authenticated Encryption/Decryption examples using libsodium library
   Key exchange: X25519, Encryption: XSalsa20, Authentication: Poly1305
"""

import socket
import struct
import base64
import argparse
import sys
import os
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box

class AuthClient:
    LENGTH_SIZE = 4
    NONCE_SIZE = 24
    KEY_SIZE = 32
    B64_KEY_SIZE = 44
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

        # 1. 클라이언트 공개키 Base64 인코딩 후 전송
        client_pubkey_b64 = base64.b64encode(bytes(self.private_key.public_key))
        self.sock.sendall(client_pubkey_b64)

        # 2. 서버 공개키 수신 (Base64) 및 디코딩
        server_pubkey_b64 = self.sock.recv(self.B64_KEY_SIZE)
        server_pubkey_bytes = base64.b64decode(server_pubkey_b64)
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

def daemonize():
    if os.fork() > 0: sys.exit()
    os.setsid()
    if os.fork() > 0: sys.exit()
    with open(os.devnull, 'r') as f: os.dup2(f.fileno(), sys.stdin.fileno())
    with open(os.devnull, 'a+') as f: os.dup2(f.fileno(), sys.stdout.fileno())
    with open(os.devnull, 'a+') as f: os.dup2(f.fileno(), sys.stderr.fileno())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Auth Encrypt Python Client")
    parser.add_argument('-i', '--ip', type=str, default='127.0.0.1', help='Server IP')
    parser.add_argument('-p', '--port', type=int, default=51822, help='Server port')
    parser.add_argument('-d', '--daemon', action='store_true', help='Run in daemon mode')
    args = parser.parse_args()

    if args.daemon:
        daemonize()

    client = AuthClient(host=args.ip, port=args.port)
    try:
        client.connect_and_exchange()
        client.send_and_receive("안녕하세요! Python 클래스 클라이언트가 보낸 비밀 메시지입니다.")
    except Exception as e:
        print(f"❌ 오류 발생: {e}")
    finally:
        client.close()
