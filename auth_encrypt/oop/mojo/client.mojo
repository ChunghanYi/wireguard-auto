"""
   SPDX-License-Identifier: MIT

   Authenticated Encryption/Decryption examples using PyNacl library
   Key exchange: X25519, Encryption: XSalsa20, Authentication: Poly1305
"""

from std.python import Python, PythonObject

def daemonize() raises:
    builtins = Python.import_module("builtins")
    # 데몬화 중 발생하는 예외 및 타입 오류를 막기 위해 파이썬 문자열 스크립트로 위임
    daemon_code = "import os\nif os.fork() > 0: os._exit(0)\nos.setsid()\nif os.fork() > 0: os._exit(0)"
    _ = builtins.exec(daemon_code)

struct AuthClient:
    var host: PythonObject
    var port: PythonObject
    var sock: PythonObject
    var box: PythonObject
    var private_key: PythonObject
    
    var socket_mod: PythonObject
    var struct_mod: PythonObject
    var base64_mod: PythonObject
    var nacl_public: PythonObject
    var nacl_utils: PythonObject
    var builtins: PythonObject

    # 최신 규격에 맞게 mut 대신 out 사용
    def __init__(out self, host: PythonObject, port: PythonObject) raises:
        self.host = host
        self.port = port
        self.sock = Python.none()
        self.box = Python.none()
        
        self.socket_mod = Python.import_module("socket")
        self.struct_mod = Python.import_module("struct")
        self.base64_mod = Python.import_module("base64")
        self.nacl_public = Python.import_module("nacl.public")
        self.nacl_utils = Python.import_module("nacl.utils")
        self.builtins = Python.import_module("builtins")
        
        self.private_key = self.nacl_public.PrivateKey.generate()

    def connect_and_exchange(mut self) raises:
        self.sock = self.socket_mod.socket(self.socket_mod.AF_INET, self.socket_mod.SOCK_STREAM)
        
        # Mojo 튜플 변환 충돌 우회를 위한 파이썬 람다 함수 사용
        make_tuple = Python.evaluate("lambda a, b: (a, b)")
        addr_tuple = make_tuple(self.host, self.port)
        _ = self.sock.connect(addr_tuple)

        pub_key_bytes = self.builtins.bytes(self.private_key.public_key)
        client_pubkey_b64 = self.base64_mod.b64encode(pub_key_bytes)
        _ = self.sock.sendall(client_pubkey_b64)
        
        server_pubkey_b64 = self.sock.recv(44)
        server_pubkey_bytes = self.base64_mod.b64decode(server_pubkey_b64)
        server_public_key = self.nacl_public.PublicKey(server_pubkey_bytes)
        
        self.box = self.nacl_public.Box(self.private_key, server_public_key)

    def send_and_receive(mut self, message: String) raises:
        msg_bytes = self.builtins.bytes(message, "utf-8")
        nonce = self.nacl_utils.random(24)
        encrypted_message = self.box.encrypt(msg_bytes, nonce)
        
        enc_bytes = self.builtins.bytes(encrypted_message)
        payload_len = self.builtins.len(enc_bytes)
        len_packed = self.struct_mod.pack(">I", payload_len)
        send_buf = len_packed + enc_bytes
        
        _ = self.sock.sendall(send_buf)
        print("🔒 암호화된 메시지 전송 성공 (Mojo)!")

        recv_buf = self.sock.recv(4096)
        recv_len = self.builtins.len(recv_buf)
        
        if recv_len >= 28:
            Slice = self.builtins.slice
            len_data = recv_buf[Slice(0, 4)]
            resp_payload_len = self.struct_mod.unpack(">I", len_data)[0]
            
            payload = recv_buf[Slice(4, 4 + resp_payload_len)]
            decrypted_msg = self.box.decrypt(payload)
            
            msg_str = decrypted_msg.decode("utf-8")
            print("🔓 서버로부터의 응답:", msg_str)

    def close(mut self) raises:
        if self.sock != Python.none():
            _ = self.sock.close()

def main() raises:
    argparse = Python.import_module("argparse")
    builtins = Python.import_module("builtins")
    parser = argparse.ArgumentParser(description="Auth Encrypt Mojo Client")
    
    _ = parser.add_argument("-i", "--ip", default="127.0.0.1")
    _ = parser.add_argument("-p", "--port", type=builtins.int, default=51822)
    _ = parser.add_argument("-d", "--daemon", action="store_true")
    
    args = parser.parse_args()
    
    if args.daemon:
        daemonize()
        
    client = AuthClient(args.ip, args.port)
    client.connect_and_exchange()
    client.send_and_receive("안녕하세요! std.python 임포트까지 완벽히 적용된 클라이언트입니다.")
    client.close()
