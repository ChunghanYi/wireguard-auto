"""
   SPDX-License-Identifier: MIT

   Authenticated Encryption/Decryption examples using PyNacl library
   Key exchange: X25519, Encryption: XSalsa20, Authentication: Poly1305
"""

from std.python import Python, PythonObject

def handle_client(conn: PythonObject, addr: PythonObject) raises:
    try:
        struct_mod = Python.import_module("struct")
        base64_mod = Python.import_module("base64")
        nacl_public = Python.import_module("nacl.public")
        nacl_utils = Python.import_module("nacl.utils")
        builtins = Python.import_module("builtins")
        Slice = builtins.slice

        client_pubkey_b64 = builtins.bytearray()
        while builtins.len(client_pubkey_b64) < 44:
            packet = conn.recv(44 - builtins.len(client_pubkey_b64))
            if not packet:
                return
            _ = client_pubkey_b64.extend(packet)
            
        client_pubkey_bytes = base64_mod.b64decode(client_pubkey_b64)
        client_public_key = nacl_public.PublicKey(client_pubkey_bytes)

        server_private_key = nacl_public.PrivateKey.generate()
        server_pubkey_b64 = base64_mod.b64encode(builtins.bytes(server_private_key.public_key))
        _ = conn.sendall(server_pubkey_b64)

        box = nacl_public.Box(server_private_key, client_public_key)

        recv_buf = conn.recv(4096)
        if builtins.len(recv_buf) < 28:
            return

        payload_len = struct_mod.unpack(">I", recv_buf[Slice(0, 4)])[0]
        if builtins.len(recv_buf) >= 4 + payload_len:
            payload = recv_buf[Slice(4, 4 + payload_len)]
            decrypted_msg = box.decrypt(payload)
            
            addr_str = builtins.str(addr)
            msg_str = decrypted_msg.decode("utf-8")
            print("[Client", addr_str, "] 🔓", msg_str)
            
            resp_msg = builtins.bytes("서버에서 보내는 암호화된 응답입니다! (Mojo Server)", "utf-8")
            encrypted_resp = box.encrypt(resp_msg, nacl_utils.random(24))
            
            enc_bytes = builtins.bytes(encrypted_resp)
            send_buf = struct_mod.pack(">I", builtins.len(enc_bytes)) + enc_bytes
            _ = conn.sendall(send_buf)

    except e:
        print("[Client Error] ❌", e)
    
    _ = conn.close()

def daemonize() raises:
    builtins = Python.import_module("builtins")
    # 💡 픽스 1: Python exec()을 사용하여 Mojo의 엄격한 타입 검사를 회피
    # sys.exit() 대신 os._exit(0)을 써서 예외(Exception) 전파를 막습니다.
    daemon_code = "import os\nif os.fork() > 0: os._exit(0)\nos.setsid()\nif os.fork() > 0: os._exit(0)"
    _ = builtins.exec(daemon_code)

struct AuthServer:
    var host: PythonObject
    var port: PythonObject
    var max_clients: PythonObject
    
    def __init__(out self, host: PythonObject, port: PythonObject, max_clients: PythonObject):
        self.host = host
        self.port = port
        self.max_clients = max_clients

    def start(self) raises:
        socket_mod = Python.import_module("socket")
        os = Python.import_module("os")
        builtins = Python.import_module("builtins")
        
        server_sock = socket_mod.socket(socket_mod.AF_INET, socket_mod.SOCK_STREAM)
        _ = server_sock.setsockopt(socket_mod.SOL_SOCKET, socket_mod.SO_REUSEADDR, 1)
        
        make_tuple = Python.evaluate("lambda a, b: (a, b)")
        addr_tuple = make_tuple(self.host, self.port)
        _ = server_sock.bind(addr_tuple)
        _ = server_sock.listen(self.max_clients)
        
        print("🚀 Mojo 서버가 포트", builtins.str(self.port), "에서 대기 중입니다...")

        while True:
            conn_addr = server_sock.accept()
            conn = conn_addr[0]
            addr = conn_addr[1]
            
            pid = os.fork()
            
            # 💡 픽스 2: Int 캐스팅 대신, 가장 안정적인 String 변환 후 "0"과 비교
            if String(builtins.str(pid)) == "0":
                _ = server_sock.close()
                handle_client(conn, addr)
                _ = os._exit(0) # 예외 없는 종료
            else:
                _ = conn.close()

def main() raises:
    argparse = Python.import_module("argparse")
    builtins = Python.import_module("builtins")
    parser = argparse.ArgumentParser(description="Auth Encrypt Mojo Server")
    
    _ = parser.add_argument("-p", "--port", type=builtins.int, default=51822)
    _ = parser.add_argument("-d", "--daemon", action="store_true")
    _ = parser.add_argument("-m", "--max-clients", type=builtins.int, default=10)
    
    args = parser.parse_args()
    
    if args.daemon:
        daemonize()

    server = AuthServer("0.0.0.0", args.port, args.max_clients)
    server.start()
