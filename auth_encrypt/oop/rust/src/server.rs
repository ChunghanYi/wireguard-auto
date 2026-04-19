/* SPDX-License-Identifier: MIT
 *
 * Authenticated Encryption/Decryption examples using libsodium library
 * Key exchange: X25519, Encryption: XSalsa20, Authentication: Poly1305
 */

use sodiumoxide::crypto::box_;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

const LENGTH_SIZE: usize = 4;
const NONCE_SIZE: usize = 24;
const KEY_SIZE: usize = 32;
const BUFFER_SIZE: usize = 4096;

pub struct AuthServer {
    address: String,
}

impl AuthServer {
    pub fn new(address: &str) -> Self {
        AuthServer {
            address: address.to_string(),
        }
    }

    fn handle_client(mut stream: TcpStream) {
        let mut client_pk_bytes = [0u8; KEY_SIZE];
        if stream.read_exact(&mut client_pk_bytes).is_err() { return; }
        
        if let Some(client_pk) = box_::PublicKey::from_slice(&client_pk_bytes) {
            let (server_pk, server_sk) = box_::gen_keypair();
            if stream.write_all(server_pk.as_ref()).is_err() { return; }

            let mut recv_buf = [0u8; BUFFER_SIZE];
            if let Ok(n) = stream.read(&mut recv_buf) {
                if n >= LENGTH_SIZE + NONCE_SIZE + box_::MACBYTES {
                    let payload_len = u32::from_be_bytes(recv_buf[0..LENGTH_SIZE].try_into().unwrap()) as usize;
                    if n >= LENGTH_SIZE + payload_len {
                        let nonce = box_::Nonce::from_slice(&recv_buf[LENGTH_SIZE..LENGTH_SIZE + NONCE_SIZE]).unwrap();
                        let ciphertext = &recv_buf[LENGTH_SIZE + NONCE_SIZE..LENGTH_SIZE + payload_len];

                        if let Ok(decrypted) = box_::open(ciphertext, &nonce, &client_pk, &server_sk) {
                            println!("🔓 복호화된 메시지: {}", String::from_utf8_lossy(&decrypted));

                            let resp_msg = b"\xec\x84\x9c\xeb\xb2\x84 \xec\x9d\x91\xeb\x8b\xb5 (Rust Server Struct)"; 
                            let resp_nonce = box_::gen_nonce();
                            let resp_ciphertext = box_::seal(resp_msg, &resp_nonce, &client_pk, &server_sk);

                            let resp_payload_len = (NONCE_SIZE + resp_ciphertext.len()) as u32;
                            let mut send_buf = Vec::with_capacity(LENGTH_SIZE + resp_payload_len as usize);
                            send_buf.extend_from_slice(&resp_payload_len.to_be_bytes());
                            send_buf.extend_from_slice(resp_nonce.as_ref());
                            send_buf.extend_from_slice(&resp_ciphertext);

                            let _ = stream.write_all(&send_buf);
                        }
                    }
                }
            }
        }
    }

    pub fn run(&self) {
        let listener = TcpListener::bind(&self.address).expect("서버 바인딩 실패");
        println!("🚀 Rust 서버가 {}에서 대기 중입니다...", self.address);

        for stream in listener.incoming() {
            if let Ok(stream) = stream {
                thread::spawn(move || Self::handle_client(stream));
            }
        }
    }
}

fn main() {
    sodiumoxide::init().expect("libsodium 초기화 실패");
    let server = AuthServer::new("0.0.0.0:51822");
    server.run();
}
