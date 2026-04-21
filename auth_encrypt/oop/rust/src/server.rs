/* SPDX-License-Identifier: MIT
 *
 * Authenticated Encryption/Decryption examples using libsodium library
 * Key exchange: X25519, Encryption: XSalsa20, Authentication: Poly1305
 */

use sodiumoxide::crypto::box_;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use base64::prelude::*;
use clap::Parser;
use daemonize::Daemonize;

const LENGTH_SIZE: usize = 4;
const NONCE_SIZE: usize = 24;
//const KEY_SIZE: usize = 32;
const B64_KEY_SIZE: usize = 44;
const BUFFER_SIZE: usize = 4096;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct ServerArgs {
    #[arg(short, long, default_value_t = String::from("51822"))]
    port: String,
    #[arg(short, long, default_value_t = false)]
    daemon: bool,
    #[arg(short, long, default_value_t = 10)]
    max_clients: usize,
}

pub struct AuthServer {
    address: String,
    max_clients: usize,
}

impl AuthServer {
    pub fn new(address: &str, max_clients: usize) -> Self {
        AuthServer { address: address.to_string(), max_clients }
    }

    fn handle_client(mut stream: TcpStream) {
        // 1. 클라이언트 공개키 수신 (Base64)
        let mut client_pk_b64 = [0u8; B64_KEY_SIZE];
        if stream.read_exact(&mut client_pk_b64).is_err() { return; }

        let client_pk_bytes = match BASE64_STANDARD.decode(&client_pk_b64) {
            Ok(bytes) => bytes,
            Err(_) => return,
        };

        if let Some(client_pk) = box_::PublicKey::from_slice(&client_pk_bytes) {
            // 2. 서버 키쌍 생성 및 공개키 전송 (Base64)
            let (server_pk, server_sk) = box_::gen_keypair();

            let server_pk_b64 = BASE64_STANDARD.encode(server_pk.as_ref());
            if stream.write_all(server_pk_b64.as_bytes()).is_err() { return; }

            let mut recv_buf = [0u8; BUFFER_SIZE];
            if let Ok(n) = stream.read(&mut recv_buf) {
                if n >= LENGTH_SIZE + NONCE_SIZE + box_::MACBYTES {
                    let payload_len = u32::from_be_bytes(recv_buf[0..LENGTH_SIZE].try_into().unwrap()) as usize;
                    if n >= LENGTH_SIZE + payload_len {
                        let nonce = box_::Nonce::from_slice(&recv_buf[LENGTH_SIZE..LENGTH_SIZE + NONCE_SIZE]).unwrap();
                        let ciphertext = &recv_buf[LENGTH_SIZE + NONCE_SIZE..LENGTH_SIZE + payload_len];

                        if let Ok(decrypted) = box_::open(ciphertext, &nonce, &client_pk, &server_sk) {
                            println!("🔓 복호화된 메시지: {}", String::from_utf8_lossy(&decrypted));

                            let resp_msg = b"\xec\x84\x9c\xeb\xb2\x84 \xec\x9d\x91\xeb\x8b\xb5 (Rust Server)";
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
        let active_connections = Arc::new(AtomicUsize::new(0));

        println!("🚀 Rust 서버가 {}에서 대기 중입니다... (Max: {})", self.address, self.max_clients);

        for stream in listener.incoming() {
            if let Ok(stream) = stream {
                let current_conns = active_connections.load(Ordering::SeqCst);
                if current_conns >= self.max_clients {
                    println!("⚠️ 최대 접속 수 초과로 연결을 거부합니다.");
                    continue;
                }

                active_connections.fetch_add(1, Ordering::SeqCst);
                let active_connections_clone = Arc::clone(&active_connections);

                thread::spawn(move || {
                    Self::handle_client(stream);
                    active_connections_clone.fetch_sub(1, Ordering::SeqCst);
                });
            }
        }
    }
}

fn main() {
    let args = ServerArgs::parse();

    if args.daemon {
        let daemonize = Daemonize::new().working_directory("/tmp");
        match daemonize.start() {
            Ok(_) => println!("데몬 모드로 전환되었습니다."),
            Err(e) => eprintln!("데몬화 실패: {}", e),
        }
    }

    sodiumoxide::init().expect("libsodium 초기화 실패");
    let addr = format!("0.0.0.0:{}", args.port);
    let server = AuthServer::new(&addr, args.max_clients);
    server.run();
}
