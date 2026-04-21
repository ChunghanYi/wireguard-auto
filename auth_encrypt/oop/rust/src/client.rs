/* SPDX-License-Identifier: MIT
 *
 * Authenticated Encryption/Decryption examples using libsodium library
 * Key exchange: X25519, Encryption: XSalsa20, Authentication: Poly1305
 */

use sodiumoxide::crypto::box_;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::fs;
use std::path::Path;
use base64::prelude::*;
use clap::Parser;
use daemonize::Daemonize;

const LENGTH_SIZE: usize = 4;
const NONCE_SIZE: usize = 24;
const KEY_SIZE: usize = 32;
const B64_KEY_SIZE: usize = 44;
const BUFFER_SIZE: usize = 4096;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct ClientArgs {
    #[arg(short, long, default_value_t = String::from("127.0.0.1"))]
    ip: String,
    #[arg(short, long, default_value_t = String::from("51822"))]
    port: String,
    #[arg(short, long, default_value_t = false)]
    daemon: bool,
}

pub struct AuthClient {
    stream: TcpStream,
    client_sk: box_::SecretKey,
    server_pk: box_::PublicKey,
}

impl AuthClient {
    pub fn connect(address: &str) -> Result<Self, String> {
        let mut stream = TcpStream::connect(address).map_err(|e| e.to_string())?;

        let (client_pk, client_sk) = box_::gen_keypair();

        // 1. 클라이언트 공개키 Base64 인코딩 후 전송
        let client_pk_b64 = BASE64_STANDARD.encode(client_pk.as_ref());
        stream.write_all(client_pk_b64.as_bytes()).map_err(|e| e.to_string())?;

        // 2. 서버 공개키 수신 (Base64) 및 디코딩
        let mut server_pk_b64 = [0u8; B64_KEY_SIZE];
        stream.read_exact(&mut server_pk_b64).map_err(|e| e.to_string())?;

        let server_pk_bytes: [u8; KEY_SIZE] = BASE64_STANDARD.decode(&server_pk_b64)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "잘못된 디코딩 길이")?;

        let server_pk = box_::PublicKey::from_slice(&server_pk_bytes).ok_or("잘못된 서버 공개키")?;

        let client = AuthClient { stream, client_sk, server_pk };
        //client.verify_server_key(&server_pk_bytes); // TOFU 로직 실행

        Ok(client)
    }

	#[allow(dead_code)]
    fn verify_server_key(&self, server_pk_bytes: &[u8; KEY_SIZE]) {
        let known_hosts_file = "known_server.pub";
        if Path::new(known_hosts_file).exists() {
            let stored_pk_bytes = fs::read(known_hosts_file).expect("파일 읽기 실패");
            if stored_pk_bytes != server_pk_bytes {
                eprintln!("🚨 [보안 경고] 서버의 공개키가 이전에 저장된 키와 다릅니다!");
                std::process::exit(1);
            } else {
                println!("✅ 서버 공개키 검증 완료 (TOFU)");
            }
        } else {
            fs::write(known_hosts_file, server_pk_bytes).expect("파일 쓰기 실패");
            println!("⚠️ [TOFU] 서버에 처음 접속했습니다. 서버 키를 저장합니다.");
        }
    }

    pub fn send_and_receive(&mut self, message: &str) {
        let nonce = box_::gen_nonce();
        let ciphertext = box_::seal(message.as_bytes(), &nonce, &self.server_pk, &self.client_sk);

        let payload_len = (NONCE_SIZE + ciphertext.len()) as u32;
        let mut send_buf = Vec::with_capacity(LENGTH_SIZE + payload_len as usize);
        send_buf.extend_from_slice(&payload_len.to_be_bytes());
        send_buf.extend_from_slice(nonce.as_ref());
        send_buf.extend_from_slice(&ciphertext);

        self.stream.write_all(&send_buf).expect("전송 실패");
        println!("🔒 암호화된 메시지 전송 성공!");

        let mut recv_buf = [0u8; BUFFER_SIZE];
        if let Ok(n) = self.stream.read(&mut recv_buf) {
            if n >= LENGTH_SIZE + NONCE_SIZE + box_::MACBYTES {
                let resp_payload_len = u32::from_be_bytes(recv_buf[0..LENGTH_SIZE].try_into().unwrap()) as usize;
                if n >= LENGTH_SIZE + resp_payload_len {
                    let resp_nonce = box_::Nonce::from_slice(&recv_buf[LENGTH_SIZE..LENGTH_SIZE + NONCE_SIZE]).unwrap();
                    let resp_ciphertext = &recv_buf[LENGTH_SIZE + NONCE_SIZE..LENGTH_SIZE + resp_payload_len];

                    if let Ok(decrypted) = box_::open(resp_ciphertext, &resp_nonce, &self.server_pk, &self.client_sk) {
                        println!("🔓 서버 응답: {}", String::from_utf8_lossy(&decrypted));
                    }
                }
            }
        }
    }
}

fn main() {
    let args = ClientArgs::parse();

    if args.daemon {
        let daemonize = Daemonize::new().working_directory("/tmp");
        if let Err(e) = daemonize.start() {
            eprintln!("데몬화 실패: {}", e);
        }
    }

    sodiumoxide::init().expect("libsodium 초기화 실패");
    let addr = format!("{}:{}", args.ip, args.port);

    match AuthClient::connect(&addr) {
        Ok(mut client) => client.send_and_receive("안녕하세요! Rust 구조체 클라이언트입니다."),
        Err(e) => eprintln!("❌ 연결 실패: {}", e),
    }
}
