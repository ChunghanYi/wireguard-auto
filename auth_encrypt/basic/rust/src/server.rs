/* SPDX-License-Identifier: MIT
 *
 * Authenticated Encryption/Decryption examples using libsodium library
 * Key exchange: X25519, Encryption: XSalsa20, Authentication: Poly1305
 */

use sodiumoxide::crypto::box_;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

// 상수 정의
const LENGTH_SIZE: usize = 4;
const NONCE_SIZE: usize = 24;
const KEY_SIZE: usize = 32;
const BUFFER_SIZE: usize = 4096;

fn handle_client(mut stream: TcpStream) {
	let addr = stream.peer_addr().unwrap();
	println!("[Thread-{}] 새로운 클라이언트 연결 처리 시작", addr);

	// 1. 클라이언트의 X25519 공개키 수신
	let mut client_pk_bytes = [0u8; KEY_SIZE];
	if stream.read_exact(&mut client_pk_bytes).is_err() {
		println!("[Thread-{}] ❌ 클라이언트 공개키 수신 실패", addr);
		return;
	}

	let client_pk = match box_::PublicKey::from_slice(&client_pk_bytes) {
		Some(pk) => pk,
			None => {
				println!("[Thread-{}] ❌ 잘못된 클라이언트 공개키", addr);
				return;
			}
	};
	println!("[Thread-{}] 클라이언트 공개키 수신 완료", addr);

	// 2. 서버의 X25519 키쌍 생성
	let (server_pk, server_sk) = box_::gen_keypair();

	// 3. 서버의 공개키를 클라이언트에게 전송 (평문)
	if stream.write_all(server_pk.as_ref()).is_err() {
		println!("[Thread-{}] ❌ 서버 공개키 전송 실패", addr);
		return;
	}
	println!("[Thread-{}] 서버 공개키 전송 완료", addr);

	// 4. 데이터 수신 (1번의 Read 호출)
	let mut recv_buf = [0u8; BUFFER_SIZE];
	let n = match stream.read(&mut recv_buf) {
		Ok(size) => size,
			Err(e) => {
				println!("[Thread-{}] ❌ 데이터 수신 실패: {}", addr, e);
				return;
			}
	};

	// 최소한의 페이로드 크기 검증 (Length + Nonce + MAC)
	if n < LENGTH_SIZE + NONCE_SIZE + box_::MACBYTES {
		println!("[Thread-{}] ❌ 수신된 페이로드 크기가 너무 작습니다.", addr);
		return;
	}

	// 첫 4바이트에서 길이 추출 (Big Endian)
	let payload_len = u32::from_be_bytes(recv_buf[0..LENGTH_SIZE].try_into().unwrap()) as usize;

	if n >= LENGTH_SIZE + payload_len {
		// Nonce와 암호문 분리
		let nonce = box_::Nonce::from_slice(&recv_buf[LENGTH_SIZE..LENGTH_SIZE + NONCE_SIZE]).unwrap();
		let ciphertext = &recv_buf[LENGTH_SIZE + NONCE_SIZE..LENGTH_SIZE + payload_len];

		// 5. Authenticated Decryption 수행 (클라이언트 Public Key + 서버 Private Key 사용)
		match box_::open(ciphertext, &nonce, &client_pk, &server_sk) {
			Ok(decrypted) => {
				let msg = String::from_utf8_lossy(&decrypted);
				println!("[Thread-{}] 🔓 복호화된 메시지: {}", addr, msg);

				// 6. 서버에서 클라이언트로 암호화된 응답 전송
				let resp_msg = b"\xec\x84\x9c\xeb\xb2\x84\xec\x97\x90\xec\x84\x9c \xeb\xb3\xb4\xeb\x82\xb4\xeb\x8a\x94 \xec\x95\x94\xed\x98\xb8\xed\x99\x94\xeb\x90\x9c \xec\x9d\x91\xeb\x8b\xb5\xec\x9e\x85\xeb\x8b\x88\xeb\x8b\xa4! (\xec\x88\x98\xec\x8b\xa0 \xec\x99\x84\xeb\xa3\x8c, Rust Server)"; // 한글 UTF-8 수동 인코딩
				let resp_nonce = box_::gen_nonce();

				// 응답 암호화 (서버 Private Key + 클라이언트 Public Key)
				let resp_ciphertext = box_::seal(resp_msg, &resp_nonce, &client_pk, &server_sk);

				// 7. 응답 Payload 구성 및 전송 (하나의 버퍼로 병합)
				let resp_payload_len = (NONCE_SIZE + resp_ciphertext.len()) as u32;
				let mut send_buf = Vec::with_capacity(LENGTH_SIZE + resp_payload_len as usize);
				send_buf.extend_from_slice(&resp_payload_len.to_be_bytes());
				send_buf.extend_from_slice(resp_nonce.as_ref());
				send_buf.extend_from_slice(&resp_ciphertext);

				// 1번의 Write로 전송 처리
				if stream.write_all(&send_buf).is_ok() {
					println!("[Thread-{}] 🔒 서버 응답 전송 완료", addr);
				} else {
					println!("[Thread-{}] ❌ 서버 응답 전송 실패", addr);
				}
			}
			Err(_) => println!("[Thread-{}] ❌ 복호화 실패! (데이터가 위조되었거나 키가 일치하지 않음)", addr),
		}
	} else {
		println!("[Thread-{}] ⚠️ TCP 단편화로 인해 전체 데이터를 한 번에 수신하지 못했습니다.", addr);
	}

	println!("[Thread-{}] 클라이언트 연결 종료\n", addr);
}

fn main() {
	// libsodium 초기화 (필수)
	sodiumoxide::init().expect("libsodium 초기화 실패");

	// 모든 네트워크 인터페이스에서 포트 51822로 대기
	let listener = TcpListener::bind("0.0.0.0:51822").expect("서버 바인딩 실패");
	println!("🚀 Rust 서버가 포트 51822에서 대기 중입니다...");

	// 클라이언트 연결 대기 루프
	for stream in listener.incoming() {
		match stream {
			Ok(stream) => {
				// 스레드를 생성하여 클라이언트 처리를 비동기적으로 위임
				thread::spawn(move || {
						handle_client(stream);
						});
			}
			Err(e) => println!("❌ 클라이언트 Accept 실패: {}", e),
		}
	}
}
