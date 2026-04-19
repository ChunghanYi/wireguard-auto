/* SPDX-License-Identifier: MIT
 *
 * Authenticated Encryption/Decryption examples using libsodium library
 * Key exchange: X25519, Encryption: XSalsa20, Authentication: Poly1305
 */

use sodiumoxide::crypto::box_;
use std::io::{Read, Write};
use std::net::TcpStream;

// 상수 정의
const LENGTH_SIZE: usize = 4;
const NONCE_SIZE: usize = 24;
const KEY_SIZE: usize = 32;
const BUFFER_SIZE: usize = 4096;

fn main() {
	// libsodium 초기화 (필수)
	sodiumoxide::init().expect("libsodium 초기화 실패");

	// TCP로 서버에 연결
	let mut stream = TcpStream::connect("127.0.0.1:51822").expect("❌ 서버 연결 실패. 서버가 실행 중인지 확인하세요.");

	// 1. 클라이언트의 X25519 키쌍 생성
	let (client_pk, client_sk) = box_::gen_keypair();

	// 2. 클라이언트 공개키 서버로 전송 (32 bytes)
	stream.write_all(client_pk.as_ref()).expect("공개키 전송 실패");

	// 3. 서버의 공개키 수신 (32 bytes)
	let mut server_pk_bytes = [0u8; KEY_SIZE];
	stream.read_exact(&mut server_pk_bytes).expect("서버 공개키 수신 실패");

	let server_pk = box_::PublicKey::from_slice(&server_pk_bytes).expect("잘못된 서버 공개키 포맷");

	// 4. 암호화할 메시지와 Nonce 준비
	let msg = "안녕하세요! Rust 클라이언트가 보낸 비밀 메시지입니다.".as_bytes();
	let nonce = box_::gen_nonce();

	// 5. Authenticated Encryption 수행 (MAC 16 Bytes 포함되어 결과가 나옴)
	let ciphertext = box_::seal(msg, &nonce, &server_pk, &client_sk);

	// 6. 데이터 전송 포맷 맞추기: Length(4 bytes, Big Endian) + Nonce + 암호문
	let payload_len = (NONCE_SIZE + ciphertext.len()) as u32;

	// 하나의 버퍼로 병합하여 1번의 Write(send)로 전송
	let mut send_buf = Vec::with_capacity(LENGTH_SIZE + payload_len as usize);
	send_buf.extend_from_slice(&payload_len.to_be_bytes());
	send_buf.extend_from_slice(nonce.as_ref());
	send_buf.extend_from_slice(&ciphertext);

	stream.write_all(&send_buf).expect("암호화된 메시지 전송 실패");
	println!("🔒 암호화된 메시지 전송 성공 (Rust)!");

	// 7. 서버로부터의 응답 수신 (1번의 Read로 처리)
	let mut recv_buf = [0u8; BUFFER_SIZE];
	let n = stream.read(&mut recv_buf).expect("서버 응답 수신 실패");

	if n >= LENGTH_SIZE + NONCE_SIZE + box_::MACBYTES {
		let resp_payload_len = u32::from_be_bytes(recv_buf[0..LENGTH_SIZE].try_into().unwrap()) as usize;

		if n >= LENGTH_SIZE + resp_payload_len {
			let resp_nonce = box_::Nonce::from_slice(&recv_buf[LENGTH_SIZE..LENGTH_SIZE + NONCE_SIZE]).unwrap();
			let resp_ciphertext = &recv_buf[LENGTH_SIZE + NONCE_SIZE..LENGTH_SIZE + resp_payload_len];

			// 7.4. 복호화 수행 (서버 Public Key + 클라이언트 Private Key 사용)
			match box_::open(resp_ciphertext, &resp_nonce, &server_pk, &client_sk) {
				Ok(decrypted) => {
					let resp_msg = String::from_utf8_lossy(&decrypted);
					println!("🔓 서버로부터의 응답: {}", resp_msg);
				}
				Err(_) => println!("❌ 서버 응답 복호화 실패! (데이터가 위조되었거나 키가 일치하지 않음)"),
			}
		} else {
			println!("⚠️ TCP 단편화로 인해 응답을 한 번에 수신하지 못했습니다.");
		}
	} else {
		println!("❌ 수신된 페이로드 크기가 너무 작습니다.");
	}
}
