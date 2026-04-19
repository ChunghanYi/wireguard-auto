/* SPDX-License-Identifier: MIT
 *
 * Authenticated Encryption/Decryption examples using libsodium library
 * Key exchange: X25519, Encryption: XSalsa20, Authentication: Poly1305
 */

package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/nacl/box"
)

const (
	LengthSize = 4    // 데이터 길이를 나타내는 헤더의 크기 (4 bytes)
	NonceSize  = 24   // X25519 Nonce 크기 (24 bytes)
	KeySize    = 32   // X25519 공개키 크기 (32 bytes)
	BufferSize = 4096 // 수신 버퍼 크기
)

func main() {
	// TCP로 C++ 서버에 연결
	conn, err := net.Dial("tcp", "127.0.0.1:51822")
	if err != nil {
		fmt.Println("서버 연결 실패. 서버가 실행 중인지 확인하세요.")
		panic(err)
	}
	defer conn.Close()

	// 1. 클라이언트용 X25519 키쌍 생성
	pubKey, privKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// 2. 클라이언트 공개키 서버로 전송 (32 bytes)
	_, err = conn.Write(pubKey[:])
	if err != nil {
		panic("공개키 전송 실패")
	}

	// 3. 서버의 공개키 수신 (32 bytes)
	serverPubKey := new([KeySize]byte)
	_, err = io.ReadFull(conn, serverPubKey[:])
	if err != nil {
		panic("서버 공개키 수신 실패")
	}

	// 4. 암호화할 메시지와 Nonce 준비
	msg := []byte("안녕하세요! Golang 클라이언트가 보낸 비밀 메시지입니다.")
	
	var nonce [NonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic("Nonce 생성 실패")
	}

	// 5. Authenticated Encryption 수행 (MAC 16 Bytes 포함되어 결과가 나옴)
	// libsodium의 crypto_box_easy 와 완벽하게 호환됩니다.
	encrypted := box.Seal(nil, msg, &nonce, serverPubKey, privKey)

	// 6. 데이터 전송 포맷 맞추기: Length(4 bytes, Big Endian) + Nonce + 암호문
	payloadLen := uint32(len(nonce) + len(encrypted))
	
	// 하나의 버퍼로 병합하여 1번의 Write(send)로 전송
	sendBuf := make([]byte, LengthSize+payloadLen)
	binary.BigEndian.PutUint32(sendBuf[:LengthSize], payloadLen)
	copy(sendBuf[LengthSize : LengthSize+NonceSize], nonce[:])
	copy(sendBuf[LengthSize+NonceSize:], encrypted)

	conn.Write(sendBuf)

	fmt.Println("🔒 암호화된 메시지 전송 성공 (Golang)!")

	// 7. 서버로부터의 응답 수신 (1번의 Read로 처리)
	recvBuf := make([]byte, BufferSize)
	n, err := conn.Read(recvBuf)
	if err != nil {
		fmt.Println("서버 응답 수신 실패")
		return
	}

	if n >= LengthSize+NonceSize+box.Overhead {
		respPayloadLen := binary.BigEndian.Uint32(recvBuf[:LengthSize])

		if n >= int(LengthSize+respPayloadLen) {
			var respNonce [NonceSize]byte
			copy(respNonce[:], recvBuf[LengthSize : LengthSize+NonceSize])
			respCiphertext := recvBuf[LengthSize+NonceSize : LengthSize+respPayloadLen]

			// 7.4. 복호화 수행 (서버 Public Key + 클라이언트 Private Key 사용)
			decrypted, ok := box.Open(nil, respCiphertext, &respNonce, serverPubKey, privKey)
			if !ok {
				fmt.Println("❌ 서버 응답 복호화 실패! (데이터가 위조되었거나 키가 일치하지 않음)")
				return
			}

			fmt.Printf("🔓 서버로부터의 응답: %s\n", string(decrypted))
		} else {
			fmt.Println("TCP 단편화로 인해 응답을 한 번에 수신하지 못했습니다.")
		}
	} else {
		fmt.Println("수신된 페이로드 크기가 너무 작습니다.")
	}
}
