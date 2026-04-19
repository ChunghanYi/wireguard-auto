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

// 상수 정의
const (
	LengthSize = 4    // 데이터 길이를 나타내는 헤더의 크기 (4 bytes)
	NonceSize  = 24   // X25519 Nonce 크기 (24 bytes)
	KeySize    = 32   // X25519 공개키 크기 (32 bytes)
	BufferSize = 4096 // 수신 버퍼 크기
)

// 개별 클라이언트 연결을 처리하는 고루틴(스레드) 함수
func handleClient(conn net.Conn) {
	addr := conn.RemoteAddr().String()
	fmt.Printf("[Goroutine-%s] 새로운 클라이언트 연결 처리 시작\n", addr)

	// 함수가 종료될 때 반드시 커넥션을 닫도록 설정
	defer func() {
		conn.Close()
		fmt.Printf("[Goroutine-%s] 클라이언트 연결 종료\n\n", addr)
	}()

	// 1. 클라이언트의 X25519 공개키 수신
	clientPubKey := new([KeySize]byte)
	if _, err := io.ReadFull(conn, clientPubKey[:]); err != nil {
		fmt.Printf("[Goroutine-%s] ❌ 클라이언트 공개키 수신 실패: %v\n", addr, err)
		return
	}
	fmt.Printf("[Goroutine-%s] 클라이언트 공개키 수신 완료\n", addr)

	// 2. 서버의 X25519 키쌍 생성
	serverPubKey, serverPrivKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("[Goroutine-%s] ❌ 서버 키쌍 생성 실패: %v\n", addr, err)
		return
	}

	// 3. 서버의 공개키를 클라이언트에게 전송 (평문)
	if _, err := conn.Write(serverPubKey[:]); err != nil {
		fmt.Printf("[Goroutine-%s] ❌ 서버 공개키 전송 실패: %v\n", addr, err)
		return
	}
	fmt.Printf("[Goroutine-%s] 서버 공개키 전송 완료\n", addr)

	// 4. 데이터 수신 (1번의 Read 호출로 길이 + Nonce + 암호문을 한 번에 수신)
	recvBuf := make([]byte, BufferSize)
	n, err := conn.Read(recvBuf)
	if err != nil {
		fmt.Printf("[Goroutine-%s] ❌ 데이터 수신 실패: %v\n", addr, err)
		return
	}

	// 최소한의 페이로드 크기 검증 (Length + Nonce + MAC)
	if n < LengthSize+NonceSize+box.Overhead {
		fmt.Printf("[Goroutine-%s] ❌ 수신된 페이로드 크기가 너무 작습니다.\n", addr)
		return
	}

	// 첫 4바이트에서 길이 추출 (Big Endian)
	payloadLen := binary.BigEndian.Uint32(recvBuf[:LengthSize])

	if n >= int(LengthSize+payloadLen) {
		// Nonce와 암호문 분리
		var nonce [NonceSize]byte
		copy(nonce[:], recvBuf[LengthSize:LengthSize+NonceSize])
		ciphertext := recvBuf[LengthSize+NonceSize : LengthSize+payloadLen]

		// 5. Authenticated Decryption 수행 (클라이언트 Public Key + 서버 Private Key 사용)
		decrypted, ok := box.Open(nil, ciphertext, &nonce, clientPubKey, serverPrivKey)
		if !ok {
			fmt.Printf("[Goroutine-%s] ❌ 복호화 실패! (데이터가 위조되었거나 키가 일치하지 않음)\n", addr)
			return
		}

		fmt.Printf("[Goroutine-%s] 🔓 복호화된 메시지: %s\n", addr, string(decrypted))

		// 6. 서버에서 클라이언트로 암호화된 응답 전송
		respMsg := []byte("서버에서 보내는 암호화된 응답입니다! (수신 완료, Golang Server)")

		var respNonce [NonceSize]byte
		if _, err := io.ReadFull(rand.Reader, respNonce[:]); err != nil {
			fmt.Printf("[Goroutine-%s] ❌ 응답 Nonce 생성 실패: %v\n", addr, err)
			return
		}

		// 응답 암호화 (서버 Private Key + 클라이언트 Public Key)
		respEncrypted := box.Seal(nil, respMsg, &respNonce, clientPubKey, serverPrivKey)

		// 7. 응답 Payload 구성 및 전송 (Length + Nonce + Ciphertext를 하나의 버퍼로 병합)
		respPayloadLen := uint32(len(respNonce) + len(respEncrypted))

		sendBuf := make([]byte, LengthSize+respPayloadLen)
		binary.BigEndian.PutUint32(sendBuf[:LengthSize], respPayloadLen)
		copy(sendBuf[LengthSize:LengthSize+NonceSize], respNonce[:])
		copy(sendBuf[LengthSize+NonceSize:], respEncrypted)

		// 1번의 Write로 전송 처리
		if _, err := conn.Write(sendBuf); err != nil {
			fmt.Printf("[Goroutine-%s] ❌ 서버 응답 전송 실패: %v\n", addr, err)
		} else {
			fmt.Printf("[Goroutine-%s] 🔒 서버 응답 전송 완료\n", addr)
		}

	} else {
		fmt.Printf("[Goroutine-%s] ⚠️ TCP 단편화로 인해 전체 데이터를 한 번에 수신하지 못했습니다.\n", addr)
	}
}

func main() {
	port := "51822"

	// 모든 네트워크 인터페이스에서 포트 51822로 대기 (Listen)
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Printf("❌ 서버 바인딩 실패: %v\n", err)
		return
	}
	defer listener.Close()

	fmt.Printf("🚀 Golang 서버가 포트 %s에서 대기 중입니다...\n", port)

	for {
		// 클라이언트 연결 대기
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("❌ 클라이언트 Accept 실패: %v\n", err)
			continue
		}

		// 고루틴을 생성하여 클라이언트 처리를 비동기적으로 위임
		// C++의 std::thread 나 Python의 threading.Thread 와 동일한 역할을 하지만 훨씬 가볍습니다.
		go handleClient(conn)
	}
}
