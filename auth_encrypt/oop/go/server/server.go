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
	LengthSize = 4
	NonceSize  = 24
	KeySize    = 32
	BufferSize = 4096
)

// 서버의 상태를 캡슐화한 구조체
type AuthServer struct {
	port string
}

func NewAuthServer(port string) *AuthServer {
	return &AuthServer{port: port}
}

func (s *AuthServer) handleClient(conn net.Conn) {
	defer conn.Close()

	clientPubKey := new([KeySize]byte)
	if _, err := io.ReadFull(conn, clientPubKey[:]); err != nil { return }

	serverPubKey, serverPrivKey, _ := box.GenerateKey(rand.Reader)
	conn.Write(serverPubKey[:])

	recvBuf := make([]byte, BufferSize)
	n, err := conn.Read(recvBuf)
	if err != nil || n < LengthSize+NonceSize+box.Overhead { return }

	payloadLen := binary.BigEndian.Uint32(recvBuf[:LengthSize])
	if n >= int(LengthSize+payloadLen) {
		var nonce [NonceSize]byte
		copy(nonce[:], recvBuf[LengthSize:LengthSize+NonceSize])
		ciphertext := recvBuf[LengthSize+NonceSize : LengthSize+payloadLen]

		decrypted, ok := box.Open(nil, ciphertext, &nonce, clientPubKey, serverPrivKey)
		if ok {
			fmt.Printf("🔓 복호화된 메시지: %s\n", string(decrypted))

			respMsg := []byte("서버에서 보내는 암호화된 응답입니다! (Golang Server)")
			var respNonce [NonceSize]byte
			io.ReadFull(rand.Reader, respNonce[:])

			respEncrypted := box.Seal(nil, respMsg, &respNonce, clientPubKey, serverPrivKey)
			respPayloadLen := uint32(len(respNonce) + len(respEncrypted))

			sendBuf := make([]byte, LengthSize+respPayloadLen)
			binary.BigEndian.PutUint32(sendBuf[:LengthSize], respPayloadLen)
			copy(sendBuf[LengthSize:LengthSize+NonceSize], respNonce[:])
			copy(sendBuf[LengthSize+NonceSize:], respEncrypted)

			conn.Write(sendBuf)
		}
	}
}

func (s *AuthServer) Start() {
	listener, err := net.Listen("tcp", ":"+s.port)
	if err != nil { panic(err) }
	defer listener.Close()

	fmt.Printf("🚀 Golang 서버가 포트 %s에서 대기 중입니다...\n", s.port)

	for {
		conn, err := listener.Accept()
		if err != nil { continue }
		go s.handleClient(conn)
	}
}

func main() {
	server := NewAuthServer("51822")
	server.Start()
}
