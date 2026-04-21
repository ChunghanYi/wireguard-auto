/* SPDX-License-Identifier: MIT
 *
 * Authenticated Encryption/Decryption examples using libsodium library
 * Key exchange: X25519, Encryption: XSalsa20, Authentication: Poly1305
 */

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"

	"golang.org/x/crypto/nacl/box"
)

const (
	LengthSize = 4
	NonceSize  = 24
	KeySize    = 32
	B64KeySize = 44
	BufferSize = 4096
)

type AuthServer struct {
	port       string
	maxClients int
	sem        chan struct{}
}

func NewAuthServer(port string, max int) *AuthServer {
	return &AuthServer{
		port:       port,
		maxClients: max,
		sem:        make(chan struct{}, max),
	}
}

func (s *AuthServer) handleClient(conn net.Conn) {
	defer conn.Close()

	// 1. 클라이언트 공개키 수신 (Base64)
	clientPubKeyB64 := make([]byte, B64KeySize)
	if _, err := io.ReadFull(conn, clientPubKeyB64); err != nil { return }

	clientPubKey := new([KeySize]byte)
	if _, err := base64.StdEncoding.Decode(clientPubKey[:], clientPubKeyB64); err != nil { return }

	// 2. 서버 키쌍 생성 및 공개키 전송 (Base64)
	serverPubKey, serverPrivKey, _ := box.GenerateKey(rand.Reader)

	serverPubKeyB64 := make([]byte, B64KeySize)
	base64.StdEncoding.Encode(serverPubKeyB64, serverPubKey[:])
	conn.Write(serverPubKeyB64)

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

	fmt.Printf("🚀 Golang 서버가 포트 %s에서 대기 중입니다... (Max: %d)\n", s.port, s.maxClients)

	for {
		conn, err := listener.Accept()
		if err != nil { continue }

		s.sem <- struct{}{} // 동시 접속 제한
		go func() {
			defer func() { <-s.sem }()
			s.handleClient(conn)
		}()
	}
}

func main() {
	port := flag.String("p", "51822", "Server port")
	daemon := flag.Bool("d", false, "Run in daemon mode")
	maxClients := flag.Int("m", 10, "Max concurrent client connections")
	flag.Parse()

	if *daemon {
		args := make([]string, 0)
		for _, arg := range os.Args[1:] {
			if arg != "-d" && arg != "--d" {
				args = append(args, arg)
			}
		}
		cmd := exec.Command(os.Args[0], args...)
		cmd.Start()
		os.Exit(0)
	}

	server := NewAuthServer(*port, *maxClients)
	server.Start()
}
