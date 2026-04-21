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

type AuthClient struct {
	conn         net.Conn
	privKey      *[32]byte
	pubKey       *[32]byte
	serverPubKey *[32]byte
}

func NewAuthClient() *AuthClient {
	pub, priv, _ := box.GenerateKey(rand.Reader)
	return &AuthClient{
		privKey: priv,
		pubKey:  pub,
	}
}

func (c *AuthClient) Connect(addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil { return err }
	c.conn = conn

	// 1. 클라이언트 공개키 Base64 인코딩 후 전송
	clientPubKeyB64 := make([]byte, B64KeySize)
	base64.StdEncoding.Encode(clientPubKeyB64, c.pubKey[:])
	c.conn.Write(clientPubKeyB64)

	// 2. 서버 공개키 수신 (Base64) 및 디코딩
	serverPubKeyB64 := make([]byte, B64KeySize)
	_, err = io.ReadFull(c.conn, serverPubKeyB64)
	if err != nil { return err }

	c.serverPubKey = new([KeySize]byte)
	_, err = base64.StdEncoding.Decode(c.serverPubKey[:], serverPubKeyB64)
	return err
}

func (c *AuthClient) SendAndReceive(message string) {
	var nonce [NonceSize]byte
	io.ReadFull(rand.Reader, nonce[:])

	encrypted := box.Seal(nil, []byte(message), &nonce, c.serverPubKey, c.privKey)
	payloadLen := uint32(len(nonce) + len(encrypted))

	sendBuf := make([]byte, LengthSize+payloadLen)
	binary.BigEndian.PutUint32(sendBuf[:LengthSize], payloadLen)
	copy(sendBuf[LengthSize:LengthSize+NonceSize], nonce[:])
	copy(sendBuf[LengthSize+NonceSize:], encrypted)

	c.conn.Write(sendBuf)
	fmt.Println("🔒 암호화된 메시지 전송 성공 (Golang)!")

	recvBuf := make([]byte, BufferSize)
	n, _ := c.conn.Read(recvBuf)

	if n >= LengthSize+NonceSize+box.Overhead {
		respPayloadLen := binary.BigEndian.Uint32(recvBuf[:LengthSize])
		if n >= int(LengthSize+respPayloadLen) {
			var respNonce [NonceSize]byte
			copy(respNonce[:], recvBuf[LengthSize:LengthSize+NonceSize])
			respCiphertext := recvBuf[LengthSize+NonceSize : LengthSize+respPayloadLen]

			decrypted, ok := box.Open(nil, respCiphertext, &respNonce, c.serverPubKey, c.privKey)
			if ok {
				fmt.Printf("🔓 서버로부터의 응답: %s\n", string(decrypted))
			}
		}
	}
}

func (c *AuthClient) Close() {
	if c.conn != nil { c.conn.Close() }
}

func main() {
	ip := flag.String("i", "127.0.0.1", "Server IP")
	port := flag.String("p", "51822", "Server port")
	daemon := flag.Bool("d", false, "Run in daemon mode")
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

	client := NewAuthClient()
	defer client.Close()

	addr := *ip + ":" + *port
	if err := client.Connect(addr); err != nil {
		fmt.Println("❌ 연결 실패:", err)
		return
	}

	client.SendAndReceive("안녕하세요! Golang 구조체 클라이언트가 보낸 비밀 메시지입니다.")
}
