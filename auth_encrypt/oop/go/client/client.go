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

// 클라이언트 연결과 키 상태를 관리하는 구조체
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

	// 키 교환
	c.conn.Write(c.pubKey[:])
	
	c.serverPubKey = new([KeySize]byte)
	_, err = io.ReadFull(c.conn, c.serverPubKey[:])
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
	client := NewAuthClient()
	defer client.Close()

	if err := client.Connect("127.0.0.1:51822"); err != nil {
		fmt.Println("❌ 연결 실패:", err)
		return
	}

	client.SendAndReceive("안녕하세요! Golang 구조체 클라이언트가 보낸 비밀 메시지입니다.")
}
