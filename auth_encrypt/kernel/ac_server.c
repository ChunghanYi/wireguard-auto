/* SPDX-License-Identifier: MIT
 *
 * Authenticated Encryption/Decryption kernel module 
 * Algorithms: Curve25519, ChaCha20-Poly1305
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/in.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/delay.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include <linux/slab.h> 
#include <linux/fs.h>      // 파일 I/O를 위한 헤더 추가 (filp_open, kernel_write)
#include <crypto/kpp.h>
#include <crypto/aead.h>
#include <crypto/hash.h>

#define PORT 51822
#define B64_KEY_SIZE 44
#define KEY_SIZE 32
#define NONCE_SIZE 12
#define MAC_SIZE 16
#define MAX_BUF_SIZE 1024

static struct task_struct *accept_thread;
static struct socket *listen_sock;

/* --- Base64 헬퍼 함수 (Stack 메모리 최적화) --- */
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64_encode(const u8 *in, int in_len, char *out) {
	int i, j; u32 val;
	for (i = 0, j = 0; i < in_len; i += 3, j += 4) {
		val = (in[i] << 16) | (i+1 < in_len ? in[i+1] << 8 : 0) | (i+2 < in_len ? in[i+2] : 0);
		out[j]   = b64_table[(val >> 18) & 0x3F];
		out[j+1] = b64_table[(val >> 12) & 0x3F];
		out[j+2] = (i+1 < in_len) ? b64_table[(val >> 6) & 0x3F] : '=';
		out[j+3] = (i+2 < in_len) ? b64_table[val & 0x3F] : '=';
	}
}

static inline int b64_char_to_val(char c) {
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return 0;
}

static int b64_decode(const char *in, int in_len, u8 *out) {
	int i, j, v;
	int val[4];
	for (i = 0, j = 0; i < in_len; i += 4, j += 3) {
		val[0] = b64_char_to_val(in[i]);
		val[1] = b64_char_to_val(in[i+1]);
		val[2] = (in[i+2] == '=') ? 0 : b64_char_to_val(in[i+2]);
		val[3] = (in[i+3] == '=') ? 0 : b64_char_to_val(in[i+3]);

		v = (val[0] << 18) | (val[1] << 12) | (val[2] << 6) | val[3];

		out[j] = (v >> 16) & 0xFF;
		if (in[i+2] != '=') out[j+1] = (v >> 8) & 0xFF;
		if (in[i+3] != '=') out[j+2] = v & 0xFF;
	}
	return j;
}

/* --- 커널 소켓 헬퍼 함수 --- */
static int kernel_recv_all(struct socket *sock, u8 *buf, size_t size) {
	struct kvec iov = { .iov_base = buf, .iov_len = size };
	struct msghdr msg = { .msg_flags = MSG_WAITALL };
	int ret, done = 0;
	while (done < size) {
		iov.iov_base = buf + done; iov.iov_len = size - done;
		ret = kernel_recvmsg(sock, &msg, &iov, 1, size - done, msg.msg_flags);
		if (ret <= 0) {
			return ret;
		}
		done += ret;
	}
	return done;
}

static int kernel_send_all(struct socket *sock, const u8 *buf, size_t size) {
	struct kvec iov = { .iov_base = (void *)buf, .iov_len = size };
	struct msghdr msg = { .msg_flags = MSG_NOSIGNAL };
	int ret, done = 0;
	while (done < size) {
		iov.iov_base = (void *)(buf + done); iov.iov_len = size - done;
		ret = kernel_sendmsg(sock, &msg, &iov, 1, size - done);
		if (ret <= 0) {
			return ret;
		}
		done += ret;
	}
	return done;
}

/* --- 비동기 Crypto API 대기 헬퍼 --- */
struct tcrypt_result {
	struct completion completion;
	int err;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static void tcrypt_complete(void *data, int err) {
	struct tcrypt_result *res = data;
#else
static void tcrypt_complete(struct crypto_async_request *req, int err) {
	struct tcrypt_result *res = req->data;
#endif
	if (err == -EINPROGRESS) {
		return;
	}
	res->err = err;
	complete(&res->completion);
}

static int wait_async_op(struct tcrypt_result *tr, int ret) {
	if (ret == -EINPROGRESS || ret == -EBUSY) {
		wait_for_completion(&tr->completion);
		reinit_completion(&tr->completion);
		ret = tr->err;
	}
	return ret;
}

/* --- 클라이언트 처리 스레드 --- */
static int client_handler_thread(void *arg) {
	struct socket *client_sock = (struct socket *)arg;
	char client_pk_b64[B64_KEY_SIZE + 1];
	char server_pk_b64[B64_KEY_SIZE + 1];
	u8 client_pk[KEY_SIZE], server_sk[KEY_SIZE], server_pk[KEY_SIZE];
	u8 shared_secret[KEY_SIZE], aead_key[KEY_SIZE];

	struct crypto_kpp *kpp = NULL;
	struct kpp_request *kpp_req = NULL;
	struct crypto_shash *hash = NULL;
	struct shash_desc *desc = NULL;
	struct crypto_aead *aead = NULL;
	struct aead_request *aead_req = NULL;
	struct tcrypt_result result;
	struct scatterlist sg_in, sg_out;
	struct file *f = NULL; // 파일 저장을 위한 포인터

	u8 *recv_buf = NULL;
	u8 *send_buf = NULL;
	u32 payload_len_be, payload_len;
	int ret;

	printk(KERN_INFO "[ACServer] 새로운 WG Client 연결 (PID: %d)\n", current->pid);

	recv_buf = kmalloc(MAX_BUF_SIZE, GFP_KERNEL);
	send_buf = kmalloc(MAX_BUF_SIZE, GFP_KERNEL);
	if (!recv_buf || !send_buf) {
		goto cleanup;
	}

	init_completion(&result.completion);

	// 1. 클라이언트 공개키 수신 및 디코딩
	memset(client_pk_b64, 0, sizeof(client_pk_b64));
	if (kernel_recv_all(client_sock, client_pk_b64, B64_KEY_SIZE) <= 0) {
		goto cleanup;
	}
	b64_decode(client_pk_b64, B64_KEY_SIZE, client_pk);

	// 2. 서버 Secret Key 생성
	get_random_bytes(server_sk, KEY_SIZE);
	server_sk[0] &= 248; server_sk[31] &= 127; server_sk[31] |= 64;

	kpp = crypto_alloc_kpp("curve25519", 0, 0);
	if (IS_ERR(kpp)) {
		goto cleanup;
	}
	crypto_kpp_set_secret(kpp, server_sk, KEY_SIZE);
	kpp_req = kpp_request_alloc(kpp, GFP_KERNEL);
	kpp_request_set_callback(kpp_req, CRYPTO_TFM_REQ_MAY_SLEEP, tcrypt_complete, &result);

	// 3. 서버 공개키 생성 및 전송
	sg_init_one(&sg_out, server_pk, KEY_SIZE);
	kpp_request_set_input(kpp_req, NULL, 0);
	kpp_request_set_output(kpp_req, &sg_out, KEY_SIZE);
	wait_async_op(&result, crypto_kpp_generate_public_key(kpp_req));

	memset(server_pk_b64, 0, sizeof(server_pk_b64));
	b64_encode(server_pk, KEY_SIZE, server_pk_b64);
	if (kernel_send_all(client_sock, server_pk_b64, B64_KEY_SIZE) <= 0) {
		goto cleanup;
	}

	// 4. Shared Secret -> AEAD Key 파생
	sg_init_one(&sg_in, client_pk, KEY_SIZE);
	sg_init_one(&sg_out, shared_secret, KEY_SIZE);
	kpp_request_set_input(kpp_req, &sg_in, KEY_SIZE);
	kpp_request_set_output(kpp_req, &sg_out, KEY_SIZE);
	wait_async_op(&result, crypto_kpp_compute_shared_secret(kpp_req));

	hash = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(hash)) {
		goto cleanup;
	}
	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(hash), GFP_KERNEL);
	if (!desc) {
		goto cleanup;
	}
	desc->tfm = hash;
	crypto_shash_digest(desc, shared_secret, KEY_SIZE, aead_key);

	// 5. ChaCha20-Poly1305 초기화
	aead = crypto_alloc_aead("rfc7539(chacha20,poly1305)", 0, 0);
	if (IS_ERR(aead)) {
		goto cleanup;
	}
	crypto_aead_setkey(aead, aead_key, KEY_SIZE);
	crypto_aead_setauthsize(aead, MAC_SIZE);
	aead_req = aead_request_alloc(aead, GFP_KERNEL);
	aead_request_set_callback(aead_req, CRYPTO_TFM_REQ_MAY_SLEEP, tcrypt_complete, &result);

	// 6. 데이터 수신 (WG 설정 정보)
	if (kernel_recv_all(client_sock, (u8 *)&payload_len_be, 4) <= 0) {
		goto cleanup;
	}
	payload_len = be32_to_cpu(payload_len_be);
	if (payload_len > MAX_BUF_SIZE || payload_len < NONCE_SIZE + MAC_SIZE) {
		goto cleanup;
	}

	if (kernel_recv_all(client_sock, recv_buf, payload_len) <= 0) {
		goto cleanup;
	}

	// 7. AEAD 복호화 수행
	u8 *nonce = recv_buf;
	u8 *ciphertext = recv_buf + NONCE_SIZE;
	u32 ciphertext_len = payload_len - NONCE_SIZE;

	sg_init_one(&sg_in, ciphertext, ciphertext_len);
	aead_request_set_crypt(aead_req, &sg_in, &sg_in, ciphertext_len, nonce);
	aead_request_set_ad(aead_req, 0);

	ret = wait_async_op(&result, crypto_aead_decrypt(aead_req));
	if (ret == 0) {
		// 복호화 완료: 널 종단 문자 삽입
		ciphertext[ciphertext_len - MAC_SIZE] = '\0';
		printk(KERN_INFO "[ACServer] 🔓 수신된 클라이언트 WG 설정: %s\n", ciphertext);

		// --- [핵심 기능] 수신된 WG 설정을 파일로 기록 ---
		f = filp_open("/tmp/wg_client.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (IS_ERR(f)) {
			printk(KERN_ERR "[ACServer] ❌ /tmp/wg_client.txt 파일 열기 실패\n");
		} else {
			loff_t pos = 0;
			// 최신 커널에서는 set_fs(KERNEL_DS) 없이도 커널 힙 버퍼(ciphertext)를 직접 기록 가능합니다.
			kernel_write(f, ciphertext, strlen(ciphertext), &pos);
			filp_close(f, NULL);
			printk(KERN_INFO "[ACServer] 📝 WG 설정 파일 저장 완료 (/tmp/wg_client.txt)\n");
		}

		// 8. 서버의 WireGuard 설정 응답 생성
		// 예시 응답: PUBKEY=...;ALLOWED_IPS=...;ENDPOINT=...
		char *resp_msg = "PUBKEY=ServerWgPubKeyFake123=;ALLOWED_IPS=10.0.0.1/32;ENDPOINT=192.168.1.10:51820";
		u32 msg_len = strlen(resp_msg);
		u8 resp_nonce[NONCE_SIZE];
		get_random_bytes(resp_nonce, NONCE_SIZE);

		u8 *resp_ciphertext = send_buf + 4 + NONCE_SIZE;
		memcpy(resp_ciphertext, resp_msg, msg_len);

		sg_init_one(&sg_out, resp_ciphertext, msg_len + MAC_SIZE);
		aead_request_set_crypt(aead_req, &sg_out, &sg_out, msg_len, resp_nonce);
		ret = wait_async_op(&result, crypto_aead_encrypt(aead_req));

		if (ret == 0) {
			u32 resp_payload_len = NONCE_SIZE + msg_len + MAC_SIZE;
			u32 net_len = cpu_to_be32(resp_payload_len);
			memcpy(send_buf, &net_len, 4);
			memcpy(send_buf + 4, resp_nonce, NONCE_SIZE);

			kernel_send_all(client_sock, send_buf, 4 + resp_payload_len);
			printk(KERN_INFO "[ACServer] 🔒 서버 WG 설정 응답 전송 완료\n");
		}
	} else {
		printk(KERN_ERR "[ACServer] ❌ 복호화 실패\n");
	}

cleanup:
	if (recv_buf) kfree(recv_buf);
	if (send_buf) kfree(send_buf);
	if (desc) kfree(desc);
	if (hash && !IS_ERR(hash)) crypto_free_shash(hash);
	if (kpp_req) kpp_request_free(kpp_req);
	if (kpp && !IS_ERR(kpp)) crypto_free_kpp(kpp);
	if (aead_req) aead_request_free(aead_req);
	if (aead && !IS_ERR(aead)) crypto_free_aead(aead);

	kernel_sock_shutdown(client_sock, SHUT_RDWR);
	sock_release(client_sock);
	return 0;
}

/* --- 메인 Listen 스레드 --- */
static int server_accept_loop(void *arg) {
	struct sockaddr_in addr;
	int ret;

	ret = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP, &listen_sock);
	if (ret < 0) {
		return ret;
	}

	sock_set_reuseaddr(listen_sock->sk);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(PORT);

	if (kernel_bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		sock_release(listen_sock); return -1;
	}

	if (kernel_listen(listen_sock, 10) < 0) {
		sock_release(listen_sock); return -1;
	}

	printk(KERN_INFO "🚀 [ACServer] 커널 서버 대기 중 (WG 설정 수신기)\n");

	while (!kthread_should_stop()) {
		struct socket *client_sock;
		ret = kernel_accept(listen_sock, &client_sock, O_NONBLOCK);
		if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
			msleep(10);
			continue;
		} else if (ret < 0) {
			break;
		}

		kthread_run(client_handler_thread, client_sock, "auth_client_kthread");
	}
	return 0;
}

static int __init auth_server_init(void) {
	accept_thread = kthread_run(server_accept_loop, NULL, "auth_server_kthread");
	return IS_ERR(accept_thread) ? PTR_ERR(accept_thread) : 0;
}

static void __exit auth_server_exit(void) {
	if (accept_thread) {
		kthread_stop(accept_thread);
	}
	if (listen_sock) {
		kernel_sock_shutdown(listen_sock, SHUT_RDWR);
		sock_release(listen_sock);
	}
	printk(KERN_INFO "[ACServer] 모듈 제거 완료\n");
}

module_init(auth_server_init);
module_exit(auth_server_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Slowboot<chunghan.yi@gmail.com>");
MODULE_DESCRIPTION("WireGuard Auto Connector");
