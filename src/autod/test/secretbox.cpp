#include <sodium.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

// Initialize libsodium
void initialize_sodium() {
	if (sodium_init() == -1) {
		throw std::runtime_error("Failed to initialize libsodium");
	}
}

std::string base64_encode(const unsigned char* input, size_t length) {
	size_t encoded_length = sodium_base64_encoded_len(length, sodium_base64_VARIANT_ORIGINAL);
	std::vector<char> encoded(encoded_length);
	sodium_bin2base64(encoded.data(), encoded_length, input, length, sodium_base64_VARIANT_ORIGINAL);
	return std::string(encoded.data());
}

std::vector<unsigned char> base64_decode(const std::string& input) {
	size_t decoded_length = input.length(); // Maximum possible decoded length
	std::vector<unsigned char> decoded(decoded_length);

	if (sodium_base642bin(decoded.data(), decoded_length, input.c_str(), input.length(), nullptr, &decoded_length, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0) {
		throw std::runtime_error("Base64 decoding failed");
	}
	decoded.resize(decoded_length); // Adjust the size to the actual decoded length
	return decoded;
}

// Generate a key pair
std::pair<std::vector<unsigned char>, std::vector<unsigned char>> generate_keypair() {
	std::vector<unsigned char> public_key(crypto_box_PUBLICKEYBYTES);
	std::vector<unsigned char> secret_key(crypto_box_SECRETKEYBYTES);
	crypto_box_keypair(public_key.data(), secret_key.data());
	return {public_key, secret_key};
}

// Encrypt a message
std::vector<unsigned char> encrypt_message(const std::vector<unsigned char>& message,
                                            const std::vector<unsigned char>& receiver_public_key,
                                            const std::vector<unsigned char>& sender_secret_key) {
	std::vector<unsigned char> nonce(crypto_box_NONCEBYTES);
	randombytes_buf(nonce.data(), nonce.size());

	std::vector<unsigned char> ciphertext(message.size() + crypto_box_MACBYTES);
	int ret = crypto_box_easy(ciphertext.data(), message.data(), message.size(), nonce.data(),
			receiver_public_key.data(), sender_secret_key.data());

	std::vector<unsigned char> result;
	result.insert(result.end(), nonce.begin(), nonce.end());
	result.insert(result.end(), ciphertext.begin(), ciphertext.end());
	return result;
}

// Decrypt a message
std::vector<unsigned char> decrypt_message(const std::vector<unsigned char>& encrypted_message,
                                            const std::vector<unsigned char>& sender_public_key,
                                            const std::vector<unsigned char>& receiver_secret_key) {
	if (encrypted_message.size() < crypto_box_NONCEBYTES + crypto_box_MACBYTES) {
		throw std::runtime_error("Invalid ciphertext size");
	}

	std::vector<unsigned char> nonce(encrypted_message.begin(), encrypted_message.begin() + crypto_box_NONCEBYTES);
	std::vector<unsigned char> ciphertext(encrypted_message.begin() + crypto_box_NONCEBYTES, encrypted_message.end());

	std::vector<unsigned char> decrypted_message(ciphertext.size() - crypto_box_MACBYTES);
	if (crypto_box_open_easy(decrypted_message.data(), ciphertext.data(), ciphertext.size(), nonce.data(),
				sender_public_key.data(), receiver_secret_key.data()) != 0) {
		throw std::runtime_error("Message decryption failed");
	}
	return decrypted_message;
}

int main() {
	initialize_sodium();

	// Generate key pairs for sender and receiver
	auto [sender_public_key, sender_secret_key] = generate_keypair();
	auto [receiver_public_key, receiver_secret_key] = generate_keypair();
	
#if 0
	std::cout << "sender_public_key" << sender_public_key.data() << std::endl;
	std::cout << "sender_secret_key" << sender_secret_key.data() << std::endl;
	std::cout << "receiver_public_key" << receiver_public_key.data() << std::endl;
	std::cout << "receiver_secret_key" << receiver_secret_key.data() << std::endl;
#endif

#if 0
	std::printf("#1> sender_public_key(%ld): ", sender_public_key.size());
	for (int i=0; i<sender_public_key.size(); i++) {
		std::printf("[0x%x]", sender_public_key.data()[i]);
	}
	std::printf("\n");
	std::string encoded_message = base64_encode(sender_public_key.data(), sender_public_key.size());
	std::cout << "base64_encode(sender_public_key): " << encoded_message << std::endl;
	std::vector<unsigned char> decoded_message_bytes = base64_decode(encoded_message);
	std::string decoded_message(decoded_message_bytes.begin(), decoded_message_bytes.end());
	std::cout << "base64_decode(sender_public_key): " << decoded_message << std::endl;
	std::printf("#2> sender_public_key: ");
	for (const auto& element : decoded_message_bytes) {
		std::printf("[0x%x]", element);
	}
	std::printf("\n");
#endif

	std::printf("sender_public_key(%ld): {", sender_public_key.size());
	for (int i=0; i<sender_public_key.size(); i++) {
		std::printf("0x%02x, ", sender_public_key.data()[i]);
	}
	std::printf("}\n");

	std::printf("sender_secret_key(%ld): {", sender_secret_key.size());
	for (int i=0; i<sender_secret_key.size(); i++) {
		std::printf("0x%02x, ", sender_secret_key.data()[i]);
	}
	std::printf("}\n");

	std::printf("receiver_public_key(%ld): {", receiver_public_key.size());
	for (int i=0; i<receiver_public_key.size(); i++) {
		std::printf("0x%02x, ", receiver_public_key.data()[i]);
	}
	std::printf("}\n");

	std::printf("receiver_secret_key(%ld): {", receiver_secret_key.size());
	for (int i=0; i<receiver_secret_key.size(); i++) {
		std::printf("0x%02x, ", receiver_secret_key.data()[i]);
	}
	std::printf("}\n");

	// Message to be encrypted
	std::string original_message_str = "Hello, this is a secret message!";
	std::vector<unsigned char> original_message(original_message_str.begin(), original_message_str.end());

	// Encrypt the message
	std::vector<unsigned char> encrypted_message = encrypt_message(original_message, receiver_public_key, sender_secret_key);

	// Decrypt the message
	std::vector<unsigned char> decrypted_message = decrypt_message(encrypted_message, sender_public_key, receiver_secret_key);

	// Output the results
	std::cout << "Original message: " << original_message_str << std::endl;
	std::cout << "Decrypted message: " << std::string(decrypted_message.begin(), decrypted_message.end()) << std::endl;

	return 0;
}
