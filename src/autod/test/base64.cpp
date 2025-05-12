#include <iostream>
#include <sodium.h>
#include <string>
#include <vector>

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

int main() {
	if (sodium_init() < 0) {
		std::cerr << "Failed to initialize libsodium" << std::endl;
		return 1;
	}

	std::string original_message = "Hello, libsodium!";
	std::cout << "Original: " << original_message << std::endl;
	std::vector<unsigned char> message_bytes(original_message.begin(), original_message.end());

	std::string encoded_message = base64_encode(message_bytes.data(), message_bytes.size());
	std::cout << "Encoded: " << encoded_message << std::endl;

	std::vector<unsigned char> decoded_message_bytes = base64_decode(encoded_message);
	std::string decoded_message(decoded_message_bytes.begin(), decoded_message_bytes.end());
	std::cout << "Decoded: " << decoded_message << std::endl;

	return 0;
}
