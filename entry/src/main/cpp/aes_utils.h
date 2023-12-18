#pragma once

#include <iostream>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <vector>
#include <sstream>

namespace aes_utils {
    static constexpr int AES_KEY_SIZE_128 = 128;

    std::string generateAESKey(int keySize) {
        std::vector<uint8_t> key;
        key.resize(keySize / 8); // AES key sizes are in bits, so divide by 8 to get bytes

        if (RAND_bytes(key.data(), keySize / 8) != 1) {
            std::cerr << "Error generating random bytes." << std::endl;
            return {};
        }


        return {key.begin(), key.end()};
    }

    std::string applyPkcs5Padding(const std::string &input, int blockSize) {
        int padding_length = blockSize - (input.size() % blockSize);
        char padding_value = static_cast<char>(padding_length);

        std::string output = input + std::string(padding_length, padding_value);

        return output;
    }

    std::string removePkcs5Padding(const std::string &input) {
        char paddingValue = input.back();
        int paddingLength = static_cast<int>(paddingValue);

        if (paddingLength > input.size() || paddingLength == 0) {
            // Invalid padding
            return "";
        }

        for (size_t i = input.size() - paddingLength; i < input.size(); ++i) {
            if (input[i] != paddingValue) {
                // Invalid padding
                return "";
            }
        }

        return input.substr(0, input.size() - paddingLength);
    }

    std::string aesEncrypt(const std::string &plaintext, const std::string &key) {
        if (key.size() != 16) {
            std::cerr << "Key size must be 16 bytes (128 bits)" << std::endl;
            return "";
        }

        AES_KEY aesKey;
        if (AES_set_encrypt_key(reinterpret_cast<const unsigned char *>(key.c_str()), 128, &aesKey) != 0) {
            std::cerr << "AES_set_encrypt_key failed" << std::endl;
            return "";
        }

        std::string padded_plaintext = applyPkcs5Padding(plaintext, AES_BLOCK_SIZE);

        std::string ciphertext(padded_plaintext.size(), 0);

        for (size_t i = 0; i < padded_plaintext.size(); i += AES_BLOCK_SIZE) {
            AES_encrypt(reinterpret_cast<const unsigned char *>(&padded_plaintext[i]),
                        reinterpret_cast<unsigned char *>(&ciphertext[i]), &aesKey);
        }

        return ciphertext;
    }

    std::string aesDecrypt(const std::string &ciphertext, const std::string &key) {
        if (key.size() != 16) {
            std::cerr << "Key size must be 16 bytes (128 bits)" << std::endl;
            return "";
        }

        AES_KEY aesKey;
        if (AES_set_decrypt_key(reinterpret_cast<const unsigned char *>(key.c_str()), 128, &aesKey) != 0) {
            std::cerr << "AES_set_decrypt_key failed" << std::endl;
            return "";
        }

        std::string plaintext(ciphertext.size(), 0);

        for (size_t i = 0; i < ciphertext.size(); i += AES_BLOCK_SIZE) {
            AES_decrypt(reinterpret_cast<const unsigned char *>(&ciphertext[i]),
                        reinterpret_cast<unsigned char *>(&plaintext[i]), &aesKey);
        }

        return removePkcs5Padding(plaintext);
    }
}