#pragma once

#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h> 

namespace rsa_utils {
    // Function to handle errors
    void handleErrors() {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    std::string rsaPubKeyEncrypt(const std::string &plaintext, std::string &publicKeyStr) {
        BIO *pubBio = BIO_new_mem_buf(publicKeyStr.c_str(), -1);

        if (!pubBio) {
            std::cerr << "Error creating BIOs." << std::endl;
            return "";
        }

        RSA *publicKey = PEM_read_bio_RSA_PUBKEY(pubBio, nullptr, nullptr, nullptr);

        if (!publicKey) {
            std::cerr << "Error loading keys." << std::endl;
            return "";
        }

        int rsaLen = RSA_size(publicKey);
        unsigned char *encryptedText = new unsigned char[rsaLen];

        int result = RSA_public_encrypt(plaintext.length(), reinterpret_cast<const unsigned char *>(plaintext.c_str()), encryptedText, publicKey, RSA_PKCS1_PADDING);
        if (result == -1) {
            handleErrors();
        }

        std::string encrypted(reinterpret_cast<char *>(encryptedText), result);
        delete[] encryptedText;
        RSA_free(publicKey);
        BIO_free(pubBio);
        return encrypted;
    }

    std::string rsaPriKeyDecrypt(const std::string &encryptedText, std::string &privateKeyStr) {

        BIO *priBio = BIO_new_mem_buf(privateKeyStr.c_str(), -1);

        if (!priBio) {
            std::cerr << "Error creating BIOs." << std::endl;
            return "";
        }

        RSA *privateKey = PEM_read_bio_RSAPrivateKey(priBio, nullptr, nullptr, nullptr);

        if (!privateKey) {
            std::cerr << "Error loading keys." << std::endl;
            return "";
        }

        int rsaLen = RSA_size(privateKey);
        unsigned char *decryptedText = new unsigned char[rsaLen];

        int result = RSA_private_decrypt(encryptedText.length(), reinterpret_cast<const unsigned char *>(encryptedText.c_str()), decryptedText, privateKey, RSA_PKCS1_PADDING);
        if (result == -1) {
            handleErrors();
        }

        std::string decrypted(reinterpret_cast<char *>(decryptedText), result);
        delete[] decryptedText;
        RSA_free(privateKey);
        BIO_free(priBio);
        return decrypted;
    }


    std::string rsaPriKeyEncrypt(const std::string &plaintext, std::string &privateKeyStr) {
        BIO *priBio = BIO_new_mem_buf(privateKeyStr.c_str(), -1);

        if (!priBio) {
            std::cerr << "Error creating BIOs." << std::endl;
            return "";
        }

        RSA *privateKey = PEM_read_bio_RSAPrivateKey(priBio, nullptr, nullptr, nullptr);

        if (!privateKey) {
            std::cerr << "Error loading keys." << std::endl;
            return "";
        }

        int rsaLen = RSA_size(privateKey);
        unsigned char *encryptedText = new unsigned char[rsaLen];

        int result = RSA_private_encrypt(plaintext.length(), reinterpret_cast<const unsigned char *>(plaintext.c_str()), encryptedText, privateKey, RSA_PKCS1_PADDING);
        if (result == -1) {
            handleErrors();
        }

        std::string encrypted(reinterpret_cast<char *>(encryptedText), result);
        delete[] encryptedText;

        RSA_free(privateKey);
        BIO_free(priBio);
        return encrypted;
    }

    std::string rsaPubKeyDecrypt(const std::string &cipherText, std::string &publicKeyStr) {
        BIO *pubBio = BIO_new_mem_buf(publicKeyStr.c_str(), -1);

        if (!pubBio) {
            std::cerr << "Error creating BIOs." << std::endl;
            return "";
        }

        RSA *publicKey = PEM_read_bio_RSA_PUBKEY(pubBio, nullptr, nullptr, nullptr);

        if (!publicKey) {
            std::cerr << "Error loading keys." << std::endl;
            return "";
        }

        int rsaLen = RSA_size(publicKey);
        unsigned char *decryptedText = new unsigned char[rsaLen];

        int result = RSA_public_decrypt(cipherText.length(), reinterpret_cast<const unsigned char *>(cipherText.c_str()), decryptedText, publicKey,
                                        RSA_PKCS1_PADDING);
        if (result == -1) {
            handleErrors();
        }

        std::string decrypted(reinterpret_cast<char *>(decryptedText), result);
        delete[] decryptedText;

        RSA_free(publicKey);
        BIO_free(pubBio);

        return decrypted;
    }
}

