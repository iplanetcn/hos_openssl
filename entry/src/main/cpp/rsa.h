#include <iostream>
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define CRYPTO_RSA_KEY_LEN_4096 4096
#define CRYPTO_RSA_KEY_LEN_2048 2048
#define CRYPTO_RSA_KEY_LEN_1024 1024
#define CRYPTO_RSA_KEY_EXP 65535

#define CRYPTO_PRINT_ERROR fprintf(stderr, "[x] %s\n", strerror(errno))

using namespace std;

class CryptoRSA {
public:
    bool GenerateKeys(int key_length) {
        SetKeyLength(key_length);
        pRSA = RSA_generate_key(GetKeyLength(), CRYPTO_RSA_KEY_EXP, NULL, NULL);
        if (RSA_check_key(pRSA) != 1) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        return true;
    }
    void SetKeyLength(int key_length) { keylen = key_length; }
    int GetKeyLength() { return keylen; }
    bool WritePublicKeyFile(char *key_public) {
        FILE *fp = fopen(key_public, "w");
        if (fp == NULL) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        if (PEM_write_RSAPublicKey(fp, pRSA) == 0) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        fclose(fp);
        return true;
    }
    bool WritePrivateKeyFile(char *key_private) {
        FILE *fp = fopen(key_private, "w");
        if (fp == NULL) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        if (PEM_write_RSAPrivateKey(fp, pRSA, NULL, NULL, 0, NULL, NULL) == 0) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        return true;
    }
    bool ReadPublicKeyBuffer(void *src, size_t src_size) {
        FILE *fp = fmemopen(src, src_size, "rb");
        if (fp == NULL) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        if (PEM_read_RSAPublicKey(fp, &pRSA, NULL, NULL) == NULL) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        fclose(fp);
        return true;
    }
    bool ReadPublicKeyFile(char *key_public) {
        FILE *fp = fopen(key_public, "rb");
        if (fp == NULL) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        if (PEM_read_RSAPublicKey(fp, &pRSA, NULL, NULL) == NULL) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        fclose(fp);
        return true;
    }
    bool ReadPrivateKeyBuffer(void *src, size_t src_size) {
        FILE *fp = fmemopen(src, src_size, "rb");
        if (fp == NULL) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        if (PEM_read_RSAPrivateKey(fp, &pRSA, NULL, NULL) == NULL) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        fclose(fp);
        return true;
    }
    bool ReadPrivateKeyFile(char *key_private) {
        FILE *fp = fopen(key_private, "rb");
        if (fp == NULL) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        if (PEM_read_RSAPrivateKey(fp, &pRSA, NULL, NULL) == NULL) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        fclose(fp);
        return true;
    }
    void InitKeyPair() { pRSA = RSA_new(); }
    bool InitPlainText() {
        plaintext = malloc(GetCipherTextSize());
        if (plaintext == NULL) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        memset(plaintext, 0, GetCipherTextSize());
        return true;
    }
    bool InitCipherText() {
        ciphertext = malloc(GetCipherTextSize());
        if (ciphertext == NULL) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        memset(ciphertext, 0, GetCipherTextSize());
        return true;
    }
    void CleanupCipherText() { free(ciphertext); }
    void CleanupPlainText() { free(plaintext); }
    void CleanupKeyPair() { RSA_free(pRSA); }
    void Initialize() {
        InitKeyPair();
        InitPlainText();
        InitCipherText();
    }
    void InitBuffers() {
        InitPlainText();
        InitCipherText();
    }
    void Cleanup() {
        CleanupKeyPair();
        CleanupPlainText();
        CleanupCipherText();
    }
    void CleanupBuffers() {
        CleanupPlainText();
        CleanupCipherText();
    }
    bool SetPlainText(void *src, size_t src_size) {
        if (src_size > (size_t)GetCipherTextSize()) {
            fprintf(stderr, "[x] the data size of %d bytes exceeds the limit of %d bytes\n", (int)src_size,
                    (int)GetCipherTextSize());
            return false;
        }
        plaintext_size = src_size;
        memcpy(plaintext, src, plaintext_size);
        return true;
    }
    bool SetCipherText(void *src, size_t src_size) {
        if (src_size > (size_t)GetCipherTextSize()) {
            fprintf(stderr, "[x] the data size of %d bytes exceeds the limit of %d bytes\n", (int)src_size,
                    (int)GetCipherTextSize());
            return false;
        }
        memcpy(ciphertext, src, src_size);
        return true;
    }
    void *GetPlainText() { return plaintext; }
    int GetPlainTextSize() { return plaintext_size; }
    void *GetCipherText() { return ciphertext; }
    RSA *GetRSABlob() { return pRSA; }
    int GetCipherTextSize() { return RSA_size(pRSA); }
    void DebugCipherText() { hex_dump((char *)"ciphertext", ciphertext, GetCipherTextSize()); }
    void DebugPlainText() { hex_dump((char *)"plaintext", plaintext, plaintext_size); }
    bool WriteCipherTextFile(char *ciphertext_file) {
        FILE *fp = fopen(ciphertext_file, "wb");
        if (fp == NULL) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        if (fwrite(ciphertext, GetCipherTextSize(), 1, fp) <= 0) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        fclose(fp);
        return true;
    }
    bool WritePlainTextFile(char *plaintext_file) {
        FILE *fp_decrypted = fopen(plaintext_file, "wb");
        if (fp_decrypted == NULL) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        if (fwrite(plaintext, GetPlainTextSize(), 1, fp_decrypted) <= 0) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        fclose(fp_decrypted);
        return true;
    }
    bool PublicEncrypt(void *src, size_t src_size) {
        if (SetPlainText(src, src_size) == false) {
            return false;
        }
        int result = RSA_public_encrypt(plaintext_size, (unsigned char *)plaintext, (unsigned char *)ciphertext, pRSA,
                                        RSA_PKCS1_PADDING);
        if (result < 0) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        return true;
    }
    bool PublicDecrypt(void *src, size_t src_size) {
        if (SetCipherText(src, src_size) == false) {
            return false;
        }
        int result = RSA_public_decrypt(GetCipherTextSize(), (unsigned char *)ciphertext, (unsigned char *)plaintext,
                                        pRSA, RSA_PKCS1_PADDING);
        if (result < 0) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        plaintext_size = result;
        return true;
    }
    bool PrivateEncrypt(void *src, size_t src_size) {
        if (SetPlainText(src, src_size) == false) {
            return false;
        }
        int result = RSA_private_encrypt(plaintext_size, (unsigned char *)plaintext, (unsigned char *)ciphertext, pRSA,
                                         RSA_PKCS1_PADDING);
        if (result < 0) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        return true;
    }
    bool PrivateDecrypt(void *src, size_t src_size) {
        if (SetCipherText(src, src_size) == false) {
            return false;
        }
        int result = RSA_private_decrypt(GetCipherTextSize(), (unsigned char *)ciphertext, (unsigned char *)plaintext,
                                         pRSA, RSA_PKCS1_PADDING);
        if (result < 0) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        plaintext_size = result;
        return true;
    }
    bool ReadPlainTextFile(char *plaintext_file) {
        FILE *fp_plaintext = fopen(plaintext_file, "rb");
        if (fp_plaintext == NULL) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        if (file_size(fp_plaintext) > GetCipherTextSize()) {
            fprintf(stderr, "[x] the data size of %d bytes exceeds the limit of %d bytes\n", file_size(fp_plaintext),
                    GetCipherTextSize());
            return false;
        }
        if (fread(plaintext, file_size(fp_plaintext), 1, fp_plaintext) <= 0) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        plaintext_size = file_size(fp_plaintext);
        fclose(fp_plaintext);
        return true;
    }
    bool ReadCipherTextFile(char *ciphertext_file) {
        FILE *fp_encrypted = fopen(ciphertext_file, "rb");
        if (fp_encrypted == NULL) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        if (fread(ciphertext, GetCipherTextSize(), 1, fp_encrypted) <= 0) {
            CRYPTO_PRINT_ERROR;
            return false;
        }
        fclose(fp_encrypted);
        return true;
    }
    bool PrivateDecryptFile(char *encrypted_file, char *decrypted_file) {
        if (ReadCipherTextFile(encrypted_file) == false) {
            return false;
        }
        if (PrivateDecrypt(ciphertext, GetCipherTextSize()) == false) {
            return false;
        }
        if (WritePlainTextFile(decrypted_file) == false) {
            return false;
        }
        return true;
    }
    bool PublicDecryptFile(char *encrypted_file, char *decrypted_file) {
        if (ReadCipherTextFile(encrypted_file) == false) {
            return false;
        }
        if (PublicDecrypt(ciphertext, GetCipherTextSize()) == false) {
            return false;
        }
        if (WritePlainTextFile(decrypted_file) == false) {
            return false;
        }
        return true;
    }

private:
    void hex_dump(char *desc, void *addr, size_t len) {
        int i;
        unsigned char buff[17];
        const unsigned char *pc = (const unsigned char *)addr;
        if (desc != NULL) {
            printf("%s:\n", desc);
        }
        for (i = 0; i < (int)len; i++) {
            if ((i % 16) == 0) {
                if (i != 0) {
                    printf("  %s\n", buff);
                }
                printf("  %04x ", i);
            }
            printf(" %02x", pc[i]);
            if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
                buff[i % 16] = '.';
            } else {
                buff[i % 16] = pc[i];
            }
            buff[(i % 16) + 1] = '\0';
        }
        while ((i % 16) != 0) {
            printf("   ");
            i++;
        }
        printf("  %s\n", buff);
    }
    int file_size(FILE *fp) {
        int prev = ftell(fp);
        fseek(fp, 0L, SEEK_END);
        int sz = ftell(fp);
        fseek(fp, prev, SEEK_SET);
        return sz;
    }
    void *plaintext;
    void *ciphertext;
    int keylen;
    size_t plaintext_size;
    RSA *pRSA;
};