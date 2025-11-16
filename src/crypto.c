#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include "../include/secret.h"

int derive_key_from_passphrase(const char *passphrase, const unsigned char *salt, int salt_len,
                               unsigned char *out_key /* 32 bytes */) {
    if (!passphrase || !salt || !out_key) return -1;
    const int iterations = 100000;
    if (!PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase), salt, salt_len, iterations, EVP_sha256(), 32, out_key)) {
        return -1;
    }
    return 0;
}

int aes_gcm_encrypt(const unsigned char *key, const unsigned char *iv, int iv_len,
                    const unsigned char *plaintext, int plaintext_len,
                    unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, ciphertext_len = 0;
    int ret = -1;

    if (!key || !iv || !plaintext || !ciphertext || !tag) return -1;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto done;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto done;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) goto done;
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) goto done;
    ciphertext_len = len;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) goto done;
    ciphertext_len += len;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) goto done;
    ret = ciphertext_len;
done:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int aes_gcm_decrypt(const unsigned char *key, const unsigned char *iv, int iv_len,
                    const unsigned char *ciphertext, int ciphertext_len,
                    const unsigned char *tag, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, plaintext_len = 0;
    int ret = -1;

    if (!key || !iv || !ciphertext || !plaintext || !tag) return -1;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto done;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto done;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) goto done;
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) goto done;
    plaintext_len = len;
    /* set expected tag */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag)) goto done;
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) goto done;
    plaintext_len += len;
    ret = plaintext_len;
    
    done:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}
