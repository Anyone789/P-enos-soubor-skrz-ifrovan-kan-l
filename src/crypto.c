/**
 * @file crypto.c
 * @author Tomáš Hrbáč (xhrbact00)
 * Last edit: 17.11.2025
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include "../include/secret.h"

#define SECRET_KEY_LITERAL "xhrbact00"

/*
 * @brief Produce a 32-byte key based on SECRET_KEY_LITERAL
 * Returns: 0 on success, -1 on error
 */
int derive_key_from(unsigned char *out_key)
{
    const unsigned char *base = (const unsigned char *)SECRET_KEY_LITERAL;
    size_t base_len = strlen(SECRET_KEY_LITERAL);

    if (!out_key || base_len == 0) return -1;

    /* Simple expansion of out_key to 32 bytes */
    for (int i = 0; i < 32; ++i) {
        out_key[i] = base[i % base_len];
    }

    return 0;
}

/*
 * @brief Data encryption using AES-256-GCM
 * @param key            — 32-byte AES-256 key
 * @param iv             — initialization vector (recommended 12 bytes)
 * @param iv_len         — length of the initialization vector
 * @param plaintext      — data to be encrypted
 * @param plaintext_len  — length of the plaintext data
 * @param ciphertext     — buffer where the encrypted data will be stored
 * @param tag[16]        — 16-byte GCM authentication tag
 */
int aes_gcm_encrypt(const unsigned char *key,
                    const unsigned char *iv, size_t iv_len,
                    const unsigned char *plaintext, size_t plaintext_len,
                    unsigned char *ciphertext,
                    unsigned char tag[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto error;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1)
        goto error;

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto error;

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1)
        goto error;

    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        goto error;

    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
        goto error;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;

error:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}


int aes_gcm_decrypt(const unsigned char *key,
                    const unsigned char *iv, size_t iv_len,
                    const unsigned char *ciphertext, size_t c_len,
                    const unsigned char tag[16],
                    unsigned char *plaintext_out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0, plaintext_len = 0;
    int ret = -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto done;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1)
        goto done;

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto done;

    if (EVP_DecryptUpdate(ctx, plaintext_out, &len, ciphertext, (int)c_len) != 1)
        goto done;

    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1)
        goto done;

    if (EVP_DecryptFinal_ex(ctx, plaintext_out + len, &len) != 1)
        goto done;

    plaintext_len += len;
    ret = plaintext_len;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/*
 * @brief Computes a SHA-256 hash of a file using streamed reading
 * @param f     — an open FILE* handle to the input file
 * @param out   — 32-byte output buffer where the resulting SHA-256 hash is stored
 *
 * @note The function reads the file incrementally in 4096-byte chunks,
 *       so the entire file does not need to be loaded into memory.
 */
void sha256_stream(FILE *f, unsigned char out[32])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

    unsigned char buffer[4096];
    size_t r;
    while ((r = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        EVP_DigestUpdate(ctx, buffer, r);
    }

    EVP_DigestFinal_ex(ctx, out, NULL);
    EVP_MD_CTX_free(ctx);
}
