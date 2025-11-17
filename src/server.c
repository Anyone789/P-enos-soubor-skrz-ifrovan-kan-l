/**
 * @file server.c
 * @author Tomáš Hrbáč (xhrbact00)
 * Last edit: 17.11.2025
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include "../include/secret.h"

int read_frame(int sockfd, uint8_t *out_type, void **out_body, uint32_t *out_body_len);
int write_frame(int sockfd, uint8_t type, const void *body, uint32_t body_len);
int derive_key_from(unsigned char *out_key);
int aes_gcm_decrypt(const unsigned char *key, const unsigned char *iv, int iv_len,
                    const unsigned char *ciphertext, int ciphertext_len,
                    const unsigned char *tag, unsigned char *plaintext);

static void *worker(void *arg) {
    int client = (int)(intptr_t)arg;
    uint8_t rtype; void *rbody = NULL; uint32_t rlen;
    unsigned char key[32];
    FILE *outf = NULL;
    unsigned char tmpname[512];
    unsigned char username[256];
    unsigned char expected_hash[32];
    unsigned char computed_hash[32];
    SHA256_CTX shactx;

    if (read_frame(client, &rtype, &rbody, &rlen) != 0) goto cleanup;
    if (rtype != FT_HELLO) goto cleanup;
    unsigned char *p = rbody;
    int uname_len = *p; p++;
    memcpy(username, p, uname_len); username[uname_len] = '\0'; p += uname_len;
    uint16_t fname_len = ntohs(*(uint16_t*)p); p += 2;
    char filename[MAX_FILENAME_LEN+1];
    memcpy(filename, p, fname_len); filename[fname_len] = '\0'; p += fname_len;

    /* derive key */
    if (derive_key_from(key) != 0) {
        /* send nok HELLO_ACK */
        unsigned char err[1] = {1};
        write_frame(client, FT_HELLO_ACK, err, 1);
        goto cleanup;
    }

    /* send OK HELLO_ACK */
    unsigned char ok[1] = {0};
    write_frame(client, FT_HELLO_ACK, ok, 1);

    snprintf((char*)tmpname, sizeof(tmpname), "%s.tmp.%d", filename, getpid());
    outf = fopen((char*)tmpname, "wb");
    if (!outf) goto cleanup;

    SHA256_Init(&shactx);

    while (1) {
        if (read_frame(client, &rtype, &rbody, &rlen) != 0) goto cleanup;
        if (rtype == FT_DATA) {
            unsigned char *q = rbody;
            uint32_t seq = ntohl(*(uint32_t*)q); q += 4;
            int iv_len = *q; q++;
            unsigned char iv[16]; memcpy(iv, q, iv_len); q += iv_len;
            uint32_t cipher_len = ntohl(*(uint32_t*)q); q += 4;
            unsigned char *cipher = malloc(cipher_len);
            memcpy(cipher, q, cipher_len); q += cipher_len;
            int tag_len = *q; q++;
            unsigned char tag[16]; memcpy(tag, q, tag_len); q += tag_len;
            unsigned char *plain = malloc(cipher_len + 16);
            int plain_len = aes_gcm_decrypt(key, iv, iv_len, cipher, cipher_len, tag, plain);
            free(cipher);
            if (plain_len < 0) { log_error("decrypt failed for seq %u", seq); free(plain); goto cleanup; }
            fwrite(plain, 1, plain_len, outf);
            SHA256_Update(&shactx, plain, plain_len);
            free(plain);
            free(rbody); rbody = NULL;
        } else if (rtype == FT_FIN) {
            if (rlen < 4 + 32) goto cleanup;
            uint32_t total_chunks = ntohl(*(uint32_t*)rbody);
            memcpy(expected_hash, (unsigned char*)rbody + 4, 32);
            SHA256_Final(computed_hash, &shactx);
            /* compare hashes */
            if (memcmp(expected_hash, computed_hash, 32) != 0) {
                unsigned char ferr[1] = {1};
                write_frame(client, FT_FIN_ACK, ferr, 1);
                goto cleanup;
            }
            unsigned char fok[1] = {0};
            write_frame(client, FT_FIN_ACK, fok, 1);
            /* rename tmp file */
            fclose(outf); outf = NULL;
            rename((char*)tmpname, filename);
            log_info("received file: %s (%u chunks)", filename, total_chunks);
            break;
        } else {
            free(rbody); rbody = NULL;
        }
    }

cleanup:
    if (rbody) free(rbody);
    if (outf) fclose(outf);
    close(client);
    return NULL;
}

int server_run(void) {
    int sfd, cfd;
    struct sockaddr_in addr;
    int opt = 1;
    pthread_t thr;

    sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) { perror("socket"); return 1; }
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(DEFAULT_PORT);
    if (bind(sfd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("bind"); 
        close(sfd);
        return 1;
    }
    if (listen(sfd, 5) != 0) {
        perror("listen");
        close(sfd);
        return 1;
    }
    log_info("server listening on port %d", DEFAULT_PORT);
    while (1) {
        cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) continue;
        if (pthread_create(&thr, NULL, worker, (void*)(intptr_t)cfd) != 0) {
            close(cfd);
            continue;
        }
        pthread_detach(thr);
    }
    close(sfd);
    return 0;
}
