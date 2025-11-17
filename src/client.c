/**
 * @file client.c
 * @author Tomáš Hrbáč (xhrbact00)
 * Last edit: 17.11.2025
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "../include/secret.h"

/* Use functions from crypto/protocol modules */
int write_frame(int sockfd, uint8_t type, const void *body, uint32_t body_len);
int read_frame(int sockfd, uint8_t *out_type, void **out_body, uint32_t *out_body_len);
int derive_key_from(unsigned char *out_key);
int aes_gcm_encrypt(const unsigned char *key, const unsigned char *iv, int iv_len,
                    const unsigned char *plaintext, int plaintext_len,
                    unsigned char *ciphertext, unsigned char *tag);

static int connect_to_host(const char *host, int port) {
    struct addrinfo hints, *res, *rp;
    char portstr[16];
    int sock = -1;
    snprintf(portstr, sizeof(portstr), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock == -1) continue;
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    return sock;
}

int client_run(const char *file_path, const char *server_host) {
    FILE *f = NULL;
    unsigned char key[32];
    unsigned char iv[12];
    unsigned char tag[16];
    unsigned char buf[DEFAULT_CHUNK_SIZE];
    unsigned char ciphertext[DEFAULT_CHUNK_SIZE + 32];
    unsigned char file_hash[32];
    struct stat st;
    int sock = -1;
    uint64_t filesize = 0;

    if (stat(file_path, &st) != 0) {
        log_error("cannot stat file: %s", file_path);
        return 1;
    }
    filesize = st.st_size;

    f = fopen(file_path, "rb");
    if (!f) { log_error("cannot open file"); return 1; }

    /* compute sha256 */
    SHA256_CTX shactx;
    SHA256_Init(&shactx);
    size_t r;
    while ((r = fread(buf, 1, sizeof(buf), f)) > 0) {
        SHA256_Update(&shactx, buf, r);
    }
    SHA256_Final(file_hash, &shactx);
    rewind(f);

    /* derive key */
    if (derive_key_from(key) != 0) {
        log_error("key derivation failed"); fclose(f); return 1;
    }

    sock = connect_to_host(server_host, DEFAULT_PORT);
    if (sock < 0) { log_error("connect failed"); fclose(f); return 1; }

    /* HELLO body: sha_256(32)|filename_len(2)|filename|filesize(8)|chunk_size(4) */
    const char *filename = strrchr(file_path, '/');
    if (filename) filename++; else filename = file_path;
    uint16_t fname_len = strlen(filename);
    uint32_t chunk_size = DEFAULT_CHUNK_SIZE;
    uint32_t body_len = 32 + fname_len + 8 + 4;
    unsigned char *body = malloc(body_len);
    unsigned char *p = body;
    memcpy(p, filename, fname_len);
    p += fname_len;
    uint64_t be_filesize = htobe64(filesize);
    memcpy(p, &be_filesize, 8);
    p += 8;
    uint32_t be_chunksz = htonl(chunk_size);
    memcpy(p, &be_chunksz, 4);
    p += 4;

    if (write_frame(sock, FT_HELLO, body, body_len) != 0) { log_error("send HELLO failed"); free(body); close(sock); fclose(f); return 1; }
    free(body);

    uint8_t rtype; void *rbody; uint32_t rlen;
    if (read_frame(sock, &rtype, &rbody, &rlen) != 0) {
        log_error("read HELLO_ACK failed");
        close(sock);
        fclose(f);
        return 1;
    }
    if (rtype != FT_HELLO_ACK) {
        log_error("unexpected frame type");
        free(rbody);
        close(sock);
        fclose(f);
        return 1;
    }
    /* check status */
    uint8_t status = ((unsigned char*)rbody)[0];
    if (status != 0) {
        log_error("server refused transfer");
        free(rbody);
        close(sock);
        fclose(f);
        return 1;
    }
    free(rbody);

    /* send DATA frames */
    uint32_t seq = 0;
    while ((r = fread(buf, 1, chunk_size, f)) > 0) {
        /* generate iv */
        if (!RAND_bytes(iv, sizeof(iv))) {
            log_error("RAND iv failed");
            close(sock);
            fclose(f);
            return 1;
        }
        int outlen = aes_gcm_encrypt(key, iv, sizeof(iv), buf, r, ciphertext, tag);
        if (outlen < 0) {
            log_error("encrypt failed");
            close(sock);
            fclose(f);
            return 1;
        }
        /* DATA body: seq(4)|iv_len(1)|iv|cipher_len(4)|ciphertext|tag_len(1)|tag */
        uint32_t bodylen = 4 + 1 + sizeof(iv) + 4 + outlen + 1 + sizeof(tag);
        unsigned char *db = malloc(bodylen);
        unsigned char *q = db;
        *(uint32_t*)q = htonl(seq); q += 4;
        *q++ = sizeof(iv);
        memcpy(q, iv, sizeof(iv));
        q += sizeof(iv);
        *(uint32_t*)q = htonl(outlen);
        q += 4;
        memcpy(q, ciphertext, outlen);
        q += outlen;
        *q++ = sizeof(tag);
        memcpy(q, tag, sizeof(tag));
        q += sizeof(tag);

        if (write_frame(sock, FT_DATA, db, bodylen) != 0) {
            log_error("send DATA failed");
            free(db);
            close(sock);
            fclose(f);
            return 1;
        }
        free(db);
        seq++;
    }

    /* send FIN: total_chunks(4), sha256(32) */
    uint32_t total_chunks = seq;
    unsigned char fin_body[4 + 32];
    *(uint32_t*)fin_body = htonl(total_chunks);
    memcpy(fin_body + 4, file_hash, 32);
    if (write_frame(sock, FT_FIN, fin_body, sizeof(fin_body)) != 0) {
        log_error("send FIN failed");
        close(sock);
        fclose(f);
        return 1;
    }
    if (read_frame(sock, &rtype, &rbody, &rlen) != 0) {
        log_error("read FIN_ACK failed");
        close(sock);
        fclose(f);
        return 1;
    }
    if (rtype != FT_FIN_ACK) {
        log_error("unexpected frame after FIN");
        free(rbody);
        close(sock);
        fclose(f);
        return 1;
    }
    uint8_t fstatus = ((unsigned char*)rbody)[0];
    if (fstatus != 0) {
        log_error("server reported error in finalization");
        free(rbody);
        close(sock);
        fclose(f);
        return 1;
    }
    free(rbody);

    log_info("file sent: %s (%llu bytes)", filename, (unsigned long long)filesize);

    close(sock);
    fclose(f);
    return 0;
}
