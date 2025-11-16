#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "../include/secret.h"

/* Frame header: 1B type | 1B ver | 2B reserved | 4B body_len (BE) = 8 bytes total */
static int write_all(int fd, const void *buf, size_t len) {
    const unsigned char *p = buf;
    while (len > 0) {
        ssize_t w = write(fd, p, len);
        if (w <= 0) return -1;
        p += w; len -= w;
    }
    return 0;
}
static int read_all(int fd, void *buf, size_t len) {
    unsigned char *p = buf;
    while (len > 0) {
        ssize_t r = read(fd, p, len);
        if (r <= 0) return -1;
        p += r; len -= r;
    }
    return 0;
}

int write_frame(int sockfd, uint8_t type, const void *body, uint32_t body_len) {
    unsigned char hdr[8];
    hdr[0] = type;
    hdr[1] = PROTOCOL_VERSION;
    hdr[2] = hdr[3] = 0;
    uint32_t be_len = htonl(body_len);
    memcpy(hdr + 4, &be_len, 4);
    if (write_all(sockfd, hdr, sizeof(hdr)) != 0) return -1;
    if (body_len > 0 && write_all(sockfd, body, body_len) != 0) return -1;
    return 0;
}

int read_frame(int sockfd, uint8_t *out_type, void **out_body, uint32_t *out_body_len) {
    unsigned char hdr[8];
    if (read_all(sockfd, hdr, sizeof(hdr)) != 0) return -1;
    *out_type = hdr[0];
    uint32_t be_len; memcpy(&be_len, hdr + 4, 4);
    uint32_t body_len = ntohl(be_len);
    *out_body_len = body_len;
    if (body_len > 0) {
        void *buf = malloc(body_len);
        if (!buf) return -1;
        if (read_all(sockfd, buf, body_len) != 0) { free(buf); return -1; }
        *out_body = buf;
    } else {
        *out_body = NULL;
    }
    return 0;
}
