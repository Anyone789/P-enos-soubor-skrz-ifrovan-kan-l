#ifndef SECRET_H
#define SECRET_H

#include <stdint.h>

#define DEFAULT_PORT 54321
#define PROTOCOL_VERSION 1
#define MAX_FILENAME_LEN 512
#define DEFAULT_CHUNK_SIZE 1024

/* Frame types */
enum frame_type {
    FT_HELLO = 1,
    FT_HELLO_ACK = 2,
    FT_DATA = 3,
    FT_DATA_ACK = 4,
    FT_FIN = 5,
    FT_FIN_ACK = 6,
    FT_ERROR = 255
};

/* Simple logger */
void log_info(const char *fmt, ...);
void log_error(const char *fmt, ...);

#endif // SECRET_H
