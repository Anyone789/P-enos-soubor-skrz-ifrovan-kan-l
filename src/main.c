/**
 * @file main.c
 * @author Tomáš Hrbáč (xhrbact00)
 * Last edit: 17.11.2025
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../include/secret.h"

/* Declarations from client/server modules */
int client_run(const char *file_path, const char *server_host);
int server_run(void);

/* Simple CLI: ./secret -r <file> -s <ip|hostname> [-l] */
int main(int argc, char **argv) {
    int opt;
    char *file = NULL;
    char *server = NULL;
    int listen_mode = 0;

    while ((opt = getopt(argc, argv, "r:s:l")) != -1) {
        switch (opt) {
            case 'r': file = optarg; break;
            case 's': server = optarg; break;
            case 'l': listen_mode = 1; break;
            default:
                fprintf(stderr, "Usage: %s -r <file> -s <host> | -l\n", argv[0]);
                return 1;
        }
    }

    if (listen_mode) {
        /* run server */
        return server_run();
    } else {
        if (!file || !server) {
            fprintf(stderr, "Usage: %s -r <file> -s <host>\n", argv[0]);
            return 1;
        }
        /* run client */
        return client_run(file, server);
    }
}
