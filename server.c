/*
 * Modified and adapted for the Jossnet project
 * © 2025 Jossua Figueiras – Licensed under the MIT License.
 *
 * This file contains portions of code derived from the Noise-C project:
 * https://github.com/rweather/noise-c
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 * Licensed under the MIT License.
 */

#include <stdio.h>
#include <noise/protocol.h>

/* Loaded keys */
#define CURVE25519_KEY_LEN 32
#define CURVE448_KEY_LEN 56
#define MAX_DH_KEY_LEN 2048

static uint8_t client_key_25519[CURVE25519_KEY_LEN];
static uint8_t server_key_25519[CURVE25519_KEY_LEN];
static uint8_t client_key_448[CURVE448_KEY_LEN];
static uint8_t server_key_448[CURVE448_KEY_LEN];
static uint8_t psk[32];

typedef struct
{
    uint8_t psk;
    uint8_t pattern;
    uint8_t cipher;
    uint8_t dh;
    uint8_t hash;

} EchoProtocolId;

const char* concatenate(char* str1, const char* str2) {
    int i=0;
    while (str1[i] != '\0') {
        ++i;
    }
    for (int j = 0; str2[j] != '\0'; j++, i++) {
        str1[i] = str2[j];
    }
    str1[i] = '\0';
    return str1;
}
int echo_load_public_key(const char *filename, uint8_t *key, size_t len)
{
    FILE *file = fopen(filename, "rb");
    uint32_t group = 0;
    size_t group_size = 0;
    uint32_t digit = 0;
    size_t posn = 0;
    int ch;
    if (len > MAX_DH_KEY_LEN) {
        fprintf(stderr, "\033[31m[!] public key length is not supported\033[0m\n");
        return 0;
    }
    if (!file) {
        perror(filename);
        return 0;
    }
    while ((ch = getc(file)) != EOF) {
        if (ch >= 'A' && ch <= 'Z') {
            digit = ch - 'A';
        } else if (ch >= 'a' && ch <= 'z') {
            digit = ch - 'a' + 26;
        } else if (ch >= '0' && ch <= '9') {
            digit = ch - '0' + 52;
        } else if (ch == '+') {
            digit = 62;
        } else if (ch == '/') {
            digit = 63;
        } else if (ch == '=') {
            break;
        } else if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n') {
            fclose(file);
            fprintf(stderr, "\033[31m[!] %s: invalid character in public key file\033[0m\n", filename);
            return 0;
        }
        group = (group << 6) | digit;
        if (++group_size >= 4) {
            if ((len - posn) < 3) {
                fclose(file);
                fprintf(stderr, "\033[31m[!] %s: public key value is too long\033[0m\n", filename);
                return 0;
            }
            group_size = 0;
            key[posn++] = (uint8_t)(group >> 16);
            key[posn++] = (uint8_t)(group >> 8);
            key[posn++] = (uint8_t)group;
        }
    }
    if (group_size == 3) {
        if ((len - posn) < 2) {
            fclose(file);
            fprintf(stderr, "\033[31m[!] %s: public key value is too long\033[0m\n", filename);
            return 0;
        }
        key[posn++] = (uint8_t)(group >> 10);
        key[posn++] = (uint8_t)(group >> 2);
    } else if (group_size == 2) {
        if ((len - posn) < 1) {
            fclose(file);
            fprintf(stderr, "\033[31m[!] %s: public key value is too long\033[0m\n", filename);
            return 0;
        }
        key[posn++] = (uint8_t)(group >> 4);
    }
    if (posn < len) {
        fclose(file);
        fprintf(stderr, "\033[31m[!] %s: public key value is too short\033[0m\n", filename);
        return 0;
    }
    fclose(file);
    return 1;
}
int echo_load_private_key(const char *filename, uint8_t *key, size_t len)
{
    FILE *file = fopen(filename, "rb");
    size_t posn = 0;
    int ch;
    if (len > MAX_DH_KEY_LEN) {
        fprintf(stderr, "\033[31m[!] private key length is not supported\033[0m\n");
        return 0;
    }
    if (!file) {
        perror(filename);
        return 0;
    }
    while ((ch = getc(file)) != EOF) {
        if (posn >= len) {
            fclose(file);
            fprintf(stderr, "\033[31m[!] %s: private key value is too long\033[0m\n", filename);
            return 0;
        }
        key[posn++] = (uint8_t)ch;
    }
    if (posn < len) {
        fclose(file);
        fprintf(stderr, "\033[31m[!] %s: private key value is too short\033[0m\n", filename);
        return 0;
    }
    fclose(file);
    return 1;
}

int main(void) {
    printf("Jossnet Server prototype 2025\n");
    printf("[*] Loading ...\n");
    NoiseHandshakeState *handshake = 0;
    NoiseCipherState *send_cipher = 0;
    NoiseCipherState *recv_cipher = 0;
    EchoProtocolId id;
    NoiseProtocolId nid;
    NoiseBuffer mbuf;
    size_t message_size;
    const char KEYFOLDER[40] = "keys/";
    int fd;
    int err;
    int ok = 1;
    int action;
    if (noise_init() != NOISE_ERROR_NONE) {
        fprintf(stderr, "\033[31m[X] Noise initialization failed\033[0m\n");
        return 1;
    }
    if (!echo_load_private_key(concatenate(KEYFOLDER, "server_key_25519"), server_key_25519, sizeof(server_key_25519))) {
        printf("\033[31m[X] Can't load server_key_25519\033[0m\n");
        return 1;
    }
    if (!echo_load_private_key("server_key_448", server_key_448, sizeof(server_key_448))) {
        return 1;
    }
    if (!echo_load_public_key
            ("client_key_25519.pub", client_key_25519, sizeof(client_key_25519))) {
        return 1;
            }
    if (!echo_load_public_key
            ("client_key_448.pub", client_key_448, sizeof(client_key_448))) {
        return 1;
            }
    if (!echo_load_public_key("psk", psk, sizeof(psk))) {
        return 1;
    }

}
