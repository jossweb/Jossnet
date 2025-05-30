/*
 * Modified and adapted for the Jossnet project
 * © 2025 FIGUEIRAS Jossua – Licensed under the MIT License.
 *
 * This file contains portions of code derived from the Noise-C project:
 * https://github.com/rweather/noise-c
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 * Licensed under the MIT License.
 */

#ifndef COMMON_H
#define COMMON_H

#endif //COMMON_H

#include <noise/protocol.h>


#define ECHO_PSK_DISABLED           0x00
#define ECHO_PSK_ENABLED            0x01

#define ECHO_PATTERN_NN             0x00
#define ECHO_PATTERN_KN             0x01
#define ECHO_PATTERN_NK             0x02
#define ECHO_PATTERN_KK             0x03
#define ECHO_PATTERN_NX             0x04
#define ECHO_PATTERN_KX             0x05
#define ECHO_PATTERN_XN             0x06
#define ECHO_PATTERN_IN             0x07
#define ECHO_PATTERN_XK             0x08
#define ECHO_PATTERN_IK             0x09
#define ECHO_PATTERN_XX             0x0A
#define ECHO_PATTERN_IX             0x0B
#define ECHO_PATTERN_HFS            0x80

#define ECHO_CIPHER_CHACHAPOLY      0x00
#define ECHO_CIPHER_AESGCM          0x01

#define ECHO_DH_25519               0x00
#define ECHO_DH_448                 0x01
#define ECHO_DH_NEWHOPE             0x02
#define ECHO_DH_MASK                0x0F

#define ECHO_HYBRID_NONE            0x00
#define ECHO_HYBRID_25519           0x10
#define ECHO_HYBRID_448             0x20
#define ECHO_HYBRID_NEWHOPE         0x30
#define ECHO_HYBRID_MASK            0xF0

#define ECHO_HASH_SHA256            0x00
#define ECHO_HASH_SHA512            0x01
#define ECHO_HASH_BLAKE2s           0x02
#define ECHO_HASH_BLAKE2b           0x03

typedef struct
{
    uint8_t psk;
    uint8_t pattern;
    uint8_t cipher;
    uint8_t dh;
    uint8_t hash;

} ProtocolId;

int get_protocol_id(ProtocolId *id, const char *name);
int convert_to_noise_protocol_id(NoiseProtocolId *nid, const ProtocolId *id);
int load_private_key(const char *filename, uint8_t *key, size_t len);
int load_public_key(const char *filename, uint8_t *key, size_t len);
int connect_to_server(const char *hostname, int port);
int accept_client(int port);
int recv_exact(int fd, uint8_t *packet, size_t len);
size_t recv_packet(int fd, uint8_t *packet, size_t max_len);
int send_noise_packet(int fd, const uint8_t *packet, size_t len);
void close_socket(int fd);
