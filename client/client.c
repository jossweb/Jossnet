/*
 * Modified and adapted for the Jossnet project
 * © 2025 FIGUEIRAS Jossua – Licensed under the MIT License.
 *
 * This file contains portions of code derived from the Noise-C project:
 * https://github.com/rweather/noise-c
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 * Licensed under the MIT License.
 */

#include <stdio.h>
#include <noise/protocol.h>
#include <stdio.h>
#include <stdlib.h>
#include "../server/common.h"
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#define short_options "c:s:p:gvf"

//you can change theses values
static const char *protocol = "NoisePSK_KK_448_ChaChaPoly_BLAKE2b";
//Port number must be between 1 and 65535
static int port = 4242;
static const char *hostname = "127.168.0.1"; //localhost for test

/* Parsed command-line options */
static const char *client_private_key = "keys/client_key_448";
static const char *server_public_key = "keys/server_key_448.pub";
static const char *psk_file = "keys/psk";
static uint8_t psk[32];
static int padding = 0;
static int fixed_ephemeral = 0;

/* Message buffer for send/receive */
#define MAX_MESSAGE_LEN 4096
static uint8_t message[MAX_MESSAGE_LEN + 2];

/* Curve25519 private key to use when fixed ephemeral mode is selected */
static uint8_t const fixed_ephemeral_25519[32] = {
    0x89, 0x3e, 0x28, 0xb9, 0xdc, 0x6c, 0xa8, 0xd6,
    0x11, 0xab, 0x66, 0x47, 0x54, 0xb8, 0xce, 0xb7,
    0xba, 0xc5, 0x11, 0x73, 0x49, 0xa4, 0x43, 0x9a,
    0x6b, 0x05, 0x69, 0xda, 0x97, 0x7c, 0x46, 0x4a
};

/* Curve448 private key to use when fixed ephemeral mode is selected */
static uint8_t const fixed_ephemeral_448[56] = {
    0x7f, 0xd2, 0x6c, 0x8b, 0x8a, 0x0d, 0x5c, 0x98,
    0xc8, 0x5f, 0xf9, 0xca, 0x1d, 0x7b, 0xc6, 0x6d,
    0x78, 0x57, 0x8b, 0x9f, 0x2c, 0x4c, 0x17, 0x08,
    0x50, 0x74, 0x8b, 0x27, 0x99, 0x27, 0x67, 0xe6,
    0xea, 0x6c, 0xc9, 0x99, 0x2a, 0x56, 0x1c, 0x9d,
    0x19, 0xdf, 0xc3, 0x42, 0xe2, 0x60, 0xc2, 0x80,
    0xef, 0x4f, 0x3f, 0x9b, 0x8f, 0x87, 0x9d, 0x4e
};

/* New Hope private key to use when fixed ephemeral mode is selected */
static uint8_t const fixed_ephemeral_newhope[64] = {
    0x93, 0x4d, 0x60, 0xb3, 0x56, 0x24, 0xd7, 0x40,
    0xb3, 0x0a, 0x7f, 0x22, 0x7a, 0xf2, 0xae, 0x7c,
    0x67, 0x8e, 0x4e, 0x04, 0xe1, 0x3c, 0x5f, 0x50,
    0x9e, 0xad, 0xe2, 0xb7, 0x9a, 0xea, 0x77, 0xe2,
    0x3e, 0x2a, 0x2e, 0xa6, 0xc9, 0xc4, 0x76, 0xfc,
    0x49, 0x37, 0xb0, 0x13, 0xc9, 0x93, 0xa7, 0x93,
    0xd6, 0xc0, 0xab, 0x99, 0x60, 0x69, 0x5b, 0xa8,
    0x38, 0xf6, 0x49, 0xda, 0x53, 0x9c, 0xa3, 0xd0
};
static int set_fixed_ephemeral(NoiseDHState *dh)
{
    if (!dh)
        return NOISE_ERROR_NONE;
    if (noise_dhstate_get_dh_id(dh) == NOISE_DH_CURVE25519) {
        return noise_dhstate_set_keypair_private
            (dh, fixed_ephemeral_25519, sizeof(fixed_ephemeral_25519));
    } else if (noise_dhstate_get_dh_id(dh) == NOISE_DH_CURVE448) {
        return noise_dhstate_set_keypair_private
            (dh, fixed_ephemeral_448, sizeof(fixed_ephemeral_448));
    } else if (noise_dhstate_get_dh_id(dh) == NOISE_DH_NEWHOPE) {
        return noise_dhstate_set_keypair_private
            (dh, fixed_ephemeral_newhope, sizeof(fixed_ephemeral_newhope));
    } else {
        return NOISE_ERROR_UNKNOWN_ID;
    }
}
static int initialize_handshake
    (NoiseHandshakeState *handshake, const void *prologue, size_t prologue_len)
{
    NoiseDHState *dh;
    uint8_t *key = 0;
    size_t key_len = 0;
    int err;

    /* Set the prologue first */
    err = noise_handshakestate_set_prologue(handshake, prologue, prologue_len);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("prologue", err);
        return 0;
    }

    /* Set the PSK if one is present.  This will fail if a PSK is not needed.
       If a PSK is needed but it wasn't provided then the protocol will
       fail later when noise_handshakestate_start() is called. */
    if (psk_file && noise_handshakestate_needs_pre_shared_key(handshake)) {
        if (!load_public_key(psk_file, psk, sizeof(psk)))
            return 0;
        err = noise_handshakestate_set_pre_shared_key
            (handshake, psk, sizeof(psk));
        if (err != NOISE_ERROR_NONE) {
            noise_perror("psk", err);
            return 0;
        }
    }

    /* Set the local keypair for the client */
    if (noise_handshakestate_needs_local_keypair(handshake)) {
        if (client_private_key) {
            dh = noise_handshakestate_get_local_keypair_dh(handshake);
            key_len = noise_dhstate_get_private_key_length(dh);
            key = (uint8_t *)malloc(key_len);
            if (!key)
                return 0;
            if (!load_private_key(client_private_key, key, key_len)) {
                noise_free(key, key_len);
                return 0;
            }
            err = noise_dhstate_set_keypair_private(dh, key, key_len);
            noise_free(key, key_len);
            if (err != NOISE_ERROR_NONE) {
                noise_perror("set client private key", err);
                return 0;
            }
        } else {
            fprintf(stderr, "Client private key required, but not provided.\n");
            return 0;
        }
    }

    /* Set the remote public key for the server */
    if (noise_handshakestate_needs_remote_public_key(handshake)) {
        if (server_public_key) {
            dh = noise_handshakestate_get_remote_public_key_dh(handshake);
            key_len = noise_dhstate_get_public_key_length(dh);
            key = (uint8_t *)malloc(key_len);
            if (!key)
                return 0;
            if (!load_public_key(server_public_key, key, key_len)) {
                noise_free(key, key_len);
                return 0;
            }
            err = noise_dhstate_set_public_key(dh, key, key_len);
            noise_free(key, key_len);
            if (err != NOISE_ERROR_NONE) {
                noise_perror("set server public key", err);
                return 0;
            }
        } else {
            fprintf(stderr, "Server public key required, but not provided.\n");
            return 0;
        }
    }

    /* Set the fixed local ephemeral value if necessary */
    if (fixed_ephemeral) {
        dh = noise_handshakestate_get_fixed_ephemeral_dh(handshake);
        err = set_fixed_ephemeral(dh);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("fixed ephemeral value", err);
            return 0;
        }
        dh = noise_handshakestate_get_fixed_hybrid_dh(handshake);
        err = set_fixed_ephemeral(dh);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("fixed ephemeral hybrid value", err);
            return 0;
        }
    }

    /* Ready to go */
    return 1;
}
int client() {
    NoiseHandshakeState *handshake;
    NoiseCipherState *send_cipher = 0;
    NoiseCipherState *recv_cipher = 0;
    NoiseRandState *rand = 0;
    NoiseBuffer mbuf;
    ProtocolId id;
    int err, ok;
    int action;
    int fd;
    size_t message_size;
    size_t max_line_len;

    if (noise_init() != NOISE_ERROR_NONE) {
        fprintf(stderr, "\033[31m[X] Noise initialization failed\033[0m\n");
        return 1;
    }

    /* Create a HandshakeState object for the protocol */
    err = noise_handshakestate_new_by_name
        (&handshake, protocol, NOISE_ROLE_INITIATOR);
    if (err != NOISE_ERROR_NONE) {
        noise_perror(protocol, err);
        return 1;
    }

    /* Set the handshake options and verify that everything we need
       has been supplied on the command-line. */
    if (!initialize_handshake(handshake, &id, sizeof(id))) {
        noise_handshakestate_free(handshake);
        return 1;
    }

    /* Attempt to connect to the remote party */
    fd = connect_to_server(hostname, port);
    if (fd < 0) {
        noise_handshakestate_free(handshake);
        return 1;
    }

    /* Send the echo protocol identifier to the server */
    ok = 1;
    if (!send_noise_packet(fd, (const uint8_t *)&id, sizeof(id)))
        ok = 0;

    /* Start the handshake */
    if (ok) {
        err = noise_handshakestate_start(handshake);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("start handshake", err);
            ok = 0;
        }
    }

    /* Run the handshake until we run out of things to read or write */
    while (ok) {
        action = noise_handshakestate_get_action(handshake);
        if (action == NOISE_ACTION_WRITE_MESSAGE) {
            /* Write the next handshake message with a zero-length payload */
            noise_buffer_set_output(mbuf, message + 2, sizeof(message) - 2);
            err = noise_handshakestate_write_message(handshake, &mbuf, NULL);
            if (err != NOISE_ERROR_NONE) {
                noise_perror("write handshake", err);
                ok = 0;
                break;
            }
            message[0] = (uint8_t)(mbuf.size >> 8);
            message[1] = (uint8_t)mbuf.size;
            if (!send_noise_packet(fd, message, mbuf.size + 2)) {
                ok = 0;
                break;
            }
        } else if (action == NOISE_ACTION_READ_MESSAGE) {
            /* Read the next handshake message and discard the payload */
            message_size = recv_packet(fd, message, sizeof(message));
            if (!message_size) {
                ok = 0;
                break;
            }
            noise_buffer_set_input(mbuf, message + 2, message_size - 2);
            err = noise_handshakestate_read_message(handshake, &mbuf, NULL);
            if (err != NOISE_ERROR_NONE) {
                noise_perror("read handshake", err);
                ok = 0;
                break;
            }
        } else {
            /* Either the handshake has finished or it has failed */
            break;
        }
    }

    /* If the action is not "split", then the handshake has failed */
    if (ok && noise_handshakestate_get_action(handshake) != NOISE_ACTION_SPLIT) {
        fprintf(stderr, "protocol handshake failed\n");
        ok = 0;
    }

    /* Split out the two CipherState objects for send and receive */
    if (ok) {
        err = noise_handshakestate_split(handshake, &send_cipher, &recv_cipher);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("split to start data transfer", err);
            ok = 0;
        }
    }

    /* We no longer need the HandshakeState */
    noise_handshakestate_free(handshake);
    handshake = 0;

    /* If we will be padding messages, we will need a random number generator */
    if (ok && padding) {
        err = noise_randstate_new(&rand);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("random number generator", err);
            ok = 0;
        }
    }

    /* Tell the user that the handshake has been successful */
    if (ok) {
        printf("%s handshake complete.  Enter text to be echoed ...\n", protocol);
    }

    /* Read lines from stdin, send to the server, and wait for echoes */
    max_line_len = sizeof(message) - 2 - noise_cipherstate_get_mac_length(send_cipher);
    while (ok && fgets((char *)(message + 2), max_line_len, stdin)) {
        /* Pad the message to a uniform size */
        message_size = strlen((const char *)(message + 2));
        if (padding) {
            err = noise_randstate_pad
                (rand, message + 2, message_size, max_line_len,
                 NOISE_PADDING_RANDOM);
            if (err != NOISE_ERROR_NONE) {
                noise_perror("pad", err);
                ok = 0;
                break;
            }
            message_size = max_line_len;
        }

        /* Encrypt the message and send it */
        noise_buffer_set_inout
            (mbuf, message + 2, message_size, sizeof(message) - 2);
        err = noise_cipherstate_encrypt(send_cipher, &mbuf);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("write", err);
            ok = 0;
            break;
        }
        message[0] = (uint8_t)(mbuf.size >> 8);
        message[1] = (uint8_t)mbuf.size;
        if (!send_noise_packet(fd, message, mbuf.size + 2)) {
            ok = 0;
            break;
        }

        /* Wait for a message from the server */
        message_size = recv_packet(fd, message, sizeof(message));
        if (!message_size) {
            fprintf(stderr, "Remote side terminated the connection\n");
            ok = 0;
            break;
        }

        /* Decrypt the incoming message */
        noise_buffer_set_input(mbuf, message + 2, message_size - 2);
        err = noise_cipherstate_decrypt(recv_cipher, &mbuf);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("read", err);
            ok = 0;
            break;
        }

        /* Remove padding from the message if necessary */
        if (padding) {
            /* Find the first '\n' and strip everything after it */
            const uint8_t *end = (const uint8_t *)
                memchr(mbuf.data, '\n', mbuf.size);
            if (end)
                mbuf.size = end + 1 - mbuf.data;
        }

        /* Write the echo to standard output */
        fputs("Received: ", stdout);
        fwrite(mbuf.data, 1, mbuf.size, stdout);
    }

    /* Clean up and exit */
    noise_cipherstate_free(send_cipher);
    noise_cipherstate_free(recv_cipher);
    noise_randstate_free(rand);
    close_socket(fd);
    return ok ? 0 : 1;
}