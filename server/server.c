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
#include <stdlib.h>
#include "common.h"
#include <noise/protocol.h>

/* Loaded keys */
#define CURVE25519_KEY_LEN 32
#define CURVE448_KEY_LEN 56
static uint8_t client_key_25519[CURVE25519_KEY_LEN];
static uint8_t server_key_25519[CURVE25519_KEY_LEN];
static uint8_t client_key_448[CURVE448_KEY_LEN];
static uint8_t server_key_448[CURVE448_KEY_LEN];
static uint8_t psk[32];

/* Message buffer for send/receive */
#define MAX_MESSAGE_LEN 65535
static uint8_t message[MAX_MESSAGE_LEN + 2];

static int fixed_ephemeral = 0;

int gen_keys();

/* Curve25519 private key to use when fixed ephemeral mode is selected */
static uint8_t const fixed_ephemeral_25519[32] = {
    0xbb, 0xdb, 0x4c, 0xdb, 0xd3, 0x09, 0xf1, 0xa1,
    0xf2, 0xe1, 0x45, 0x69, 0x67, 0xfe, 0x28, 0x8c,
    0xad, 0xd6, 0xf7, 0x12, 0xd6, 0x5d, 0xc7, 0xb7,
    0x79, 0x3d, 0x5e, 0x63, 0xda, 0x6b, 0x37, 0x5b
};

/* Curve448 private key to use when fixed ephemeral mode is selected */
static uint8_t const fixed_ephemeral_448[56] = {
    0x3f, 0xac, 0xf7, 0x50, 0x3e, 0xbe, 0xe2, 0x52,
    0x46, 0x56, 0x89, 0xf1, 0xd4, 0xe3, 0xb1, 0xdd,
    0x21, 0x96, 0x39, 0xef, 0x9d, 0xe4, 0xff, 0xd6,
    0x04, 0x9d, 0x6d, 0x71, 0xa0, 0xf6, 0x21, 0x26,
    0x84, 0x0f, 0xeb, 0xb9, 0x90, 0x42, 0x42, 0x1c,
    0xe1, 0x2a, 0xf6, 0x62, 0x6d, 0x98, 0xd9, 0x17,
    0x02, 0x60, 0x39, 0x0f, 0xbc, 0x83, 0x99, 0xa5
};

/* New Hope private key to use when fixed ephemeral mode is selected */
static uint8_t const fixed_ephemeral_newhope[32] = {
    0xba, 0xc5, 0xba, 0x88, 0x1d, 0xd3, 0x5c, 0x59,
    0x71, 0x96, 0x70, 0x00, 0x46, 0x92, 0xd6, 0x75,
    0xb8, 0x3c, 0x98, 0xdb, 0x6a, 0x0e, 0x55, 0x80,
    0x0b, 0xaf, 0xeb, 0x7e, 0x70, 0x49, 0x1b, 0xf4
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
/* Initializes the handshake with all necessary keys */
static int initialize_handshake(NoiseHandshakeState *handshake, const NoiseProtocolId *nid, const void *prologue, size_t prologue_len)
{
    NoiseDHState *dh;
    int dh_id;
    int err;

    /* Set the prologue first */
    err = noise_handshakestate_set_prologue(handshake, prologue, prologue_len);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("prologue", err);
        return 0;
    }

    /* Set the PSK if one is needed */
    if (nid->prefix_id == NOISE_PREFIX_PSK) {
        err = noise_handshakestate_set_pre_shared_key
            (handshake, psk, sizeof(psk));
        if (err != NOISE_ERROR_NONE) {
            noise_perror("psk", err);
            return 0;
        }
    }

    /* Set the local keypair for the server based on the DH algorithm */
    if (noise_handshakestate_needs_local_keypair(handshake)) {
        dh = noise_handshakestate_get_local_keypair_dh(handshake);
        dh_id = noise_dhstate_get_dh_id(dh);
        if (dh_id == NOISE_DH_CURVE25519) {
            err = noise_dhstate_set_keypair_private
                (dh, server_key_25519, sizeof(server_key_25519));
        } else if (dh_id == NOISE_DH_CURVE448) {
            err = noise_dhstate_set_keypair_private
                (dh, server_key_448, sizeof(server_key_448));
        } else {
            err = NOISE_ERROR_UNKNOWN_ID;
        }
        if (err != NOISE_ERROR_NONE) {
            noise_perror("set server private key", err);
            return 0;
        }
    }

    /* Set the remote public key for the client */
    if (noise_handshakestate_needs_remote_public_key(handshake)) {
        dh = noise_handshakestate_get_remote_public_key_dh(handshake);
        dh_id = noise_dhstate_get_dh_id(dh);
        if (dh_id == NOISE_DH_CURVE25519) {
            err = noise_dhstate_set_public_key
                (dh, client_key_25519, sizeof(client_key_25519));
        } else if (dh_id == NOISE_DH_CURVE448) {
            err = noise_dhstate_set_public_key
                (dh, client_key_448, sizeof(client_key_448));
        } else {
            err = NOISE_ERROR_UNKNOWN_ID;
        }
        if (err != NOISE_ERROR_NONE) {
            noise_perror("set client public key", err);
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
const char* concatenate(char* str1, const char* str2) {
    int i = 0;
    while (str1[i] != '\0') {
        ++i;
    }

    for (int j = 0; str2[j] != '\0'; j++, i++) {
        str1[i] = str2[j];
    }

    str1[i] = '\0';
    return str1;
}
int server() {
    printf("Jossnet Server prototype 2025\n");
    printf("[*] Loading ...\n");
    NoiseHandshakeState *handshake = 0;
    NoiseCipherState *send_cipher = 0;
    NoiseCipherState *recv_cipher = 0;
    ProtocolId id;
    NoiseProtocolId nid;
    NoiseBuffer mbuf;
    size_t message_size;
    const char KEYFOLDER[40] = "keys/";
    int fd;
    int err;
    int ok = 1;
    int action;
    int port = 4242;

    int gen = gen_keys();
    printf("[*] Generating keys %d\n", gen);

    if (noise_init() != NOISE_ERROR_NONE) {
        fprintf(stderr, "\033[31m[X] Noise initialization failed\033[0m\n");
        return 0;
    }
    if (!load_private_key(concatenate(KEYFOLDER, "server_key_25519"), server_key_25519, sizeof(server_key_25519))) {
        printf("\033[31m[X] Can't load server_key_25519\033[0m\n");
        return 0;
    }
    if (!load_private_key("server_key_448", server_key_448, sizeof(server_key_448))) {
        return 0;
    }
    if (!load_public_key("client_key_25519.pub", client_key_25519, sizeof(client_key_25519))) {
        return 1;
    }
    if (!load_public_key("client_key_448.pub", client_key_448, sizeof(client_key_448))) {
        return 0;
    }
    if (!load_public_key("keys/psk", psk, sizeof(psk))) {
        return 0;
    }
    fd = accept_client(port);

    if (ok && !recv_exact(fd, (uint8_t *)&id, sizeof(id))) {
        fprintf(stderr, "Did not receive the echo protocol identifier\n");
        ok = 0;
    }
    /* Convert the echo protocol identifier into a Noise protocol identifier */
    if (ok && !convert_to_noise_protocol_id(&nid, &id)) {
        fprintf(stderr, "Unknown echo protocol identifier\n");
        ok = 0;
    }
    /* Create a HandshakeState object to manage the server's handshake */
    if (ok) {
        err = noise_handshakestate_new_by_id
            (&handshake, &nid, NOISE_ROLE_RESPONDER);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("create handshake", err);
            ok = 0;
        }
    }
    if (ok) {
        if (!initialize_handshake(handshake, &nid, &id, sizeof(id))) {
            ok = 0;
        }
    }

    /* Start the handshake */
    if (ok) {
        err = noise_handshakestate_start(handshake);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("start handshake", err);
            ok = 0;
        }
    }
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

    printf("[✓] Server started and listening on %d", port);
    /* Process all incoming data packets and echo them back to the client */
    while (ok) {
        /* Read the next message, including the two byte length prefix */
        message_size = recv_packet(fd, message, sizeof(message));
        if (!message_size)
            break;

        /* Decrypt the message */
        noise_buffer_set_inout
            (mbuf, message + 2, message_size - 2, sizeof(message) - 2);
        err = noise_cipherstate_decrypt(recv_cipher, &mbuf);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("read", err);
            ok = 0;
            break;
        }

        /* Re-encrypt it with the sending cipher and send back to the client */
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
    }

    /* Clean up and exit */
    noise_cipherstate_free(send_cipher);
    noise_cipherstate_free(recv_cipher);
    close_socket(fd);

    return 1;
}
