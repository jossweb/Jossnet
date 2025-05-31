/*
 * Modified and adapted for the Jossnet project
 * © 2025 FIGUEIRAS Jossua – Licensed under the MIT License.
 *
 */

#include <stdio.h>
#include "server/server.h"
#include "client/client.h"
#include <pthread.h>

void* client_thread(void* arg) {
    client();
    return NULL;
}

void* server_thread(void* arg) {
    printf("[*] server is starting ...\n");
    server();  // ta fonction server
    printf("[*] server is started\n");
    return NULL;
}

int main() {
    printf("Test!\n");

    pthread_t t_client, t_server;

    printf("[*] Server starting ...\n");
    if (pthread_create(&t_server, NULL, server_thread, NULL) != 0) {
        perror("Erreur lors de la création du thread serveur");
        return 1;
    }

    printf("[*] Client starting ...\n");
    if (pthread_create(&t_client, NULL, client_thread, NULL) != 0) {
        perror("Erreur lors de la création du thread client");
        return 1;
    }

    pthread_join(t_client, NULL);
    pthread_join(t_server, NULL);

    return 0;
}