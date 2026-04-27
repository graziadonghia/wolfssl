#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>

#define PORT 5683

/* --- Dynamic Hash Configuration --- */
int g_hash_type = WC_HASH_TYPE_SHA3_384;
int g_digest_size = WC_SHA3_384_DIGEST_SIZE;

/* State N (Active) */
byte current_k_wrap[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                           0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};
byte current_k_hmac[32] = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
                           0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40};

/* State N+1 (Pending - waiting for ACK) */
byte pending_k_wrap[32];
byte pending_k_hmac[32];
int waiting_for_ack = 0;

WC_RNG rng;

double get_timestamp() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + (tv.tv_usec / 1000000.0);
}

void handle_coap_request(int server_sock, struct sockaddr_in6 *client_addr, socklen_t addr_len, uint8_t *buffer, int len) {
    if (len < 4) return;
    uint8_t tkl = buffer[0] & 0x0F; 
    uint8_t resp_pkt[1024];
    int resp_len = 0;

    resp_pkt[0] = (1 << 6) | (2 << 4) | tkl; 
    resp_pkt[1] = 0x44; /* 2.04 Changed (Default Success) */                     
    resp_pkt[2] = buffer[2];                
    resp_pkt[3] = buffer[3];
    resp_len = 4;

    if (tkl > 0 && len >= 4 + tkl) {
        memcpy(&resp_pkt[resp_len], &buffer[4], tkl);
        resp_len += tkl;
    }
    resp_pkt[resp_len++] = 0xFF;

    char *payload = NULL;
    for (int i = 4 + tkl; i < len; i++) {
        if (buffer[i] == 0xFF) { payload = (char *)&buffer[i + 1]; break; }
    }

    if (strstr((char*)buffer, "enc_keys")) {
        /* --- PHASE 2: Key Request (Auth with current_k_hmac) --- */
        printf("Received Key Request - authenticating...\n");
        char *auth_tag = strstr(payload, "\"auth\":\"");
        if (auth_tag) {
            auth_tag += 8; 
            Hmac hmac;
            byte mac_tag[64];
            char hex_mac[129];
            const char *benchmark_body = "{\"number\": 1, \"size\": 256}";
            
            wc_HmacSetKey(&hmac, g_hash_type, current_k_hmac, 32);
            wc_HmacUpdate(&hmac, (const byte*)benchmark_body, strlen(benchmark_body));
            wc_HmacFinal(&hmac, mac_tag);
            
            for (int j = 0; j < g_digest_size; j++) sprintf(&hex_mac[j * 2], "%02x", mac_tag[j]);

            if (strncmp(auth_tag, hex_mac, g_digest_size * 2) == 0) {
                //printf("Key Request authenticated successfully.\n");
                //printf("Generating new keys for State N+1 and encrypting with State N...\n");
                byte k_tls[32];
                wc_RNG_GenerateBlock(&rng, pending_k_wrap, 32);
                wc_RNG_GenerateBlock(&rng, pending_k_hmac, 32);
                wc_RNG_GenerateBlock(&rng, k_tls, 32);

                byte pt[96];
                memcpy(pt, pending_k_wrap, 32);
                memcpy(pt + 32, pending_k_hmac, 32);
                memcpy(pt + 64, k_tls, 32);

                byte iv[12]; byte ct[96]; byte auth_gcm_tag[16];
                wc_RNG_GenerateBlock(&rng, iv, 12);

                Aes aes;
                wc_AesInit(&aes, NULL, INVALID_DEVID);
                wc_AesGcmSetKey(&aes, current_k_wrap, 32);
                wc_AesGcmEncrypt(&aes, ct, pt, 96, iv, 12, auth_gcm_tag, 16, NULL, 0);

                memcpy(&resp_pkt[resp_len], iv, 12);
                memcpy(&resp_pkt[resp_len + 12], ct, 96);
                memcpy(&resp_pkt[resp_len + 108], auth_gcm_tag, 16);
                resp_len += 124;

                waiting_for_ack = 1; 
                sendto(server_sock, resp_pkt, resp_len, 0, (struct sockaddr *)client_addr, addr_len);
            } else {
                printf("FATAL: Key Request Authentication Failed!\n");
            }
        }
    }
    else if (strstr((char*)buffer, "ack")) {
        /* --- PHASE 4: Verification of ACK (Auth with pending_k_hmac) --- */
        if (waiting_for_ack) {
            //printf("Received ACK - verifying...\n");
            char *auth_tag = strstr(payload, "\"auth\":\"");
            if (auth_tag) {
                auth_tag += 8;
                Hmac hmac; byte mac_tag[64]; char hex_mac[129];
                const char *ack_body = "{\"status\": \"ACK_SUCCESS\"}";
                
                wc_HmacSetKey(&hmac, g_hash_type, pending_k_hmac, 32);
                wc_HmacUpdate(&hmac, (const byte*)ack_body, strlen(ack_body));
                wc_HmacFinal(&hmac, mac_tag);
                
                for (int j = 0; j < g_digest_size; j++) sprintf(&hex_mac[j * 2], "%02x", mac_tag[j]);

                if (strncmp(auth_tag, hex_mac, g_digest_size * 2) == 0) {
                    //printf("ACK verified successfully.\n");
                    //printf("Discarding old keys and committing new keys for State N+1...\n");
                    memcpy(current_k_wrap, pending_k_wrap, 32);
                    memcpy(current_k_hmac, pending_k_hmac, 32);
                    waiting_for_ack = 0;

                    const char *ok = "OK";
                    memcpy(&resp_pkt[resp_len], ok, 2);
                    resp_len += 2;
                    sendto(server_sock, resp_pkt, resp_len, 0, (struct sockaddr *)client_addr, addr_len);
                    printf("Handshake %f: ACK received. State N+1 committed.\n", get_timestamp());
                } else {
                    printf("FATAL: ACK Authentication Failed!\n");
                }
            }
        }
    }
    else {
        /* Fallback: Respond to generic/status requests */
        const char *resp_json = "{\"source_KME_ID\":\"172.20.0.100\",\"key_size\":256}";
        memcpy(&resp_pkt[resp_len], resp_json, strlen(resp_json));
        resp_len += strlen(resp_json);
        sendto(server_sock, resp_pkt, resp_len, 0, (struct sockaddr *)client_addr, addr_len);
    }
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "512") == 0) {
        g_hash_type = WC_HASH_TYPE_SHA3_512;
        g_digest_size = WC_SHA3_512_DIGEST_SIZE;
        //printf("KMS Server configured for SHA3-512\n");
    } else {
        //printf("KMS Server configured for SHA3-384 (Default)\n");
    }

    int server_sock; struct sockaddr_in6 server_addr, client_addr; uint8_t buffer[2048];
    wolfCrypt_Init(); wc_InitRng(&rng);

    server_sock = socket(AF_INET6, SOCK_DGRAM, 0);
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6; server_addr.sin6_addr = in6addr_any; server_addr.sin6_port = htons(PORT);
    bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));

    printf("AEAD KMS (With ACK State Sync) Running on port %d...\n", PORT);
    while (1) {
        socklen_t addr_len = sizeof(client_addr);
        int len = recvfrom(server_sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&client_addr, &addr_len);
        if (len > 0) { buffer[len] = '\0'; handle_coap_request(server_sock, &client_addr, addr_len, buffer, len); }
    }
    return 0;
}