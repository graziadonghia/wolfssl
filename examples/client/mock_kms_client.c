#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/aes.h>

#define A8_KMS_IP "2001:660:3207:400::2" 
#define SLAVE_SAE_ID "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
#define KMS_SECRET "ClientSecretIoTKey384BitQuantumSafe1234567890123"
#define COAP_PORT 5683

byte current_k_wrap[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                           0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};
byte current_k_hmac[32] = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
                           0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40};

uint64_t get_time_usec() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
}

int build_coap_req(uint8_t *buf, int method, uint16_t msg_id, const char *path, const char *payload) {
    buf[0] = 0x40; buf[1] = method; buf[2] = (msg_id >> 8) & 0xFF; buf[3] = msg_id & 0xFF;
    int len = 4, path_len = strlen(path);
    if (path_len < 13) { buf[len++] = (11 << 4) | path_len; } 
    else { buf[len++] = (11 << 4) | 13; buf[len++] = path_len - 13; }
    memcpy(&buf[len], path, path_len); len += path_len;
    if (payload != NULL) { buf[len++] = 0xFF; memcpy(&buf[len], payload, strlen(payload)); len += strlen(payload); }
    return len;
}

int main(int argc, char **argv) {
    int hash_type = WC_HASH_TYPE_SHA3_384;
    int digest_size = WC_SHA3_384_DIGEST_SIZE;
    const char *algo_name = "SHA3-384";

    if (argc > 1 && strcmp(argv[1], "512") == 0) {
        hash_type = WC_HASH_TYPE_SHA3_512;
        digest_size = WC_SHA3_512_DIGEST_SIZE;
        algo_name = "SHA3-512";
    }

    printf("\nStarting AEAD Ratchet Benchmark A8 Client (%s - 100 runs)...\n", algo_name);
    wolfCrypt_Init();

    struct sockaddr_in6 remote;
    memset(&remote, 0, sizeof(remote));
    remote.sin6_family = AF_INET6; remote.sin6_port = htons(COAP_PORT);
    inet_pton(AF_INET6, A8_KMS_IP, &remote.sin6_addr);

    uint8_t coap_buf[1024]; Hmac hmac; uint16_t msg_id = 1000;

    if (1) {
        printf("\nrun_id,algo_name,t_start_us,t_auth_start_us,t_auth_end_us,t_extract_start_us,t_extract_end_us,t_ack_start_us,t_ack_end_us,auth_lat_ms,gcm_decrypt_ms,ack_rtt_ms,total_ms\n");
    }

    for (int i = 0; i < 100; i++) {
        uint64_t t_start = get_time_usec();
        uint64_t t_auth_start = 0, t_auth_end = 0;
        uint64_t t_extract_start = 0, t_extract_end = 0;
        uint64_t t_ack_start = 0, t_ack_end = 0;

        int sock; ssize_t res = -1;

        if ((sock = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) continue;
        struct timeval tv = {2, 0}; setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        /* --- PHASE 2: Request TLS Key --- */
        t_auth_start = get_time_usec();
        const char *json_body = "{\"number\": 1, \"size\": 256}";
        byte mac_tag[64]; char hex_mac[129]; 
        
        wc_HmacSetKey(&hmac, hash_type, current_k_hmac, 32);
        wc_HmacUpdate(&hmac, (const byte*)json_body, strlen(json_body));
        wc_HmacFinal(&hmac, mac_tag);
        for (int j = 0; j < digest_size; j++) sprintf(&hex_mac[j * 2], "%02x", mac_tag[j]);

        char payload[512]; 
        sprintf(payload, "{\"alg\":\"%s\",\"auth\":\"%s\",\"body\":%s}", algo_name, hex_mac, json_body);
        int pkt_len = build_coap_req(coap_buf, 2, msg_id++, "api/v1/keys/slave/enc_keys", payload);

        sendto(sock, coap_buf, pkt_len, 0, (struct sockaddr *)&remote, sizeof(remote));
        socklen_t addr_len = sizeof(remote);
        res = recvfrom(sock, coap_buf, sizeof(coap_buf), 0, (struct sockaddr *)&remote, &addr_len);
        
        if (res <= 0) { close(sock); continue; }

        uint8_t *ct_payload = NULL; int ct_len = 0;
        for (int k = 4; k < res; k++) {
            if (coap_buf[k] == 0xFF) { ct_payload = &coap_buf[k + 1]; ct_len = res - (k + 1); break; }
        }
        t_auth_end = get_time_usec();

        /* --- PHASE 3: AES-GCM Decryption & State Ratchet --- */
        t_extract_start = get_time_usec();
        int dec_res = -1;
        
        if (ct_len == 124) { 
            byte *iv = ct_payload; byte *ct = ct_payload + 12; byte *tag = ct_payload + 108; byte pt[96];

            Aes aes; wc_AesInit(&aes, NULL, INVALID_DEVID);
            wc_AesGcmSetKey(&aes, current_k_wrap, 32);
            dec_res = wc_AesGcmDecrypt(&aes, pt, ct, 96, iv, 12, tag, 16, NULL, 0);

            if (dec_res == 0) {
                memcpy(current_k_wrap, pt, 32);
                memcpy(current_k_hmac, pt + 32, 32);
            }
        }
        t_extract_end = get_time_usec(); 

        /* --- PHASE 4: Synchronization ACK --- */
        if (dec_res == 0) {
            t_ack_start = get_time_usec();
            const char *ack_body = "{\"status\": \"ACK_SUCCESS\"}";
            wc_HmacSetKey(&hmac, hash_type, current_k_hmac, 32); 
            wc_HmacUpdate(&hmac, (const byte*)ack_body, strlen(ack_body));
            wc_HmacFinal(&hmac, mac_tag);
            for (int j = 0; j < digest_size; j++) sprintf(&hex_mac[j * 2], "%02x", mac_tag[j]);

            sprintf(payload, "{\"alg\":\"%s\",\"auth\":\"%s\",\"body\":%s}", algo_name, hex_mac, ack_body);
            pkt_len = build_coap_req(coap_buf, 2, msg_id++, "api/v1/keys/slave/ack", payload);

            sendto(sock, coap_buf, pkt_len, 0, (struct sockaddr *)&remote, sizeof(remote));
            res = recvfrom(sock, coap_buf, sizeof(coap_buf), 0, (struct sockaddr *)&remote, &addr_len);
            t_ack_end = get_time_usec();
        }
        close(sock);

        uint64_t t_final = (t_ack_end > 0) ? t_ack_end : get_time_usec();

        /* --- METRICS --- */
        float auth_ms = (t_auth_end > t_auth_start) ? (t_auth_end - t_auth_start) / 1000.0f : 0.0f;
        float extract_ms = (t_extract_end > t_extract_start) ? (t_extract_end - t_extract_start) / 1000.0f : 0.0f;
        float ack_ms = (t_ack_end > t_ack_start) ? (t_ack_end - t_ack_start) / 1000.0f : 0.0f;
        float total_ms = (t_final > t_start) ? (t_final - t_start) / 1000.0f : 0.0f;

        printf("%d,%s,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%.3f,%.3f,%.3f,%.3f\n", 
               i + 1, 
               algo_name,
               (unsigned long long)t_start, 
               (unsigned long long)t_auth_start, 
               (unsigned long long)t_auth_end, 
               (unsigned long long)t_extract_start, 
               (unsigned long long)t_extract_end, 
               (unsigned long long)t_ack_start, 
               (unsigned long long)t_ack_end, 
               auth_ms, extract_ms, ack_ms, total_ms);
        
        usleep(100000); 
    }
    return 0;
}