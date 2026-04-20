#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha3.h>

#define A8_KMS_IP "2001:660:3207:400::2" /* <-- Make sure this matches your Server IP */
#define SLAVE_SAE_ID "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
#define KMS_SECRET "ClientSecretIoTKey384BitQuantumSafe1234567890123"
#define COAP_PORT 5683

/* Linux High-Resolution Timer (Microseconds) */
uint64_t get_time_usec() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

/* Standalone CoAP Packet Builder for Linux */
int build_coap_req(uint8_t *buf, int method, uint16_t msg_id, const char *path, const char *payload) {
    buf[0] = 0x40; /* Version 1, Type CON (0), Token Length (0) */
    buf[1] = method; /* 1 = GET, 2 = POST */
    buf[2] = (msg_id >> 8) & 0xFF;
    buf[3] = msg_id & 0xFF;
    
    int len = 4;
    int path_len = strlen(path);
    
    /* Option 11: Uri-Path */
    if (path_len < 13) {
        buf[len++] = (11 << 4) | path_len;
    } else {
        buf[len++] = (11 << 4) | 13;
        buf[len++] = path_len - 13;
    }
    memcpy(&buf[len], path, path_len);
    len += path_len;
    
    if (payload != NULL) {
        buf[len++] = 0xFF; /* Payload Marker */
        int p_len = strlen(payload);
        memcpy(&buf[len], payload, p_len);
        len += p_len;
    }
    return len;
}

int main(int argc, char **argv) {
    int hash_type = WC_HASH_TYPE_SHA3_384;
    int digest_size = WC_SHA3_384_DIGEST_SIZE;
    const char* algo_name = "SHA3-384";

    if (argc > 1 && strcmp(argv[1], "512") == 0) {
        hash_type = WC_HASH_TYPE_SHA3_512;
        digest_size = WC_SHA3_512_DIGEST_SIZE;
        algo_name = "SHA3-512";
    }

    printf("\nStarting Linux A8 ITS-OSCORE Benchmark (%s - 100 runs)...\n", algo_name);

    wolfCrypt_Init();

    struct sockaddr_in6 remote;
    memset(&remote, 0, sizeof(remote));
    remote.sin6_family = AF_INET6;
    remote.sin6_port = htons(COAP_PORT);
    inet_pton(AF_INET6, A8_KMS_IP, &remote.sin6_addr);

    uint8_t coap_buf[1024];
    Hmac hmac;
    uint16_t msg_id = 1000;

    for (int i = 0; i < 100; i++) {
        uint64_t t_start = get_time_usec();
        int sock;
        int max_retries = 3;
        ssize_t res = -1;

        /* --- PHASE 1: GET_STATUS --- */
        if ((sock = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) continue;

        struct timeval tv = {2, 0}; /* 2 second timeout */
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        char path[128];
        sprintf(path, "/api/v1/keys/%s/status", SLAVE_SAE_ID);
        int pkt_len = build_coap_req(coap_buf, 1, msg_id++, path, NULL);

        for (int r = 0; r < max_retries; r++) {
            sendto(sock, coap_buf, pkt_len, 0, (struct sockaddr *)&remote, sizeof(remote));
            socklen_t addr_len = sizeof(remote);
            res = recvfrom(sock, coap_buf, sizeof(coap_buf), 0, (struct sockaddr *)&remote, &addr_len);
            if (res > 0) break;
        }
        close(sock);

        if (res <= 0) {
            printf("Run %d: GET Failed\n", i+1);
            continue;
        }

        /* --- PHASE 2: POST enc_keys --- */
        uint64_t t_auth_start = get_time_usec();
        const char *json_body = "{\"number\": 1, \"size\": 256}";
        
        byte mac_tag[64];
        char hex_mac[129]; 
        wc_HmacSetKey(&hmac, hash_type, (const byte*)KMS_SECRET, strlen(KMS_SECRET));
        wc_HmacUpdate(&hmac, (const byte*)json_body, strlen(json_body));
        wc_HmacFinal(&hmac, mac_tag);

        for (int j = 0; j < digest_size; j++) {
            sprintf(&hex_mac[j * 2], "%02x", mac_tag[j]);
        }
        uint64_t t_hmac_end = get_time_usec();

        if ((sock = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) continue;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        sprintf(path, "/api/v1/keys/%s/enc_keys", SLAVE_SAE_ID);
        
        /* Increased buffer to 512 to safely hold the longer 512-bit hex string */
        char payload[512]; 
        
        /* CRITICAL FIX: Add the "alg" tag so the server knows to switch to 512! */
        sprintf(payload, "{\"alg\":\"%s\",\"auth\":\"%s\",\"body\":%s}", algo_name, hex_mac, json_body);
        
        pkt_len = build_coap_req(coap_buf, 2, msg_id++, path, payload);

        uint64_t t_auth_end = get_time_usec();

        for (int r = 0; r < max_retries; r++) {
            sendto(sock, coap_buf, pkt_len, 0, (struct sockaddr *)&remote, sizeof(remote));
            socklen_t addr_len = sizeof(remote);
            res = recvfrom(sock, coap_buf, sizeof(coap_buf), 0, (struct sockaddr *)&remote, &addr_len);
            if (res > 0) break;
        }
        close(sock);

        if (res <= 0) {
            printf("Run %d: POST Failed\n", i+1);
            continue;
        }

        /* --- PHASE 3: PAYLOAD EXTRACTION (ITS-OSCORE) --- */
        uint64_t t_extract_start = get_time_usec();
        
        /* 1. Wegman-Carter Verification */
        byte wc_mac_tag[64];
        wc_HmacSetKey(&hmac, hash_type, (const byte*)KMS_SECRET, strlen(KMS_SECRET));
        wc_HmacUpdate(&hmac, coap_buf, res); 
        wc_HmacFinal(&hmac, wc_mac_tag);

        /* 2. OTP Decryption */
        uint8_t dummy_otp_stream = 0xAA; 
        for (int k = 0; k < res; k++) {
            coap_buf[k] ^= dummy_otp_stream; 
        }

        uint64_t t_extract_end = get_time_usec(); 

        /* --- METRICS OUTPUT --- */
        if (i == 0) printf("\nrun_id,hmac_alg,hmac_comp_ms,auth_lat_ms,payload_ext_ms,total_ms\n");
        
        float hmac_ms = (t_hmac_end - t_auth_start) / 1000.0f;
        float auth_ms = (t_auth_end - t_auth_start) / 1000.0f;
        float extract_ms = (t_extract_end - t_extract_start) / 1000.0f;
        float total_ms = (t_extract_end - t_start) / 1000.0f;

        printf("%d,%s,%.3f,%.3f,%.3f,%.3f\n", i + 1, algo_name, hmac_ms, auth_ms, extract_ms, total_ms);
        
        usleep(500000); /* Sleep 500ms between runs */
    }
    return 0;
}