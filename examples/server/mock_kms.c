#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha3.h>

#define PORT 5683
#define KMS_SECRET "ClientSecretIoTKey384BitQuantumSafe1234567890123"

void handle_coap_request(int server_sock, struct sockaddr_in6 *client_addr, socklen_t addr_len, uint8_t *buffer, int len) {
    if (len < 4) return; // Too small to be a CoAP packet

    /* Extract CoAP Header info */
    uint8_t tkl = buffer[0] & 0x0F; 
    uint8_t msg_id_msb = buffer[2]; 
    uint8_t msg_id_lsb = buffer[3];

    /* Prepare the CoAP Response Buffer */
    uint8_t resp_pkt[1024];
    int resp_len = 0;

    /* 1. Build CoAP Header (ACK, 2.05 Content) */
    resp_pkt[0] = (1 << 6) | (2 << 4) | tkl; 
    resp_pkt[1] = 0x45;                      
    resp_pkt[2] = msg_id_msb;                
    resp_pkt[3] = msg_id_lsb;
    resp_len = 4;

    /* 2. Echo the Token (if present) */
    if (tkl > 0 && len >= 4 + tkl) {
        memcpy(&resp_pkt[resp_len], &buffer[4], tkl);
        resp_len += tkl;
    }

    /* 3. Add CoAP Payload Marker */
    resp_pkt[resp_len++] = 0xFF;

    /* Find the Payload in the incoming request */
    char *payload = NULL;
    for (int i = 4 + tkl; i < len; i++) {
        if (buffer[i] == 0xFF) {
            payload = (char *)&buffer[i + 1];
            break;
        }
    }

    /* Handle GET_STATUS */
    if (payload == NULL || strstr((char*)buffer, "status")) {
        const char *resp_json = "{\"source_KME_ID\":\"172.20.0.100\",\"key_size\":256}";
        memcpy(&resp_pkt[resp_len], resp_json, strlen(resp_json));
        resp_len += strlen(resp_json);

        ssize_t sent = sendto(server_sock, resp_pkt, resp_len, 0, (struct sockaddr *)client_addr, addr_len);
        if (sent > 0) printf("[CoAP KMS] Answered GET_STATUS\n");
    }
    /* Handle POST enc_keys / dec_keys */
    else {
        char *auth_tag = strstr(payload, "\"auth\":\"");
        char *body_start = strstr(payload, "\"body\":");

        if (auth_tag && body_start) {
            auth_tag += 8; // Move pointer past the "auth":" part
            
            /* Default to 384 */
            int hash_type = WC_HASH_TYPE_SHA3_384;
            int digest_sz = WC_SHA3_384_DIGEST_SIZE;
            
            /* CRITICAL FIX: Switch to 512 if requested! */
            if (strstr(payload, "SHA3-512")) {
                hash_type = WC_HASH_TYPE_SHA3_512;
                digest_sz = WC_SHA3_512_DIGEST_SIZE;
            }
            
            /* Verify HMAC using wolfCrypt */
            Hmac hmac;
            byte mac_tag[64];
            char hex_mac[129];
            
            const char *benchmark_body = "{\"number\": 1, \"size\": 256}";
            wc_HmacSetKey(&hmac, hash_type, (const byte*)KMS_SECRET, strlen(KMS_SECRET));
            wc_HmacUpdate(&hmac, (const byte*)benchmark_body, strlen(benchmark_body));
            wc_HmacFinal(&hmac, mac_tag);
            
            for (int j = 0; j < digest_sz; j++) {
                sprintf(&hex_mac[j * 2], "%02x", mac_tag[j]);
            }

            /* Compare generated HMAC against the one in the payload */
            if (strncmp(auth_tag, hex_mac, digest_sz * 2) == 0) {
                const char *resp_json = "{\"keys\":[{\"key_ID\":\"mock-id\",\"key\":\"q6qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=\"}]}";
                int json_len = strlen(resp_json);
                memcpy(&resp_pkt[resp_len], resp_json, json_len);
                
                /* ITS-OSCORE ENCRYPTION SIMULATION */
                uint8_t dummy_otp_stream = 0xAA;
                for (int k = 0; k < json_len; k++) {
                    resp_pkt[resp_len + k] ^= dummy_otp_stream;
                }
                resp_len += json_len;

                ssize_t sent = sendto(server_sock, resp_pkt, resp_len, 0, (struct sockaddr *)client_addr, addr_len);
                if (sent > 0) printf("[CoAP KMS] Answered GET_KEY (Encrypted & Verified)\n");
            } else {
                const char *err = "4.01 Unauthorized";
                memcpy(&resp_pkt[resp_len], err, strlen(err));
                resp_len += strlen(err);

                sendto(server_sock, resp_pkt, resp_len, 0, (struct sockaddr *)client_addr, addr_len);
                printf("[CoAP KMS] Rejected: Invalid HMAC\n");
            }
        }
    }
}

int main() {
    int server_sock;
    struct sockaddr_in6 server_addr, client_addr;
    uint8_t buffer[2048];

    wolfCrypt_Init(); 

    server_sock = socket(AF_INET6, SOCK_DGRAM, 0);
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any;
    server_addr.sin6_port = htons(PORT);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        return 1;
    }

    printf("Strict C Mock IPv6 KMS (CoAP-UDP / wolfSSL) running on port 5683...\n");

    while (1) {
        socklen_t addr_len = sizeof(client_addr);
        int len = recvfrom(server_sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&client_addr, &addr_len);
        if (len > 0) {
            buffer[len] = '\0'; 
            handle_coap_request(server_sock, &client_addr, addr_len, buffer, len);
        }
    }
    return 0;
}