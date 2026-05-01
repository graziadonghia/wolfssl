#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <signal.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>

#define PORT 5683

int last_seen_seq = 0;
double pending_timestamp = 0.0;
#define PENDING_STATE_TTL 5.0 /* seconds */
/* --- Dynamic Configuration --- */
int g_hash_type = WC_HASH_TYPE_SHA3_384;
int g_digest_size = WC_SHA3_384_DIGEST_SIZE;
const char *g_algo_name = "SHA3-384";
char g_client_type[16] = "unknown";
int g_target_runs = 1000;

/* --- Benchmarking Metrics --- */
int total_requests = 0;
int completed_acks = 0;
int recovered_acks = 0;
char recovery_history[8192] = ""; 

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

void save_metrics_and_exit(int sig) {
    printf("\n\n======================================================\n");
    if (sig == 0) {
        printf(">>> Target of %d runs reached! Saving Benchmark Metrics...\n", g_target_runs);
    } else {
        printf(">>> Caught Signal (Ctrl+C). Saving Benchmark Metrics early...\n");
    }
    
    FILE *f = fopen("kms_recovery_metrics.csv", "a");
    if (f) {
        fseek(f, 0, SEEK_END);
        if (ftell(f) == 0) {
            fprintf(f, "client_type,algo,target_runs,total_completed,recovered_acks,recovery_percentage,recovery_rounds_history\n");
        }
        
        int total_runs = completed_acks + recovered_acks;
        float pct = 0.0f;
        if (total_runs > 0) pct = ((float)recovered_acks / total_runs) * 100.0f;
        
        fprintf(f, "%s,%s,%d,%d,%d,%.2f%%,%s\n", 
                g_client_type, g_algo_name, g_target_runs, total_runs, recovered_acks, pct, recovery_history);
        fclose(f);
        
        printf(">>> Saved to 'kms_recovery_metrics.csv'\n");
        printf(">>> Total Completed: %d | Recovered: %d (%.2f%%)\n", total_runs, recovered_acks, pct);
    } else {
        printf(">>> ERROR: Could not open 'kms_recovery_metrics.csv' for writing.\n");
    }
    printf("======================================================\n\n");
    exit(0);
}

void handle_sigint(int sig) {
    save_metrics_and_exit(sig);
}

void handle_coap_request(int server_sock, struct sockaddr_in6 *client_addr, socklen_t addr_len, uint8_t *buffer, int len) {
    if (len < 4) return;
    uint8_t tkl = buffer[0] & 0x0F; 
    uint8_t resp_pkt[1024];
    int resp_len = 0;

    resp_pkt[0] = (1 << 6) | (2 << 4) | tkl; 
    resp_pkt[1] = 0x44; 
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

    if (waiting_for_ack && (get_timestamp() - pending_timestamp) > PENDING_STATE_TTL) {
        printf(">>> SECURITY: Pending state expired due to TTL! Dropping State N+1 to prevent exhaustion.\n");
        waiting_for_ack = 0;
    }

    int incoming_seq = -1;
    if (payload != NULL) {
        char *seq_ptr = strstr(payload, "\"seq\":");
        if (seq_ptr) {
            incoming_seq = atoi(seq_ptr + 6);
        }
    }

    if (payload != NULL && strstr((char*)buffer, "enc_keys")) {
        char *auth_tag = strstr(payload, "\"auth\":\"");
        if (auth_tag) {
            auth_tag += 8; 
            
            char *body_start = strstr(payload, "\"body\":{");
            char benchmark_body[256] = {0};
            if (body_start) {
                char *body_end = strchr(body_start + 7, '}');
                if (body_end) strncpy(benchmark_body, body_start + 7, (body_end - body_start) - 6);
            }
            
            Hmac hmac = {0};
            byte mac_tag[64]; char hex_mac[129];
            
            wc_HmacInit(&hmac, NULL, INVALID_DEVID);
            wc_HmacSetKey(&hmac, g_hash_type, current_k_hmac, 32);
            wc_HmacUpdate(&hmac, (const byte*)benchmark_body, strlen(benchmark_body));
            wc_HmacFinal(&hmac, mac_tag);
            wc_HmacFree(&hmac);
            for (int j = 0; j < g_digest_size; j++) sprintf(&hex_mac[j * 2], "%02x", mac_tag[j]);

            int auth_success = 0;

            if (strncmp(auth_tag, hex_mac, g_digest_size * 2) == 0) {
                auth_success = 1;
            } 
            else if (waiting_for_ack) {
                wc_HmacInit(&hmac, NULL, INVALID_DEVID);
                wc_HmacSetKey(&hmac, g_hash_type, pending_k_hmac, 32);
                wc_HmacUpdate(&hmac, (const byte*)benchmark_body, strlen(benchmark_body));
                wc_HmacFinal(&hmac, mac_tag);
                wc_HmacFree(&hmac);
                for (int j = 0; j < g_digest_size; j++) sprintf(&hex_mac[j * 2], "%02x", mac_tag[j]);
                
                if (strncmp(auth_tag, hex_mac, g_digest_size * 2) == 0) {
                    printf(">>> RECOVERY: Lost ACK detected! Committing keys...\n");
                    memcpy(current_k_wrap, pending_k_wrap, 32);
                    memcpy(current_k_hmac, pending_k_hmac, 32);
                    waiting_for_ack = 0;
                    recovered_acks++;
                    auth_success = 1;
                }
            }

            if (auth_success) {
                /* SECURITY FIX: Drop only if strictly older than the last seen sequence */
                /* If it's equal, it means the client is retrying its current request */
                if (incoming_seq < last_seen_seq) {
                    printf(">>> SECURITY: Replay attack detected (Seq %d < %d)! Dropping packet.\n", incoming_seq, last_seen_seq);
                } else {
                    last_seen_seq = incoming_seq;
                    total_requests++;
                    
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

                    Aes aes = {0};
                    wc_AesInit(&aes, NULL, INVALID_DEVID);
                    wc_AesGcmSetKey(&aes, current_k_wrap, 32);
                    wc_AesGcmEncrypt(&aes, ct, pt, 96, iv, 12, auth_gcm_tag, 16, NULL, 0);
                    wc_AesFree(&aes);

                    memcpy(&resp_pkt[resp_len], iv, 12);
                    memcpy(&resp_pkt[resp_len + 12], ct, 96);
                    memcpy(&resp_pkt[resp_len + 108], auth_gcm_tag, 16);
                    resp_len += 124;

                    waiting_for_ack = 1; 
                    pending_timestamp = get_timestamp(); 
                    sendto(server_sock, resp_pkt, resp_len, 0, (struct sockaddr *)client_addr, addr_len);
                }
            } else {
                printf("FATAL: Key Request Authentication Failed!\n");
            }
        }
    }
    else if (payload != NULL && strstr((char*)buffer, "ack")) {
        if (waiting_for_ack) {
            char *auth_tag = strstr(payload, "\"auth\":\"");
            if (auth_tag) {
                auth_tag += 8;
                
                char *body_start = strstr(payload, "\"body\":{");
                char ack_body[256] = {0};
                if (body_start) {
                    char *body_end = strchr(body_start + 7, '}');
                    if (body_end) strncpy(ack_body, body_start + 7, (body_end - body_start) - 6);
                }

                Hmac hmac = {0}; 
                byte mac_tag[64]; char hex_mac[129];
                
                wc_HmacInit(&hmac, NULL, INVALID_DEVID);
                wc_HmacSetKey(&hmac, g_hash_type, pending_k_hmac, 32);
                wc_HmacUpdate(&hmac, (const byte*)ack_body, strlen(ack_body));
                wc_HmacFinal(&hmac, mac_tag);
                wc_HmacFree(&hmac);
                
                for (int j = 0; j < g_digest_size; j++) sprintf(&hex_mac[j * 2], "%02x", mac_tag[j]);

                if (strncmp(auth_tag, hex_mac, g_digest_size * 2) == 0) {
                    if (incoming_seq < last_seen_seq) {
                         printf(">>> SECURITY: Replay attack detected on ACK (Seq %d < %d)! Dropping packet.\n", incoming_seq, last_seen_seq);
                    } else {
                        last_seen_seq = incoming_seq;
                        memcpy(current_k_wrap, pending_k_wrap, 32);
                        memcpy(current_k_hmac, pending_k_hmac, 32);
                        waiting_for_ack = 0;
                        completed_acks++;

                        const char *ok = "OK";
                        memcpy(&resp_pkt[resp_len], ok, 2);
                        resp_len += 2;
                        sendto(server_sock, resp_pkt, resp_len, 0, (struct sockaddr *)client_addr, addr_len);
                        
                        if ((completed_acks + recovered_acks) >= g_target_runs) {
                            save_metrics_and_exit(0);
                        }
                    }
                } else {
                    printf("ACK verification FAILED!\n");
                }
            }
        }
    }
    else {
        const char *resp_json = "{\"source_KME_ID\":\"172.20.0.100\",\"key_size\":256}";
        memcpy(&resp_pkt[resp_len], resp_json, strlen(resp_json));
        resp_len += strlen(resp_json);
        sendto(server_sock, resp_pkt, resp_len, 0, (struct sockaddr *)client_addr, addr_len);
    }
}

int main(int argc, char **argv) {
    signal(SIGINT, handle_sigint);

    if (argc > 1 && strcmp(argv[1], "512") == 0) {
        g_hash_type = WC_HASH_TYPE_SHA3_512;
        g_digest_size = WC_SHA3_512_DIGEST_SIZE;
        g_algo_name = "SHA3-512";
    }
    
    if (argc > 2) {
        strncpy(g_client_type, argv[2], sizeof(g_client_type) - 1);
    }
    
    if (argc > 3) {
        g_target_runs = atoi(argv[3]);
        if (g_target_runs <= 0) g_target_runs = 1000;
    }

    printf("======================================================\n");
    printf("KMS Server Configured:\n");
    printf("Algorithm: %s\n", g_algo_name);
    printf("Client Type: %s\n", g_client_type);
    printf("Target Runs: %d\n", g_target_runs);
    printf("Port: %d\n", PORT);
    printf("======================================================\n\n");

    int server_sock; struct sockaddr_in6 server_addr, client_addr; uint8_t buffer[2048];
    wolfCrypt_Init(); wc_InitRng(&rng);

    server_sock = socket(AF_INET6, SOCK_DGRAM, 0);
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6; server_addr.sin6_addr = in6addr_any; server_addr.sin6_port = htons(PORT);
    bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));

    struct timeval tv;
    tv.tv_sec = 5;  
    tv.tv_usec = 0;
    setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (1) {
        socklen_t addr_len = sizeof(client_addr);
        int len = recvfrom(server_sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&client_addr, &addr_len);
        
        if (len < 0) {
            int total_runs = completed_acks + recovered_acks;
            if (total_runs > 0) {
                printf("\n>>> Network idle for 5 seconds. Assuming client has finished early!\n");
                save_metrics_and_exit(0);
            }
            continue;
        }

        if (len > 0) { 
            buffer[len] = '\0'; 
            handle_coap_request(server_sock, &client_addr, addr_len, buffer, len); 
        }
    }
    return 0;
}