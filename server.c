/*
 * Reliable Group Notification System - UDP Server
 * Project #18: Reliable UDP with ACK, Retransmission, Timeout
 *
 * Features:
 *  - Custom packet format with sequence numbers
 *  - Group membership management
 *  - Loss detection and retransmission
 *  - Performance comparison with best-effort UDP
 *
 * Build: gcc -o server server.c -lpthread -lm
 * Run:   ./server [port]  (default: 9000)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
/* ─────────────────────────── CONSTANTS ─────────────────────────── */
#define DEFAULT_PORT        9000
#define MAX_GROUPS          32
#define MAX_SUBSCRIBERS     64
#define MAX_PAYLOAD         1024
#define WINDOW_SIZE         8          /* sliding window */
#define MAX_RETRIES         5
#define TIMEOUT_MS          300        /* retransmit timeout (ms) */
#define HEARTBEAT_INTERVAL  10         /* seconds */
#define MAX_PENDING_ACKS    256

/* ─────────────────────────── PACKET FORMAT ─────────────────────── */
#define MAGIC               0xA5B3

typedef enum {
    PKT_NOTIFY   = 0x01,   /* notification payload          */
    PKT_ACK      = 0x02,   /* acknowledgement               */
    PKT_JOIN     = 0x03,   /* subscribe to group            */
    PKT_LEAVE    = 0x04,   /* unsubscribe from group        */
    PKT_HEARTBEAT= 0x05,   /* keepalive                     */
    PKT_NACK     = 0x06,   /* negative ACK (request resend) */
    PKT_BESTEFF  = 0x07,   /* best-effort (no ACK needed)   */
    PKT_STATS    = 0x08,   /* statistics request/response   */
} PktType;

#pragma pack(push, 1)
typedef struct {
    uint16_t magic;        /* 0xA5B3                         */
    uint8_t  type;         /* PktType                        */
    uint8_t  flags;        /* 0x01=reliable, 0x02=last_frag  */
    uint32_t seq_num;      /* sequence number                */
    uint32_t ack_num;      /* ack number (in ACK packets)    */
    uint16_t group_id;     /* target group                   */
    uint16_t payload_len;  /* bytes of payload               */
    uint32_t checksum;     /* simple CRC32                   */
    char     payload[MAX_PAYLOAD];
} Packet;
#pragma pack(pop)

#define HEADER_SIZE  (sizeof(Packet) - MAX_PAYLOAD)

/* ─────────────────────────── DATA STRUCTURES ───────────────────── */
typedef struct {
    struct sockaddr_in addr;
    char   client_id[64];
    time_t last_seen;
    int    active;
    uint32_t pkts_sent;
    uint32_t pkts_acked;
    uint32_t pkts_lost;
} Subscriber;

typedef struct {
    uint16_t    group_id;
    char        name[64];
    Subscriber  members[MAX_SUBSCRIBERS];
    int         member_count;
    pthread_mutex_t lock;
} Group;

typedef struct {
    Packet   pkt;
    size_t   pkt_len;
    struct sockaddr_in dest;
    int      retries;
    time_t   last_sent_ms;  /* milliseconds */
    int      acked;
} PendingAck;

#define MAX_TP_SAMPLES 3600   /* up to 1 hour of 1-second samples */
typedef struct {
    /* reliable stats */
    uint64_t total_sent;
    uint64_t total_acked;
    uint64_t total_retransmit;
    uint64_t total_lost;
    double   avg_latency_ms;
    /* best-effort stats */
    uint64_t be_sent;
    uint64_t be_dropped;   /* simulated drop for comparison */
    /* throughput samples (1 per second, filled by tp_thread) */
    uint32_t rel_tp_samples[MAX_TP_SAMPLES];
    uint32_t be_tp_samples[MAX_TP_SAMPLES];
    int      tp_count;
    /* per-second counters (reset each tick) */
    uint32_t rel_tick;
    uint32_t be_tick;
} Stats;

/* ─────────────────────────── GLOBALS ───────────────────────────── */
static int        g_sockfd;
static Group      g_groups[MAX_GROUPS];
static int        g_group_count = 0;
static PendingAck g_pending[MAX_PENDING_ACKS];
static Stats      g_stats;
static pthread_mutex_t g_pending_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_stats_lock   = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_running = 1;
static long long    g_start_ms;        /* server start time (monotonic ms) */

/* ─────────────────────────── CRC32 ─────────────────────────────── */
static uint32_t crc32_table[256];

static void crc32_init(void) {
    for (int i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
}

static uint32_t crc32(const void *buf, size_t len) {
    const uint8_t *p = buf;
    uint32_t c = 0xFFFFFFFF;
    while (len--) c = crc32_table[(c ^ *p++) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFF;
}

static uint32_t packet_checksum(Packet *pkt) {
    uint32_t saved = pkt->checksum;
    pkt->checksum = 0;
    uint32_t cs = crc32(pkt, HEADER_SIZE + ntohs(pkt->payload_len));
    pkt->checksum = saved;
    return cs;
}

/* ─────────────────────────── TIME HELPERS ──────────────────────── */
static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

/* ─────────────────────────── GROUP MANAGEMENT ──────────────────── */
static Group *find_group(uint16_t id) {
    for (int i = 0; i < g_group_count; i++)
        if (g_groups[i].group_id == id) return &g_groups[i];
    return NULL;
}

static Group *find_or_create_group(uint16_t id, const char *name) {
    Group *g = find_group(id);
    if (g) return g;
    if (g_group_count >= MAX_GROUPS) return NULL;
    g = &g_groups[g_group_count++];
    memset(g, 0, sizeof(*g));
    g->group_id = id;
    snprintf(g->name, sizeof(g->name), "%s", name ? name : "unnamed");
    pthread_mutex_init(&g->lock, NULL);
    printf("[GROUP] Created group %d (\"%s\")\n", id, g->name);
    return g;
}

static int group_add_member(Group *g, struct sockaddr_in *addr, const char *cid) {
    pthread_mutex_lock(&g->lock);
    /* check if already member */
    for (int i = 0; i < g->member_count; i++) {
        if (g->members[i].addr.sin_addr.s_addr == addr->sin_addr.s_addr &&
            g->members[i].addr.sin_port        == addr->sin_port) {
            g->members[i].last_seen = time(NULL);
            g->members[i].active    = 1;
            pthread_mutex_unlock(&g->lock);
            return 0; /* already exists */
        }
    }
    if (g->member_count >= MAX_SUBSCRIBERS) {
        pthread_mutex_unlock(&g->lock);
        return -1;
    }
    Subscriber *s = &g->members[g->member_count++];
    memset(s, 0, sizeof(*s));
    s->addr      = *addr;
    s->last_seen = time(NULL);
    s->active    = 1;
    snprintf(s->client_id, sizeof(s->client_id), "%s", cid ? cid : "unknown");
    pthread_mutex_unlock(&g->lock);
    printf("[GROUP] %s joined group %d (\"%s\")  [%d members]\n",
           s->client_id, g->group_id, g->name, g->member_count);
    return 1;
}

static void group_remove_member(Group *g, struct sockaddr_in *addr) {
    pthread_mutex_lock(&g->lock);
    for (int i = 0; i < g->member_count; i++) {
        if (g->members[i].addr.sin_addr.s_addr == addr->sin_addr.s_addr &&
            g->members[i].addr.sin_port        == addr->sin_port) {
            printf("[GROUP] %s left group %d\n", g->members[i].client_id, g->group_id);
            /* shift */
            memmove(&g->members[i], &g->members[i+1],
                    (g->member_count - i - 1) * sizeof(Subscriber));
            g->member_count--;
            break;
        }
    }
    pthread_mutex_unlock(&g->lock);
}

/* ─────────────────────────── SEND WITH RELIABILITY ─────────────── */
static uint32_t g_seq = 1;

static int send_packet(int sock, Packet *pkt, size_t plen,
                       struct sockaddr_in *dest, int reliable) {
    pkt->checksum = htonl(packet_checksum(pkt));
    ssize_t r = sendto(sock, pkt, plen, 0, (struct sockaddr*)dest, sizeof(*dest));
    if (r < 0) {
        perror("sendto");
        return -1;
    }

    if (reliable && (pkt->flags & 0x01)) {
        pthread_mutex_lock(&g_pending_lock);
        for (int i = 0; i < MAX_PENDING_ACKS; i++) {
            if (!g_pending[i].retries && !g_pending[i].acked) continue;
            if (g_pending[i].acked) {
                /* reuse slot */
                memcpy(&g_pending[i].pkt, pkt, plen);
                g_pending[i].pkt_len     = plen;
                g_pending[i].dest        = *dest;
                g_pending[i].retries     = 0;
                g_pending[i].last_sent_ms= now_ms();
                g_pending[i].acked       = 0;
                pthread_mutex_unlock(&g_pending_lock);
                return 0;
            }
        }
        /* find empty slot */
        for (int i = 0; i < MAX_PENDING_ACKS; i++) {
            if (g_pending[i].acked || g_pending[i].retries == 0) {
                memcpy(&g_pending[i].pkt, pkt, plen);
                g_pending[i].pkt_len     = plen;
                g_pending[i].dest        = *dest;
                g_pending[i].retries     = 0;
                g_pending[i].last_sent_ms= now_ms();
                g_pending[i].acked       = 0;
                break;
            }
        }
        pthread_mutex_unlock(&g_pending_lock);
    }

    pthread_mutex_lock(&g_stats_lock);
    g_stats.total_sent++;
    g_stats.rel_tick++;
    pthread_mutex_unlock(&g_stats_lock);
    return 0;
}

/* ─────────────────────────── NOTIFY GROUP ──────────────────────── */
static void notify_group(uint16_t group_id, const char *message,
                         int reliable_mode) {
    Group *g = find_group(group_id);
    if (!g) {
        printf("[WARN] No such group %d\n", group_id);
        return;
    }

    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.magic       = htons(MAGIC);
    pkt.type        = reliable_mode ? PKT_NOTIFY : PKT_BESTEFF;
    pkt.flags       = reliable_mode ? 0x01 : 0x00;
    pkt.seq_num     = htonl(g_seq++);
    pkt.group_id    = htons(group_id);
    uint16_t mlen   = (uint16_t)strlen(message);
    if (mlen > MAX_PAYLOAD - 1) mlen = MAX_PAYLOAD - 1;
    pkt.payload_len = htons(mlen);
    memcpy(pkt.payload, message, mlen);
    size_t plen = HEADER_SIZE + mlen;

    pthread_mutex_lock(&g->lock);
    int n = g->member_count;
    Subscriber members_copy[MAX_SUBSCRIBERS];
    memcpy(members_copy, g->members, n * sizeof(Subscriber));
    pthread_mutex_unlock(&g->lock);

    printf("[NOTIFY] Group %d (\"%s\") → %d members | %s | msg=\"%.*s\"\n",
           group_id, g->name, n,
           reliable_mode ? "RELIABLE" : "BEST-EFFORT",
           (int)mlen, message);

    for (int i = 0; i < n; i++) {
        if (!members_copy[i].active) continue;
        Packet p = pkt;
        send_packet(g_sockfd, &p, plen, &members_copy[i].addr, reliable_mode);

        /* simulate 20% loss for best-effort comparison */
        if (!reliable_mode && (rand() % 5) == 0) {
            pthread_mutex_lock(&g_stats_lock);
            g_stats.be_dropped++;
            pthread_mutex_unlock(&g_stats_lock);
            printf("[BE-LOSS] Simulated drop to %s\n", members_copy[i].client_id);
        }
        if (!reliable_mode) {
            pthread_mutex_lock(&g_stats_lock);
            g_stats.be_sent++;
            g_stats.be_tick++;
            pthread_mutex_unlock(&g_stats_lock);
        }
    }
}

/* ─────────────────────────── ACK HANDLING ──────────────────────── */
static void handle_ack(uint32_t seq, struct sockaddr_in *from) {
    pthread_mutex_lock(&g_pending_lock);
    for (int i = 0; i < MAX_PENDING_ACKS; i++) {
        if (!g_pending[i].acked &&
            ntohl(g_pending[i].pkt.seq_num) == seq) {
            long long lat = now_ms() - g_pending[i].last_sent_ms;
            g_pending[i].acked = 1;
            pthread_mutex_lock(&g_stats_lock);
            g_stats.total_acked++;
            /* running average */
            double a = g_stats.avg_latency_ms;
            uint64_t n = g_stats.total_acked;
            g_stats.avg_latency_ms = a + (lat - a) / n;
            pthread_mutex_unlock(&g_stats_lock);
            printf("[ACK] seq=%u  latency=%lldms  retries=%d\n",
                   seq, lat, g_pending[i].retries);
            break;
        }
    }
    pthread_mutex_unlock(&g_pending_lock);
}

/* ─────────────────────────── RETRANSMIT THREAD ─────────────────── */
static void *retransmit_thread(void *arg) {
    (void)arg;
    printf("[THREAD] Retransmit monitor started\n");
    while (g_running) {
        usleep(50000); /* check every 50ms */
        long long now = now_ms();
        pthread_mutex_lock(&g_pending_lock);
        for (int i = 0; i < MAX_PENDING_ACKS; i++) {
            PendingAck *pa = &g_pending[i];
            if (pa->acked) continue;
            if (pa->pkt.magic == 0) continue;
            if (now - pa->last_sent_ms < TIMEOUT_MS) continue;

            if (pa->retries >= MAX_RETRIES) {
                printf("[LOST] seq=%u  gave up after %d retries\n",
                       ntohl(pa->pkt.seq_num), pa->retries);
                pa->acked = 1; /* mark done */
                pthread_mutex_lock(&g_stats_lock);
                g_stats.total_lost++;
                pthread_mutex_unlock(&g_stats_lock);
                continue;
            }

            pa->retries++;
            pa->last_sent_ms = now;
            printf("[RETX] seq=%u  attempt=%d\n",
                   ntohl(pa->pkt.seq_num), pa->retries);
            sendto(g_sockfd, &pa->pkt, pa->pkt_len, 0, (struct sockaddr*)&pa->dest, sizeof(pa->dest));
            pthread_mutex_lock(&g_stats_lock);
            g_stats.total_retransmit++;
            pthread_mutex_unlock(&g_stats_lock);
        }
        pthread_mutex_unlock(&g_pending_lock);
    }
    return NULL;
}

/* ─────────────────────────── HEARTBEAT THREAD ──────────────────── */
static void *heartbeat_thread(void *arg) {
    (void)arg;
    printf("[THREAD] Heartbeat thread started (%ds interval)\n", HEARTBEAT_INTERVAL);
    while (g_running) {
        sleep(HEARTBEAT_INTERVAL);
        time_t now = time(NULL);
        for (int gi = 0; gi < g_group_count; gi++) {
            Group *g = &g_groups[gi];
            pthread_mutex_lock(&g->lock);
            for (int i = 0; i < g->member_count; i++) {
                Subscriber *s = &g->members[i];
                if (!s->active) continue;
                if (now - s->last_seen > HEARTBEAT_INTERVAL * 3) {
                    printf("[TIMEOUT] %s timed out from group %d — removing\n",
                           s->client_id, g->group_id);
                    /* remove member by shifting array */
                    memmove(&g->members[i], &g->members[i+1],
                            (g->member_count - i - 1) * sizeof(Subscriber));
                    g->member_count--;
                    i--; /* recheck this index */
                    continue;
                }
                /* send heartbeat */
                Packet hb;
                memset(&hb, 0, sizeof(hb));
                hb.magic    = htons(MAGIC);
                hb.type     = PKT_HEARTBEAT;
                hb.seq_num  = htonl(g_seq++);
                hb.group_id = htons(g->group_id);
                size_t hlen = HEADER_SIZE;
                hb.checksum = htonl(packet_checksum(&hb));
                sendto(g_sockfd, &hb, hlen, 0, (struct sockaddr*)&s->addr, sizeof(s->addr));
            }
            pthread_mutex_unlock(&g->lock);
        }
    }
    return NULL;
}

/* ─────────────────────────── THROUGHPUT SAMPLER ────────────────── */
static void *tp_thread(void *arg) {
    (void)arg;
    printf("[THREAD] Throughput sampler started (1s interval)\n");
    while (g_running) {
        sleep(1);
        pthread_mutex_lock(&g_stats_lock);
        if (g_stats.tp_count < MAX_TP_SAMPLES) {
            g_stats.rel_tp_samples[g_stats.tp_count] = g_stats.rel_tick;
            g_stats.be_tp_samples[g_stats.tp_count]  = g_stats.be_tick;
            g_stats.tp_count++;
        }
        g_stats.rel_tick = 0;
        g_stats.be_tick  = 0;
        pthread_mutex_unlock(&g_stats_lock);
    }
    return NULL;
}

/* ─────────────────────────── STATS PRINT ───────────────────────── */
static void print_stats(void) {
    pthread_mutex_lock(&g_stats_lock);
    long long elapsed_ms = now_ms() - g_start_ms;
    double elapsed_s = elapsed_ms / 1000.0;
    /* compute avg throughput from per-second samples */
    double rel_avg_tp = 0.0, be_avg_tp = 0.0;
    if (g_stats.tp_count > 0) {
        uint64_t rel_sum = 0, be_sum = 0;
        for (int i = 0; i < g_stats.tp_count; i++) {
            rel_sum += g_stats.rel_tp_samples[i];
            be_sum  += g_stats.be_tp_samples[i];
        }
        rel_avg_tp = (double)rel_sum / g_stats.tp_count;
        be_avg_tp  = (double)be_sum  / g_stats.tp_count;
    }
    printf("\n┌─────────────────────────────────────────────────────┐\n");
    printf("│           PERFORMANCE STATISTICS                   │\n");
    printf("├─────────────────────────────────────────────────────┤\n");
    printf("│  RELIABLE UDP:                                      │\n");
    printf("│    Total Sent       : %8llu                      │\n", g_stats.total_sent);
    printf("│    Total ACKed      : %8llu  (%.1f%%)           │\n",
           g_stats.total_acked,
           g_stats.total_sent ? 100.0 * g_stats.total_acked / g_stats.total_sent : 0.0);
    printf("│    Retransmissions  : %8llu                      │\n", g_stats.total_retransmit);
    printf("│    Lost (gave up)   : %8llu                      │\n", g_stats.total_lost);
    printf("│    Avg Latency      : %8.2f ms                  │\n", g_stats.avg_latency_ms);
    printf("│    Avg Throughput   : %8.1f msg/s (sampled/s)   │\n", rel_avg_tp);
    printf("├─────────────────────────────────────────────────────┤\n");
    printf("│  BEST-EFFORT UDP (simulated 20%% drop):             │\n");
    printf("│    Total Sent       : %8llu                      │\n", g_stats.be_sent);
    printf("│    Simulated Drops  : %8llu  (%.1f%%)           │\n",
           g_stats.be_dropped,
           g_stats.be_sent ? 100.0 * g_stats.be_dropped / g_stats.be_sent : 0.0);
    printf("│    Effective Deliv  : %8llu                      │\n",
           g_stats.be_sent - g_stats.be_dropped);
    printf("│    Avg Throughput   : %8.1f msg/s (sampled/s)   │\n", be_avg_tp);
    printf("├─────────────────────────────────────────────────────┤\n");
    printf("│    Elapsed          : %8.1f s                   │\n", elapsed_s);
    printf("│    Samples taken    : %8d                       │\n", g_stats.tp_count);
    printf("└─────────────────────────────────────────────────────┘\n\n");
    pthread_mutex_unlock(&g_stats_lock);
}

/* ─────────────────────────── MAIN RECEIVE LOOP ─────────────────── */
static void handle_packet(Packet *pkt, size_t len,
                          struct sockaddr_in *from) {
    /* validate magic */
    if (ntohs(pkt->magic) != MAGIC) return;

    /* validate checksum */
    uint32_t recv_cs = ntohl(pkt->checksum);
    uint32_t calc_cs = packet_checksum(pkt);
    if (recv_cs != calc_cs) {
        printf("[WARN] Bad checksum from %s:%d\n",
               inet_ntoa(from->sin_addr), ntohs(from->sin_port));
        return;
    }

    uint32_t seq      = ntohl(pkt->seq_num);
    uint16_t group_id = ntohs(pkt->group_id);
    uint16_t plen     = ntohs(pkt->payload_len);

    switch (pkt->type) {
    case PKT_NOTIFY:
    case PKT_BESTEFF: {
        /* Publisher sent a notification — forward to all group members */
        int reliable = (pkt->type == PKT_NOTIFY);
        char msg[MAX_PAYLOAD+1] = {0};
        if (plen > 0) memcpy(msg, pkt->payload, plen < MAX_PAYLOAD ? plen : MAX_PAYLOAD);
        printf("[PUBLISH] group=%d  reliable=%d  msg=\"%s\"\n", group_id, reliable, msg);
        notify_group(group_id, msg, reliable);
        /* ACK back to publisher */
        Packet ack;
        memset(&ack, 0, sizeof(ack));
        ack.magic    = htons(MAGIC);
        ack.type     = PKT_ACK;
        ack.seq_num  = htonl(g_seq++);
        ack.ack_num  = htonl(seq);
        ack.group_id = pkt->group_id;
        ack.checksum = htonl(packet_checksum(&ack));
        sendto(g_sockfd, &ack, HEADER_SIZE, 0, (struct sockaddr*)from, sizeof(*from));
        break;
    }
    case PKT_JOIN: {
        char name[65] = {0};
        if (plen > 0) memcpy(name, pkt->payload, plen < 64 ? plen : 64);
        char cid[64];
        snprintf(cid, sizeof(cid), "%s:%d", inet_ntoa(from->sin_addr), ntohs(from->sin_port));
        Group *g = find_or_create_group(group_id, name);
        if (g) group_add_member(g, from, cid);
        /* ACK the join */
        Packet ack;
        memset(&ack, 0, sizeof(ack));
        ack.magic   = htons(MAGIC);
        ack.type    = PKT_ACK;
        ack.seq_num = htonl(g_seq++);
        ack.ack_num = htonl(seq);
        ack.group_id= pkt->group_id;
        ack.checksum= htonl(packet_checksum(&ack));
        sendto(g_sockfd, &ack, HEADER_SIZE, 0, (struct sockaddr*)from, sizeof(*from));
        break;
    }
    case PKT_LEAVE: {
        Group *g = find_group(group_id);
        if (g) group_remove_member(g, from);
        break;
    }
    case PKT_ACK: {
        uint32_t ack_seq = ntohl(pkt->ack_num);
        handle_ack(ack_seq, from);
        /* update last_seen */
        Group *g = find_group(group_id);
        if (g) {
            pthread_mutex_lock(&g->lock);
            for (int i = 0; i < g->member_count; i++) {
                if (g->members[i].addr.sin_addr.s_addr == from->sin_addr.s_addr &&
                    g->members[i].addr.sin_port        == from->sin_port) {
                    g->members[i].last_seen = time(NULL);
                    g->members[i].pkts_acked++;
                }
            }
            pthread_mutex_unlock(&g->lock);
        }
        break;
    }
    case PKT_HEARTBEAT: {
        /* update last_seen for any group */
        for (int gi = 0; gi < g_group_count; gi++) {
            Group *g = &g_groups[gi];
            pthread_mutex_lock(&g->lock);
            for (int i = 0; i < g->member_count; i++) {
                if (g->members[i].addr.sin_addr.s_addr == from->sin_addr.s_addr &&
                    g->members[i].addr.sin_port        == from->sin_port) {
                    g->members[i].last_seen = time(NULL);
                }
            }
            pthread_mutex_unlock(&g->lock);
        }
        break;
    }
    case PKT_NACK: {
        uint32_t nack_seq = ntohl(pkt->ack_num);
        printf("[NACK] Client requests resend seq=%u\n", nack_seq);
        pthread_mutex_lock(&g_pending_lock);
        for (int i = 0; i < MAX_PENDING_ACKS; i++) {
            if (!g_pending[i].acked &&
                ntohl(g_pending[i].pkt.seq_num) == nack_seq) {
                g_pending[i].last_sent_ms = 0; /* force immediate retransmit */
                break;
            }
        }
        pthread_mutex_unlock(&g_pending_lock);
        break;
    }
    case PKT_STATS: {
        print_stats();
        break;
    }
    default:
        printf("[WARN] Unknown packet type 0x%02X\n", pkt->type);
    }
}

/* ─────────────────────────── CLI THREAD ────────────────────────── */
static void *cli_thread(void *arg) {
    (void)arg;
    char line[256];
    printf("\nServer CLI ready. Commands:\n");
    printf("  notify <group_id> <message>   - reliable notification\n");
    printf("  bcast  <group_id> <message>   - best-effort notification\n");
    printf("  groups                        - list groups\n");
    printf("  stats                         - show stats\n");
    printf("  quit                          - stop server\n\n");

    while (g_running && fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\n")] = 0;
        if (strncmp(line, "notify ", 7) == 0) {
            char *rest = line + 7;
            int gid = atoi(rest);
            char *msg = strchr(rest, ' ');
            if (msg) notify_group((uint16_t)gid, msg + 1, 1);
        } else if (strncmp(line, "bcast ", 6) == 0) {
            char *rest = line + 6;
            int gid = atoi(rest);
            char *msg = strchr(rest, ' ');
            if (msg) notify_group((uint16_t)gid, msg + 1, 0);
        } else if (strcmp(line, "groups") == 0) {
            for (int i = 0; i < g_group_count; i++) {
                Group *g = &g_groups[i];
                printf("  Group %d \"%s\" — %d members\n",
                       g->group_id, g->name, g->member_count);
                for (int j = 0; j < g->member_count; j++)
                    printf("    [%d] %s  last_seen=%lds ago\n", j,
                           g->members[j].client_id,
                           (long)(time(NULL) - g->members[j].last_seen));
            }
        } else if (strcmp(line, "stats") == 0) {
            print_stats();
        } else if (strcmp(line, "quit") == 0) {
            g_running = 0;
        }
    }
    return NULL;
}

/* ─────────────────────────── MAIN ──────────────────────────────── */
int main(int argc, char *argv[]) {
    int port = (argc > 1) ? atoi(argv[1]) : DEFAULT_PORT;
    srand((unsigned)time(NULL));
    crc32_init();
    g_start_ms = now_ms();
    memset(g_pending, 0, sizeof(g_pending));
    /* mark all as acked (available) */
    for (int i = 0; i < MAX_PENDING_ACKS; i++) g_pending[i].acked = 1;

    /* create UDP socket */
    g_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_sockfd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(g_sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(g_sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    /* Set receive timeout */
    struct timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;
    setsockopt(g_sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family      = AF_INET;
    srv.sin_addr.s_addr = INADDR_ANY;
    srv.sin_port        = htons(port);
    if (bind(g_sockfd, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        perror("bind"); return 1;
    }

    printf("[NET] Bound to 0.0.0.0:%d (all interfaces)\n", port);
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║   Reliable Group Notification Server  (UDP)         ║\n");
    printf("║   Port: %-5d  Window: %d  Timeout: %dms            ║\n",
           port, WINDOW_SIZE, TIMEOUT_MS);
    printf("╚══════════════════════════════════════════════════════╝\n\n");

    /* pre-create a default group */
    find_or_create_group(1, "alerts");
    find_or_create_group(2, "warnings");
    find_or_create_group(3, "info");

    /* start background threads */
    pthread_t rt, ht, ct, tt;
    pthread_create(&rt, NULL, retransmit_thread, NULL);
    pthread_create(&ht, NULL, heartbeat_thread, NULL);
    pthread_create(&ct, NULL, cli_thread, NULL);
    pthread_create(&tt, NULL, tp_thread, NULL);

    /* main receive loop */
    uint8_t raw_buf[sizeof(Packet) + 64];
    struct sockaddr_in from;
    socklen_t fromlen;

    while (g_running) {
        fromlen = sizeof(from);
        ssize_t r = recvfrom(g_sockfd, raw_buf, sizeof(raw_buf), 0,
                             (struct sockaddr *)&from, &fromlen);
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            perror("recvfrom");
            break;
        }
        if (r < (ssize_t)HEADER_SIZE) continue;
        handle_packet((Packet *)raw_buf, (size_t)r, &from);
    }

    g_running = 0;
    close(g_sockfd);
    print_stats();
    printf("[SERVER] Shutdown complete.\n");
    return 0;
}
