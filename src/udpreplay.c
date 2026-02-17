/*
 * Super-simple UDP replay tool from a tcpdump capture file.
 *
 * Initially forked from: https://github.com/rigtorp/udpreplay
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <time.h>
#include <unistd.h>

#define NANOSECONDS_PER_SECOND 1000000000L
#define DBG 0

/* Command line config */
struct cfg_t {
    /* PENDING - not all config is here */
    int64_t loss_int_sec;  // Interval between loss events (sec; 0 means disabled)
    int64_t loss_pkts;     // Drop these many packets during one loss event
    int64_t ooo_int_sec;   // Interval between OOO events (sec; 0 means disabled)
    int64_t ooo_pkts;      // Queue and reorder these many packets during one OOO event
};

/* Running context */
struct ctx_t {
    struct cfg_t *cfg;
    int fd;

    /* Loss and OOO counters */
    int64_t lossint_count; // packets until next loss
    int64_t losspkt_count; // packets dropped during this loss event
    int64_t oooint_count;  // packets until next ooo
    int64_t ooopkt_count;  // packets buffered during this ooo event
    int64_t loss_count;    // total packets dropped so far
    int64_t ooo_count;     // total packets queued for ooo so far
};

/* A 'packet' */
struct pkt_t {
    const u_char *d;
    ssize_t len;
    struct sockaddr_in addr;
};

static struct pkt_t pktq[1024];

/*
 *
 * Not thread safe (has globals)
 */
static int pkt_send(struct ctx_t *ctx, struct pkt_t pkt) {

    static int npkts = 0;

    if (DBG >= 1) printf("sendto %s:%hu len=%zd\n",
        inet_ntoa(pkt.addr.sin_addr), ntohs(pkt.addr.sin_port), pkt.len);

    ssize_t n = sendto(ctx->fd, pkt.d, pkt.len, 0,
                        (struct sockaddr *)&pkt.addr, sizeof(pkt.addr));
    if (n != pkt.len) {
        fprintf(stderr, "sendto: %s\n", strerror(errno));
        return -1;
    }

    if (npkts ++ % 10000 == 0) {
        printf("Sent: %d %s:%hu \n", npkts, inet_ntoa(pkt.addr.sin_addr), ntohs(pkt.addr.sin_port));
    }

    return 0;
}

/*
 *
 * Not thread safe (uses globals)
 */
static int pkt_queue(struct ctx_t *ctx, const u_char *d, ssize_t len, struct sockaddr_in addr) {

    struct cfg_t *cfg = ctx->cfg;

    int rc;
    struct pkt_t pkt = {d, len, addr};

    if (cfg->loss_int_sec) {

        /* Should drop? */
        if (-- ctx->lossint_count <= 0) {
            ++ ctx->loss_count;
            ++ ctx->losspkt_count;

            /* If this is the last packet to drop, restor interval */
            if (ctx->losspkt_count >= cfg->loss_pkts) {
                ctx->lossint_count = ctx->cfg->loss_int_sec;
                ctx->losspkt_count = 0;
            }
            printf("Drop - total=%lld\n", (long long)ctx->loss_count);
            return 0;
        }
    }

    if (cfg->ooo_int_sec) {

        /* Should queue for OOO? */
        if (-- ctx->oooint_count <= 0) {
            ++ ctx->ooo_count;
            ++ ctx->ooopkt_count;

            pktq[ctx->ooopkt_count - 1] = pkt;
            printf("OOO queue - total=%lld\n", (long long)ctx->ooo_count);

            /* If this is the last packet to queue, replay all */
            if (ctx->ooopkt_count >= cfg->ooo_pkts) {
                int i;
                for (i = ctx->ooopkt_count - 1; i >= 0; i --) {
                    printf("OOO replay - %d\n", i);
                    rc = pkt_send(ctx, pktq[i]);
                    if (rc < 0) {
                        return rc;
                    }
                }
                ctx->oooint_count = cfg->ooo_int_sec;
                ctx->ooopkt_count = 0;
            }

            return 0;
        }
    }

    /* Send regular packet */
    rc = pkt_send(ctx, pkt);
    return rc;
}

/*
 * Format - colon separated:  LOSSINT:NLOSS:OOOINT:NOOO
 * - LOSSINT - loss interval (sec; 0 means disabled)
 * - NLOSS - number of packets to drop in one loss event
 * - OOOINT - ooo interval (sec; 0 means disabled)
 * - NOOO - number of packets to reorder in one ooo event
 */
static int
parse_impairment(struct cfg_t *pcfg, char* impairment)
{
    char *ptr;

    if (!impairment)
        return 0;

    ptr = strtok(impairment, ":");
    if (ptr == NULL)
        return -1;
    pcfg->loss_int_sec = atoi(ptr);
    ptr = strtok(NULL, ":");
    if (ptr == NULL)
        return -1;
    pcfg->loss_pkts = atoi(ptr);
    ptr = strtok(NULL, ":");
    if (ptr == NULL)
        return -1;
    pcfg->ooo_int_sec = atoi(ptr);
    ptr = strtok(NULL, ":");
    if (ptr == NULL)
        return -1;
    pcfg->ooo_pkts = atoi(ptr);

    if ((size_t)pcfg->ooo_pkts > sizeof(pktq)/sizeof(struct pkt_t))
        return -1;

    // If both loss and OOO intervals are 0, this is likely not what the user meant
    // (0's could also be integer parsing failures)
    if (pcfg->loss_int_sec == 0 && pcfg->ooo_int_sec == 0) {
        return -1;
    }

    printf("Impairment: loss %lld/%lld ooo %lld/%lld\n",
        (long long)pcfg->loss_int_sec, (long long)pcfg->loss_pkts,
        (long long)pcfg->ooo_int_sec, (long long)pcfg->ooo_pkts);

    return 0;
}

int main(int argc, char *argv[]) {

  int ifindex = 0;
  int loopback = 0;
  double speed = 1;
  int interval = -1;
  int repeat = 1;
  int ttl = -1;
  int broadcast = 0;
  char *dst_addr = NULL;
  short dst_port = 0;
  char *impairment = NULL;

  struct cfg_t cfg;
  struct ctx_t ctx;

  memset(&cfg, 0, sizeof(struct cfg_t));
  memset(&ctx, 0, sizeof(struct ctx_t));

  ctx.cfg = &cfg;

  int opt;
  while ((opt = getopt(argc, argv, "i:bls:c:r:t:h:p:m:")) != -1) {
    switch (opt) {
    case 'i':
      ifindex = if_nametoindex(optarg);
      if (ifindex == 0) {
        fprintf(stderr, "if_nametoindex: %s\n", strerror(errno));
        return 1;
      }
      break;
    case 'l':
      loopback = 1;
      break;
    case 's':
      speed = atof(optarg);
      if (speed < 0) {
        fprintf(stderr, "speed must be positive\n");
      }
      break;
    case 'c':
      interval = atoi(optarg);
      if (interval < 0) {
        fprintf(stderr, "interval must be non-negative integer\n");
        return 1;
      }
      break;
    case 'r':
      repeat = atoi(optarg);
      if (repeat != -1 && repeat <= 0) {
        fprintf(stderr, "repeat must be positive integer or -1\n");
        return 1;
      }
      break;
    case 't':
      ttl = atoi(optarg);
      if (ttl < 0) {
        fprintf(stderr, "ttl must be non-negative integer\n");
        return 1;
      }
      break;
    case 'b':
      broadcast = 1;
      break;
    case 'h':
      dst_addr = strdup(optarg);
      break;
    case 'p':
      dst_port = atoi(optarg);
      break;
    case 'm':
      impairment = strdup(optarg);
      break;
    default:
      goto usage;
    }
  }
  if (optind >= argc) {
  usage:
    fprintf(stderr,
        "Usage: udpreplay [-i iface] [-l] [-s speed] [-c millisec] [-r "
        "repeat] [-t ttl] [-h host] [-p port] "
        "pcap\n"
        "\n"
        "  -i iface    interface to send packets through\n"
        "  -l          enable loopback\n"
        "  -c millisec constant milliseconds between packets\n"
        "  -r repeat   number of times to loop data (-1 for infinite loop)\n"
        "  -s speed    replay speed relative to pcap timestamps (0.5 is double speed)\n"
        "  -t ttl      packet ttl\n"
        "  -b          enable broadcast (SO_BROADCAST)\n"
        "  -h          destination address (optional)\n"
        "  -p          destination port (optional)\n"
        "  -m          impairment (format: LOSS_INT_SEC:N_LOSS:OOO_INT_SEC:N_OOO)\n"
        "\n"
        "Example: ./udpreplay -m 5000:5:8000:8 -h 127.0.0.1 -p 12000 sample.pcap\n");
    return 1;
  }

  if (parse_impairment(&cfg, impairment) < 0) {
      fprintf(stderr, "bad impairment options: %s\n", impairment);
      return 1;
  }

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) {
    fprintf(stderr, "socket: %s\n", strerror(errno));
    return 1;
  }

  if (ifindex != 0) {
    struct ip_mreqn mreqn;
    memset(&mreqn, 0, sizeof(mreqn));
    mreqn.imr_ifindex = ifindex;
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &mreqn, sizeof(mreqn)) ==
        -1) {
      fprintf(stderr, "setsockopt: %s\n", strerror(errno));
      return 1;
    }
  }

  if (loopback != 0) {
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loopback,
                   sizeof(loopback)) == -1) {
      fprintf(stderr, "setsockopt: %s\n", strerror(errno));
      return 1;
    }
  }

  if (broadcast != 0) {
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &broadcast,
                   sizeof(broadcast)) == -1) {
      fprintf(stderr, "setsockopt: %s\n", strerror(errno));
      return 1;
    }
  }

  if (ttl != -1) {
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) == -1) {
      fprintf(stderr, "setsockopt: %s\n", strerror(errno));
      return 1;
    }
  }

  size_t bufsz = 128*1024*1024;
  if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const void *)&bufsz, (socklen_t)sizeof(bufsz)) == -1) {
      fprintf(stderr, "setsockopt: %s\n", strerror(errno));
      return 1;
  }

  struct timespec deadline;
  memset(&deadline, 0, sizeof(deadline));
  if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1) {
    fprintf(stderr, "clock_gettime: %s\n", strerror(errno));
    return 1;
  }

  /* Initialize context */
  ctx.fd = fd;
  ctx.lossint_count = cfg.loss_int_sec;
  ctx.oooint_count = cfg.ooo_int_sec;

  int i;
  for (i = 0; repeat == -1 || i < repeat; i++) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline_with_tstamp_precision(
        argv[optind], PCAP_TSTAMP_PRECISION_NANO, errbuf);

    if (handle == NULL) {
      fprintf(stderr, "pcap_open: %s\n", errbuf);
      return 1;
    }

    struct timespec start = {-1, -1};
    struct timespec pcap_start = {-1, -1};

    struct pcap_pkthdr header;
    const u_char *p;
    while ((p = pcap_next(handle, &header))) {
      if (start.tv_nsec == -1) {
        if (clock_gettime(CLOCK_MONOTONIC, &start) == -1) {
          fprintf(stderr, "clock_gettime: %s\n", strerror(errno));
          return 1;
        }
        pcap_start.tv_sec = header.ts.tv_sec;
        pcap_start.tv_nsec =
            header.ts.tv_usec; // Note PCAP_TSTAMP_PRECISION_NANO
      }

      if (DBG >= 2) printf("packet len=%d ts=%ld.%6ld\n",
          header.len, header.ts.tv_sec, (long)header.ts.tv_usec);

      if (header.len != header.caplen) {
        continue;
      }
      const struct ether_header *eth = (const struct ether_header *)p;

      // jump over and ignore vlan tags
      while (ntohs(eth->ether_type) == ETHERTYPE_VLAN) {
        p += 4;
        eth = (const struct ether_header *)p;
      }
      if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        continue;
      }
      const struct ip *iph = (const struct ip *)(p + sizeof(struct ether_header));
      if (iph->ip_v != 4) {
        continue;
      }
      if (iph->ip_p != IPPROTO_UDP) {
        continue;
      }
      const struct udphdr *udp = (const struct udphdr *)(p + sizeof(struct ether_header) +
                                                  iph->ip_hl * 4);
      if (interval != -1) {
        // Use constant packet rate
        deadline.tv_sec += interval / 1000L;
        deadline.tv_nsec += (interval * 1000000L) % NANOSECONDS_PER_SECOND;
      } else {
        // Next packet deadline = start + (packet ts - first packet ts) * speed
        int64_t delta =
            (header.ts.tv_sec - pcap_start.tv_sec) * NANOSECONDS_PER_SECOND +
            (header.ts.tv_usec -
             pcap_start.tv_nsec); // Note PCAP_TSTAMP_PRECISION_NANO
        if (speed != 1.0) {
          delta *= speed;
        }

        deadline = start;
        deadline.tv_sec += delta / NANOSECONDS_PER_SECOND;
        deadline.tv_nsec += delta % NANOSECONDS_PER_SECOND;
      }

      // Normalize timespec
      if (deadline.tv_nsec > NANOSECONDS_PER_SECOND) {
        deadline.tv_sec++;
        deadline.tv_nsec -= NANOSECONDS_PER_SECOND;
      }

      if (DBG >= 3) printf("send time %lu.%09lu\n", deadline.tv_sec, deadline.tv_nsec);

      struct timespec now;
      memset(&now, 0, sizeof(now));
      if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
        fprintf(stderr, "clock_gettime: %s\n", strerror(errno));
        return 1;
      }

      if (deadline.tv_sec - now.tv_sec > 1)
            fprintf(stderr, "** sleeping %ld sec\n", (long)(deadline.tv_sec - now.tv_sec));

      if (deadline.tv_sec > now.tv_sec ||
          (deadline.tv_sec == now.tv_sec && deadline.tv_nsec > now.tv_nsec)) {

#if __APPLE__
          struct timespec tosleep = {deadline.tv_sec - now.tv_sec, 0};
          if (deadline.tv_nsec < now.tv_nsec) {
              tosleep.tv_sec --;
              tosleep.tv_nsec = NANOSECONDS_PER_SECOND + deadline.tv_nsec - now.tv_nsec;
          } else {
              tosleep.tv_nsec = deadline.tv_nsec - now.tv_nsec;
          }

          if (DBG >= 3) printf("sleep=%ld.%09ld\n", tosleep.tv_sec, tosleep.tv_nsec);
          nanosleep(&tosleep, NULL);
#else
        if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline,
                            NULL) == -1) {
          fprintf(stderr, "clock_nanosleep: %s\n", strerror(errno));
          return 1;
        }
#endif
      }

#ifdef __GLIBC__
      ssize_t len = ntohs(udp->len) - 8;
#else
      ssize_t len = ntohs(udp->uh_ulen) - 8;
#endif
      if (len <= 0)
        fprintf(stderr, "Invalid len: %zd\n", len);

      const u_char *d =
          &p[sizeof(struct ether_header) + iph->ip_hl * 4 + sizeof(struct udphdr)];

      struct sockaddr_in addr;
      memset(&addr, 0, sizeof(addr));
      addr.sin_family = AF_INET;

      if (dst_port) {
        addr.sin_port = htons(dst_port);
      } else {
#ifdef __GLIBC__
        addr.sin_port = udp->dest;
#else
        addr.sin_port = udp->uh_dport;
#endif
      }
      if (dst_addr) {
        inet_pton(AF_INET, dst_addr, &(addr.sin_addr));
      } else {
        addr.sin_addr = iph->ip_dst;
      }

      int err = pkt_queue(&ctx, d, len, addr);
      if (err < 0) {
          return 1;
      }
    }

    pcap_close(handle);
  }

  return 0;
}
