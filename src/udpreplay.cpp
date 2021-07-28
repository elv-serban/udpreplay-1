// © 2020 Erik Rigtorp <erik@rigtorp.se>
// SPDX-License-Identifier: MIT

#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

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
    cfg_t *cfg;
    int fd;
};

/* A 'packet' */
struct pkt_t {
    const u_char *d;
    ssize_t len;
    sockaddr_in addr;
};

pkt_t pktq[1024];

/*
 *
 * Not thread safe (has globals)
 */
static int pkt_send(ctx_t ctx, pkt_t pkt) {

    static int npkts = 0;

    if (DBG >= 1) printf("sendto %s:%hu len=%zd\n",
        inet_ntoa(pkt.addr.sin_addr), ntohs(pkt.addr.sin_port), pkt.len);

    auto n = sendto(ctx.fd, pkt.d, pkt.len, 0, reinterpret_cast<sockaddr *>(&pkt.addr),
                      sizeof(pkt.addr));
    if (n != pkt.len) {
        std::cerr << "sendto: " << strerror(errno) << std::endl;
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
static int pkt_queue(ctx_t ctx, const u_char *d, ssize_t len, sockaddr_in addr) {

    cfg_t *cfg = ctx.cfg;

    int rc;
    struct pkt_t pkt = {d, len, addr};

    static int64_t lossint_count = cfg->loss_int_sec; // packets until next loss
    static int64_t losspkt_count = 0;                 // packets dropped during this loss event
    static int64_t oooint_count = cfg->ooo_int_sec;   // packets until next ooo
    static int64_t ooopkt_count = 0;                  // packets buffered during this ooo event
    static int64_t loss_count = 0;                    // total packets dropped so far
    static int64_t ooo_count = 0;                     // total packets queued for ooo so far

    if (cfg->loss_int_sec) {

        /* Should drop? */
        if (-- lossint_count <= 0) {
            ++ loss_count;
            ++ losspkt_count;

            /* If this is the last packet to drop, restor interval */
            if (losspkt_count >= cfg->loss_pkts) {
                lossint_count = cfg->loss_int_sec;
                losspkt_count = 0;
            }
            printf("Drop - total=%lld\n", loss_count);
            return 0;
        }
    }

    if (cfg->ooo_int_sec) {
        /* Should queue for OOO? */
        if (-- oooint_count <= 0) {
            ++ ooo_count;
            ++ ooopkt_count;

            pktq[ooopkt_count - 1] = pkt;
            printf("OOO queue - total=%lld\n", ooo_count);

            /* If this is the last packet to queue, replay all */
            if (ooopkt_count >= cfg->ooo_pkts) {
                for (int i = ooopkt_count - 1; i >= 0; i --) {
                    printf("OOO replay - %d\n", i);
                    rc = pkt_send(ctx, pktq[i]);
                    if (rc < 0) {
                        return rc;
                    }
                }
                oooint_count = cfg->ooo_int_sec;
                ooopkt_count = 0;
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
parse_impairment(cfg_t *pcfg, char* impairment)
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

    if ((size_t)pcfg->ooo_pkts > sizeof(pktq)/sizeof(pkt_t))
        return -1;

    printf("Impairment: loss %lld/%lld ooo %lld/%lld\n",
        pcfg->loss_int_sec, pcfg->loss_pkts, pcfg->ooo_int_sec, pcfg->ooo_pkts);

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

  cfg_t cfg;
  ctx_t ctx;

  memset(&cfg, 0, sizeof(cfg_t));
  memset(&ctx, 0, sizeof(ctx_t));

  ctx.cfg = &cfg;

  int opt;
  while ((opt = getopt(argc, argv, "i:bls:c:r:t:h:p:m:")) != -1) {
    switch (opt) {
    case 'i':
      ifindex = if_nametoindex(optarg);
      if (ifindex == 0) {
        std::cerr << "if_nametoindex: " << strerror(errno) << std::endl;
        return 1;
      }
      break;
    case 'l':
      loopback = 1;
      break;
    case 's':
      speed = std::stod(optarg);
      if (speed < 0) {
        std::cerr << "speed must be positive" << std::endl;
      }
      break;
    case 'c':
      interval = std::stoi(optarg);
      if (interval < 0) {
        std::cerr << "interval must be non-negative integer" << std::endl;
        return 1;
      }
      break;
    case 'r':
      repeat = std::stoi(optarg);
      if (repeat != -1 && repeat <= 0) {
        std::cerr << "repeat must be positive integer or -1" << std::endl;
        return 1;
      }
      break;
    case 't':
      ttl = std::stoi(optarg);
      if (ttl < 0) {
        std::cerr << "ttl must be non-negative integer" << std::endl;
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
      dst_port = std::stoi(optarg);
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
    std::cerr
        << "udpreplay 1.0.0 © 2020 Erik Rigtorp <erik@rigtorp.se> "
           "https://github.com/rigtorp/udpreplay\n"
           "usage: udpreplay [-i iface] [-l] [-s speed] [-c millisec] [-r "
           "repeat] [-t ttl] [-h host] [-p port]"
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
           "Example: ./udpreplay -m 5000:5:8000:8 -h 127.0.0.1 -p 12000 sample.pcap\n"
        << std::endl;
    return 1;
  }

  if (parse_impairment(&cfg, impairment) < 0) {
      std::cerr << "bad impairment options: " << impairment << std::endl;
      return 1;
  }

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) {
    std::cerr << "socket: " << strerror(errno) << std::endl;
    return 1;
  }

  if (ifindex != 0) {
    ip_mreqn mreqn;
    memset(&mreqn, 0, sizeof(mreqn));
    mreqn.imr_ifindex = ifindex;
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &mreqn, sizeof(mreqn)) ==
        -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  if (loopback != 0) {
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loopback,
                   sizeof(loopback)) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  if (broadcast != 0) {
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &broadcast,
                   sizeof(broadcast)) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  if (ttl != -1) {
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  timespec deadline = {};
  if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1) {
    std::cerr << "clock_gettime: " << strerror(errno) << std::endl;
    return 1;
  }

  ctx.fd = fd;

  for (int i = 0; repeat == -1 || i < repeat; i++) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline_with_tstamp_precision(
        argv[optind], PCAP_TSTAMP_PRECISION_NANO, errbuf);

    if (handle == nullptr) {
      std::cerr << "pcap_open: " << errbuf << std::endl;
      return 1;
    }

    timespec start = {-1, -1};
    timespec pcap_start = {-1, -1};

    pcap_pkthdr header;
    const u_char *p;
    while ((p = pcap_next(handle, &header))) {
      if (start.tv_nsec == -1) {
        if (clock_gettime(CLOCK_MONOTONIC, &start) == -1) {
          std::cerr << "clock_gettime: " << strerror(errno) << std::endl;
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
      auto eth = reinterpret_cast<const ether_header *>(p);

      // jump over and ignore vlan tags
      while (ntohs(eth->ether_type) == ETHERTYPE_VLAN) {
        p += 4;
        eth = reinterpret_cast<const ether_header *>(p);
      }
      if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        continue;
      }
      auto ip = reinterpret_cast<const struct ip *>(p + sizeof(ether_header));
      if (ip->ip_v != 4) {
        continue;
      }
      if (ip->ip_p != IPPROTO_UDP) {
        continue;
      }
      auto udp = reinterpret_cast<const udphdr *>(p + sizeof(ether_header) +
                                                  ip->ip_hl * 4);
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

      timespec now = {};
      if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
        std::cerr << "clock_gettime: " << strerror(errno) << std::endl;
        return 1;
      }

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
                            nullptr) == -1) {
          std::cerr << "clock_nanosleep: " << strerror(errno) << std::endl;
          return 1;
        }
#endif
      }

#ifdef __GLIBC__
      ssize_t len = ntohs(udp->len) - 8;
#else
      ssize_t len = ntohs(udp->uh_ulen) - 8;
#endif
      const u_char *d =
          &p[sizeof(ether_header) + ip->ip_hl * 4 + sizeof(udphdr)];

      sockaddr_in addr;
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
        addr.sin_addr = {ip->ip_dst};
      }

      int err = pkt_queue(ctx, d, len, addr);
      if (err < 0) {
          return 1;
      }
    }

    pcap_close(handle);
  }

  return 0;
}

