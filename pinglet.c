#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>

// common ports
// TODO should probs not hardcode these and have them in an external txt file
int target_ports[] = {21, 22, 80, 443, 445, 3389, 8080};
#define NUM_PORTS (sizeof(target_ports) / sizeof(target_ports[0]))
#define TIMEOUT_MS 500 // 500 millisecond timeout per port

// Detection method flags
#define DETECT_ARP  1
#define DETECT_ICMP 2
#define DETECT_TCP  3

// ARP/ICMP timeouts per host
#define ARP_TIMEOUT_MS  200
#define ICMP_TIMEOUT_MS 500

// Cached local interface info for ARP/ICMP (populated once in main)
static struct {
    char         if_name[16];
    unsigned int if_index;
    uint8_t      mac_addr[6];
    uint32_t     local_ip;
    int          has_arp;
    int          has_icmp;
} local_iface;

static int arp_sockfd = -1;
static pthread_mutex_t arp_lock = PTHREAD_MUTEX_INITIALIZER;

// Discover local interface info (IP, MAC, interface index)
static int init_local_interface(void) {
    struct ifaddrs *ifaddr, *ifa;
    int ret = -1;
    int fd = -1;

    if (getifaddrs(&ifaddr) == -1)
        return -1;

    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if (ifa->ifa_flags & IFF_LOOPBACK)
            continue;
        if (!(ifa->ifa_flags & IFF_UP))
            continue;

        struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
        local_iface.local_ip = sin->sin_addr.s_addr;
        strncpy(local_iface.if_name, ifa->ifa_name, sizeof(local_iface.if_name) - 1);
        local_iface.if_name[sizeof(local_iface.if_name) - 1] = '\0';
        local_iface.if_index = if_nametoindex(ifa->ifa_name);

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd >= 0) {
            struct ifreq ifr;
            strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
            ifr.ifr_name[IFNAMSIZ - 1] = '\0';
            if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
                memcpy(local_iface.mac_addr, ifr.ifr_hwaddr.sa_data, 6);
                ret = 0;
            }
            close(fd);
        }
        break;
    }

    freeifaddrs(ifaddr);
    return ret;
}

// Send ARP request and check for a reply for a given IP. Returns 1 if found.
static int detect_arp(uint32_t target_ip) {
    if (arp_sockfd < 0) return 0;

    unsigned char buf[sizeof(struct ether_header) + sizeof(struct ether_arp)];
    struct ether_header *eth = (struct ether_header *)buf;
    struct ether_arp *arp = (struct ether_arp *)(buf + sizeof(struct ether_header));
    int found = 0;

    memset(eth->ether_dhost, 0xFF, 6);
    memcpy(eth->ether_shost, local_iface.mac_addr, 6);
    eth->ether_type = htons(ETHERTYPE_ARP);

    arp->arp_hrd = htons(ARPHRD_ETHER);
    arp->arp_pro = htons(ETHERTYPE_IP);
    arp->arp_hln = 6;
    arp->arp_pln = 4;
    arp->arp_op  = htons(ARPOP_REQUEST);
    memcpy(arp->arp_sha, local_iface.mac_addr, 6);
    memcpy(arp->arp_spa, &local_iface.local_ip, 4);
    memset(arp->arp_tha, 0, 6);
    memcpy(arp->arp_tpa, &target_ip, 4);

    struct sockaddr_ll dest;
    memset(&dest, 0, sizeof(dest));
    dest.sll_family   = AF_PACKET;
    dest.sll_ifindex  = local_iface.if_index;
    dest.sll_protocol = htons(ETH_P_ARP);
    dest.sll_halen    = 6;
    memcpy(dest.sll_addr, eth->ether_dhost, 6);

    pthread_mutex_lock(&arp_lock);

    if (sendto(arp_sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        pthread_mutex_unlock(&arp_lock);
        return 0;
    }

    struct timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = ARP_TIMEOUT_MS * 1000;

    unsigned char recv_buf[64];
    while (1) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(arp_sockfd, &fds);

        struct timeval timeout = tv;
        int ret = select(arp_sockfd + 1, &fds, NULL, NULL, &timeout);
        if (ret <= 0) break;

        struct sockaddr_ll sender;
        socklen_t slen = sizeof(sender);
        ssize_t n = recvfrom(arp_sockfd, recv_buf, sizeof(recv_buf), 0,
                             (struct sockaddr *)&sender, &slen);
        if (n < (ssize_t)(sizeof(struct ether_header) + sizeof(struct ether_arp))) continue;

        struct ether_header *re = (struct ether_header *)recv_buf;
        struct ether_arp *ra = (struct ether_arp *)(recv_buf + sizeof(struct ether_header));

        if (re->ether_type != htons(ETHERTYPE_ARP)) continue;
        if (ra->arp_op != htons(ARPOP_REPLY)) continue;

        uint32_t reply_ip;
        memcpy(&reply_ip, ra->arp_spa, 4);
        if (reply_ip == target_ip) {
            found = 1;
            break;
        }
    }

    pthread_mutex_unlock(&arp_lock);
    return found;
}

// Send ICMP echo request and wait for reply. Returns 1 if found.
static int detect_icmp(uint32_t target_ip) {
    // SOCK_DGRAM + IPPROTO_ICMP — kernel handles IP header and checksum.
    // Works as non-root when ping_group_range is set.
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sock < 0) return 0;

    struct timeval tv;
    tv.tv_sec  = ICMP_TIMEOUT_MS / 1000;
    tv.tv_usec = (ICMP_TIMEOUT_MS % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct icmphdr icmp;
    memset(&icmp, 0, sizeof(icmp));
    icmp.type = ICMP_ECHO;
    icmp.code = 0;
    icmp.un.echo.sequence = htons(1);
    // ID is assigned by kernel (SOCK_DGRAM), so match on sequence number instead
    // checksum computed by kernel for SOCK_DGRAM

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = target_ip;

    int found = 0;
    if (sendto(sock, &icmp, sizeof(icmp), 0, (struct sockaddr *)&target, sizeof(target)) > 0) {
        unsigned char recv_buf[512];
        while (1) {
            struct sockaddr_in sender;
            socklen_t slen = sizeof(sender);
            ssize_t n = recvfrom(sock, recv_buf, sizeof(recv_buf), 0,
                                 (struct sockaddr *)&sender, &slen);
            if (n <= 0) break;
            if (sender.sin_addr.s_addr != target_ip) continue;
            if ((size_t)n < sizeof(struct icmphdr)) continue;

            struct icmphdr *ir = (struct icmphdr *)recv_buf;
            if (ir->type == ICMP_ECHOREPLY && ir->un.echo.sequence == icmp.un.echo.sequence) {
                found = 1;
                break;
            }
        }
    }

    close(sock);
    return found;
}

// Structure to pass data to threads
typedef struct {
    char ip_address[16];
} ThreadArgs;

// check specific port on ip w/ timeout
int scan_port(const char *ip, int port) {
    int sockfd;
    struct sockaddr_in target;
    fd_set fdset;
    struct timeval tv;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return 0;

    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target.sin_addr);

    // set socket non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    int res = connect(sockfd, (struct sockaddr *)&target, sizeof(target));

    if (res < 0 && errno != EINPROGRESS) {
        close(sockfd);
        return 0;
    }

    if (res == 0) {
        // connect asap
        close(sockfd);
        return 1;
    }

    // wait on connection via select()
    FD_ZERO(&fdset);
    FD_SET(sockfd, &fdset);
    tv.tv_sec = 0;
    tv.tv_usec = TIMEOUT_MS * 1000;

    res = select(sockfd + 1, NULL, &fdset, NULL, &tv);

    if (res == 1) {
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0) {
            close(sockfd);
            return 1; // port open
        }
    }

    close(sockfd);
    return 0; // port closed/timeout
}

// resolve hostnames via reverse DNS
void resolve_hostname(const char *ip, char *hostname_buf, size_t buf_size) {
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &sa.sin_addr);

    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), hostname_buf, buf_size, NULL, 0, NI_NAMEREQD) != 0) {
        strncpy(hostname_buf, "N/A", buf_size);
    }
}

// thread routine, scans a single IP address
void *scan_ip(void *arguments) {
    ThreadArgs *args = (ThreadArgs *)arguments;
    char hostname[256];
    int detection_method = 0;
    int open_ports[NUM_PORTS];
    int open_count = 0;

    struct in_addr ip_bin;
    inet_pton(AF_INET, args->ip_address, &ip_bin);

    // 1. Try ARP (fastest, local subnet only)
    if (local_iface.has_arp && detect_arp(ip_bin.s_addr))
        detection_method = DETECT_ARP;

    // 2. Try ICMP (if ARP didn't find it)
    if (!detection_method && local_iface.has_icmp && detect_icmp(ip_bin.s_addr))
        detection_method = DETECT_ICMP;

    // 3. TCP port scan runs for hosts found by any method
    for (size_t i = 0; i < NUM_PORTS; i++) {
        if (scan_port(args->ip_address, target_ports[i]))
            open_ports[open_count++] = target_ports[i];
    }
    if (!detection_method && open_count > 0)
        detection_method = DETECT_TCP;

    // Report host if detected by any method
    if (detection_method > 0) {
        resolve_hostname(args->ip_address, hostname, sizeof(hostname));

        const char *method = detection_method == DETECT_ARP  ? "ARP"  :
                             detection_method == DETECT_ICMP ? "ICMP" : "TCP";

        printf("[+] Host Active: %-15s | Hostname: %-25s | Method: %-4s",
               args->ip_address, hostname, method);
        if (open_count > 0) {
            printf(" | Ports: ");
            for (int i = 0; i < open_count; i++)
                printf("%d ", open_ports[i]);
        }
        printf("\n");
    }

    free(args);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <base_ip_subnet>\n", argv[0]);
        printf("Example: %s 192.168.1\n", argv[0]);
        return 1;
    }

    char *base_ip = argv[1];
    pthread_t threads[254];

    // Discover local interface for ARP/ICMP
    if (init_local_interface() == 0) {
        arp_sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (arp_sockfd >= 0) {
            local_iface.has_arp = 1;
            // Bind to interface to avoid capturing ARP from other interfaces
            struct sockaddr_ll sll;
            memset(&sll, 0, sizeof(sll));
            sll.sll_family  = AF_PACKET;
            sll.sll_ifindex = local_iface.if_index;
            sll.sll_protocol = htons(ETH_P_ARP);
            bind(arp_sockfd, (struct sockaddr *)&sll, sizeof(sll));
        }

        // SOCK_DGRAM + IPPROTO_ICMP is available to non-root via ping_group_range
        int test_icmp = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        if (test_icmp >= 0) {
            close(test_icmp);
            local_iface.has_icmp = 1;
        }
    }

    if (!local_iface.has_arp)
        fprintf(stderr, "[!] ARP scan unavailable (need root / CAP_NET_RAW).\n");
    if (!local_iface.has_icmp)
        fprintf(stderr, "[!] ICMP ping unavailable (need root or ping_group_range).\n");

    printf("Starting scan on %s.0/24...\n", base_ip);
    printf("--------------------------------------------------------------------------------\n");

    // init 254 threads to scan .1 through .254 concurrently
    for (int i = 1; i <= 254; i++) {
        ThreadArgs *args = malloc(sizeof(ThreadArgs));
        snprintf(args->ip_address, sizeof(args->ip_address), "%s.%d", base_ip, i);

        if (pthread_create(&threads[i-1], NULL, scan_ip, (void *)args) != 0) {
            perror("Failed to create thread");
        }
    }

    // wait on all threads to finish
    for (int i = 0; i < 254; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("--------------------------------------------------------------------------------\n");
    printf("Scan complete.\n");

    if (arp_sockfd >= 0)
        close(arp_sockfd);

    return 0;
}
