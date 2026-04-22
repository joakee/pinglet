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

// common ports
// TODO should probs not hardcode these and have them in an external txt file
int target_ports[] = {21, 22, 80, 443, 445, 3389, 8080};
#define NUM_PORTS (sizeof(target_ports) / sizeof(target_ports[0]))
#define TIMEOUT_MS 500 // 500 millisecond timeout per port

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

// thread routine, scans a single IP addres
void *scan_ip(void *arguments) {
    ThreadArgs *args = (ThreadArgs *)arguments;
    char hostname[256];
    int open_ports[NUM_PORTS];
    int open_count = 0;

    // scan specified ports
    for (int i = 0; i < NUM_PORTS; i++) {
        if (scan_port(args->ip_address, target_ports[i])) {
            open_ports[open_count++] = target_ports[i];
        }
    }

    // if open ports found --> host active --> resolve hostname --> print
    if (open_count > 0) {
        resolve_hostname(args->ip_address, hostname, sizeof(hostname));

        printf("[+] Host Active: %-15s | Hostname: %-25s | Ports: ", args->ip_address, hostname);
        for (int i = 0; i < open_count; i++) {
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

    printf("Starting fast LAN scan on %s.0/24...\n", base_ip);
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

    return 0;
}
