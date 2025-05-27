#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>    // IP 標頭結構
#include <arpa/inet.h>     // for inet_ntoa / inet_ntop
#include <errno.h>         // for errno and perror

#define BUFFER_SIZE 65536 // 足夠大的緩衝區來接收整個 IP 封包 (最大 MTU)

// 函式: 重新計算 IP 標頭 checksum
// 這是網路編程中常用的一個簡單的校驗和計算方法
unsigned short calculate_checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
    return (answer);
}

int main() {
    int sock_fd; // 單一 socket 用於接收和發送
    unsigned char buffer[BUFFER_SIZE];
    struct sockaddr_in saddr;
    socklen_t saddr_len = sizeof(saddr);

    // 創建 Raw Socket
    // AF_INET: IPv4 協議
    // SOCK_RAW: Raw Socket
    // IPPROTO_IP: 接收所有 IP 協議的封包。
    //              同時，如果發送時設置 IP_HDRINCL，它也能發送原始 IP 標頭。
    sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (sock_fd < 0) {
        perror("Error creating raw socket");
        return 1;
    }

    // 設置 IP_HDRINCL 選項，表示我們自己構建 IP 標頭
    // 這允許我們在發送時提供完整的 IP 封包，包括 IP 標頭
    int one = 1;
    if (setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("Error setting IP_HDRINCL option");
        close(sock_fd);
        return 1;
    }

    printf("Raw Socket (packet filter/forwarder) started.\n");
    printf("Monitoring and processing packets...\n");

    while (1) {
        // 接收封包
        ssize_t packet_len = recvfrom(sock_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&saddr, &saddr_len);
        if (packet_len < 0) {
            if (errno == EINTR) { // 被訊號中斷，通常可以重試
                continue;
            }
            perror("Error receiving packet");
            close(sock_fd);
            return 1;
        }

        // 檢查封包是否足夠包含 IP 標頭
        if (packet_len < sizeof(struct iphdr)) {
            // fprintf(stderr, "Received packet too short for IP header (%zd bytes).\n", packet_len);
            continue; // 忽略過短的封包
        }

        // 將緩衝區解析為 IP 標頭結構
        struct iphdr *iph = (struct iphdr *)buffer;

        char src_ip_str[INET_ADDRSTRLEN];
        char dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(iph->saddr), src_ip_str, sizeof(src_ip_str));
        inet_ntop(AF_INET, &(iph->daddr), dst_ip_str, sizeof(dst_ip_str));

        printf("Received packet: %s -> %s (Proto: %d, Len: %zd)\n",
               src_ip_str, dst_ip_str, iph->protocol, packet_len);

        // ==== 過濾邏輯 ====

        // 規則 1: 阻擋所有從 192.168.2.3 到 192.168.2.1 的封包
        if (strcmp(src_ip_str, "192.168.2.3") == 0 && strcmp(dst_ip_str, "192.168.2.1") == 0) {
            printf("  ACTION: BLOCK. Packet from %s to %s dropped by filter.\n\n", src_ip_str, dst_ip_str);
            continue; // 丟棄此封包，不進行任何轉發
        }

        // 規則 2: 允許所有從 192.168.2.4 到 192.168.2.1 的封包
        if (strcmp(src_ip_str, "192.168.2.4") == 0 && strcmp(dst_ip_str, "192.168.2.1") == 0) {
            printf("  ACTION: ALLOW. Packet from %s to %s will be forwarded.\n", src_ip_str, dst_ip_str);
            // 進入轉發流程
        }
        // else 規則：所有不被明確阻擋的封包，都將被轉發
        else {
            printf("  ACTION: DEFAULT. Packet from %s to %s will be forwarded.\n", src_ip_str, dst_ip_str);
        }

        // ==== 轉發邏輯 (對於被允許或默認轉發的封包) ====

        // 減少 TTL (Time To Live)
        // 每次路由器轉發封包，TTL 應減 1。如果 TTL 歸零，則丟棄。
        if (iph->ttl <= 1) {
            printf("  WARNING: TTL expired for packet %s -> %s. Dropping.\n\n", src_ip_str, dst_ip_str);
            // 實際上，如果 TTL 歸零，路由器應該發送 ICMP Time Exceeded 訊息回源主機，但這裡簡化處理。
            continue;
        }
        iph->ttl--;

        // 重新計算 IP 標頭 checksum
        // 因為 TTL 改變了，IP 標頭的校驗和也需要重新計算
        iph->check = 0; // 先清零
        iph->check = calculate_checksum((unsigned short *)iph, iph->ihl * 4); // iph->ihl 是標頭長度，單位是 32-bit words

        // 設置目標地址以發送封包
        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = 0; // 對於 IP 協議，端口號不重要
        dest_addr.sin_addr.s_addr = iph->daddr; // 目標是封包的原始目的 IP

        // 發送封包
        // 由於我們在同一個 Docker 橋接網路中，直接使用 sendto 發送回網路即可
        // 核心會處理封包的二層封裝 (MAC 地址解析等)
        ssize_t bytes_sent = sendto(sock_fd, buffer, packet_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (bytes_sent < 0) {
            perror("Error sending packet");
            // 根據錯誤類型決定是否停止或重試，這裡簡化處理
        } else if (bytes_sent != packet_len) {
            fprintf(stderr, "  WARNING: Sent %zd bytes, but packet length was %zd.\n", bytes_sent, packet_len);
        }
        printf("  FORWARDED: Packet from %s to %s.\n\n", src_ip_str, dst_ip_str);
    }

    close(sock_fd);
    return 0;
}