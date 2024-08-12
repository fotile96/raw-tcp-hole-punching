#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "const.h"
#include <string>
#include <iostream>

#define __cpp_lib_jthread

#include <thread>
#include <chrono>
#include <absl/cleanup/cleanup.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "in_cksum.h"

inline std::string read_env(const char *env_name, bool allow_omit = false) {
    auto res = std::getenv(env_name);
    if (res == nullptr) {
        std::cerr << "Unspecified environment variable: " << env_name << std::endl;
        if (!allow_omit)
            std::exit(EINVAL);
        else
            return "";
    }
    return std::string(res);
}

std::string tcp_opponent_addr;
std::string tcp_local_addr;
std::string udp_listen_addr;
std::string udp_forward_addr;
std::string raw_listen_dev;

std::string tcp_opponent_host;
std::string tcp_opponent_port;
std::string tcp_local_host;
std::string tcp_local_port;
std::string udp_listen_host;
std::string udp_listen_port;
std::string udp_forward_host;
std::string udp_forward_port;

int udp_sockfd;
int raw_sockfd;
sockaddr_in raw_sin;
sockaddr_in *udp_sin;
char raw_ip_packet[4096];
iphdr *const iph = reinterpret_cast<iphdr *>(raw_ip_packet);
tcphdr *const tcph = reinterpret_cast<tcphdr *>(raw_ip_packet + sizeof(iphdr));
char *const raw_payload = raw_ip_packet + sizeof(iphdr) + sizeof(tcphdr);
char raw_tcp_phdr[4];
const cksum_vec tcp_cksum_vecs[] = {
        cksum_vec{reinterpret_cast<uint8_t *>(&iph->saddr), 4},
        cksum_vec{reinterpret_cast<uint8_t *>(&iph->daddr), 4},
        cksum_vec{reinterpret_cast<uint8_t *>(raw_tcp_phdr), 4},
        cksum_vec{reinterpret_cast<uint8_t *>(tcph), 0}
};
const cksum_vec ip_cksum_vecs[] = {
        cksum_vec{reinterpret_cast<uint8_t *>(iph), sizeof(iphdr)}
};

inline void update_raw_tcp_checksum(int payload_len) {
    tcph->check = 0;
    *reinterpret_cast<uint16_t *>(raw_tcp_phdr + 2) = htons(payload_len + sizeof(tcphdr));
    uint16_t tcp_cksumh = ones_complement_sum<4, true>(tcp_cksum_vecs, payload_len + sizeof(tcphdr));
#ifndef NDEBUG
    std::cerr << "tcp_cksumh = " << std::hex << tcp_cksumh << std::endl;
#endif
    tcph->check = tcp_cksumh;
    iph->tot_len = htons(sizeof(iphdr) + sizeof(tcphdr) + payload_len);

    /*
    iph->check = 0;
    uint16_t ip_cksumh = ones_complement_sum<1, true>(ip_cksum_vecs, -1);
    iph->check = ip_cksumh;*/
}


void pcap_get_packet(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
#ifndef NDEBUG
    std::cerr << "in pcap_get_packet()" << std::endl;
#endif
    if (pkthdr->caplen < 14 + sizeof(iphdr) + sizeof(tcphdr))
        return;

    const iphdr *iph = reinterpret_cast<const iphdr *>(packet + 14);

    const uint8_t *tcp_payload = packet + 14 + sizeof(iphdr) + sizeof(tcphdr);
    int payload_len = std::min(pkthdr->caplen - 14 - sizeof(iphdr) - sizeof(tcphdr),
                               ntohs(iph->tot_len) - sizeof(iphdr) - sizeof(tcphdr));
#ifndef NDEBUG
    std::cerr << "payload_len = " << payload_len << std::endl;
#endif

    if (payload_len <= 0)
        return;


    int sent = 0;
    if (udp_sin != nullptr)
        sent = sendto(udp_sockfd, tcp_payload, payload_len, 0, reinterpret_cast<const sockaddr *>(udp_sin),
                      sizeof(sockaddr_in));

#ifndef NDEBUG
    std::cerr << "sent = " << sent << std::endl;
    if (sent == -1)
        std::cerr << "errno = " << errno << std::endl;
#endif

}

void pcap_thread_main() {
    char errBuf[PCAP_ERRBUF_SIZE];
    //pcap_t *device = pcap_open_live(raw_listen_dev.c_str(), 65535, 1, 1, errBuf);
    pcap_t *device = pcap_create(raw_listen_dev.c_str(), errBuf);

    if (device == nullptr) {
        std::cerr << "error: pcap_create(): " << errBuf << std::endl;
        std::exit(EPERM);
    }

    if (pcap_set_snaplen(device, 65535) != 0) {
        std::cerr << "error: pcap_set_snaplen() failed" << std::endl;
        std::exit(EPERM);
    }

    if (pcap_set_immediate_mode(device, 1) != 0) {
        std::cerr << "error: pcap_set_immediate_mode() failed" << std::endl;
        std::exit(EPERM);
    }

    if (pcap_activate(device) != 0) {
        std::cerr << "error: pcap_activate() failed" << std::endl;
        std::exit(EPERM);
    }

    pcap_set_buffer_size(device, 32 * 1024 * 1024);

    absl::Cleanup device_closer = [device] {
        pcap_close(device);
        std::cerr << "pcap device closed." << std::endl;
    };

    bpf_program filter;
    std::string filter_rule =
            "ip src host " + tcp_opponent_host + " and tcp src port " + tcp_opponent_port + " and ip dst host " +
            tcp_local_host + " and tcp dst port " + tcp_local_port + " and " + MAGIC_URGENT_POINTER_PCAP_RULE;

    /*filter_rule =
            "ip dst host " + tcp_opponent_host + " and tcp dst port " + tcp_opponent_port + " and ip src host " +
            tcp_local_host + " and tcp src port " + tcp_local_port + " and " + MAGIC_URGENT_POINTER_PCAP_RULE;*/

    // filter_rule = "tcp";

#ifndef NDEBUG
    std::cerr << filter_rule << std::endl;
#endif

    int res = pcap_compile(device, &filter, filter_rule.c_str(), 1, 0);
    if (res != 0) {
        std::cerr << "error: pcap_compile() failed: " << pcap_geterr(device) << std::endl;
        std::exit(res);
    }
    res = pcap_setfilter(device, &filter);
    if (res != 0) {
        std::cerr << "error: pcap_setfilter() failed: " << pcap_geterr(device) << std::endl;
        std::exit(res);
    }

    u_char id = 0;
    pcap_loop(device, -1, pcap_get_packet, &id);

#ifndef NDEBUG
    std::cerr << "thread_raw exits." << std::endl;
#endif
}

void udp_thread_main() {
    while (true) {
        int recv_len = 0;
        if (udp_sin != nullptr)
            recv_len = recvfrom(udp_sockfd, raw_payload, 3072, 0, NULL, NULL);
        else {
            auto *sin = new sockaddr_in;
            socklen_t sin_len = sizeof(sockaddr_in);
            std::memset(sin, 0, sin_len);
            recv_len = recvfrom(udp_sockfd, raw_payload, 3072, 0, reinterpret_cast<sockaddr *>(sin), &sin_len);
            udp_sin = sin;
        }
        if (recv_len <= 0)
            continue;
#ifndef NDEBUG
        std::cerr << "udp recvfrom: len = " << recv_len << std::endl;
#endif
        update_raw_tcp_checksum(recv_len);
        /*
        sendto(raw_sockfd, raw_ip_packet, recv_len + sizeof(iphdr) + sizeof(tcphdr), 0,
               reinterpret_cast<const sockaddr *>(&raw_sin), sizeof(raw_sin));*/
        int sent = sendto(raw_sockfd, tcph, recv_len + sizeof(tcphdr), 0,
                          reinterpret_cast<const sockaddr *>(&raw_sin), sizeof(raw_sin));
#ifndef NDEBUG
        std::cerr << "sent = " << sent << std::endl;
#endif
    }
}

using namespace std::chrono_literals;

inline void parse_addr_to_str(const std::string &addr, std::string &host, std::string &port) {
    int n = addr.find(':');
    host = addr.substr(0, n);
    port = addr.substr(n + 1);
}

void open_udp_sin() {
    if (!(udp_forward_addr.length() > 0 && udp_sin == nullptr))
        return;
    parse_addr_to_str(udp_forward_addr, udp_forward_host, udp_forward_port);

    auto _udp_sin = new sockaddr_in;
    std::memset(_udp_sin, 0, sizeof(sockaddr_in));
    _udp_sin->sin_family = AF_INET;
    _udp_sin->sin_port = htons(std::stoi(udp_forward_port));
    _udp_sin->sin_addr.s_addr = inet_addr(udp_forward_host.c_str());

    udp_sin = _udp_sin;
}

void open_udp_socket() {
    udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sockfd < 0) {
        std::cerr << "Failed to open udp socket!" << std::endl;
        std::exit(errno);
    }

    int reuse = 1;
    if (setsockopt(udp_sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *) &reuse, sizeof(reuse)) < 0) {
        std::cerr << "setsockopt(SO_REUSEADDR) failed." << std::endl;
        close(udp_sockfd);
        std::exit(errno);
    }
    reuse = 1;
    if (setsockopt(udp_sockfd, SOL_SOCKET, SO_REUSEPORT, (const char *) &reuse, sizeof(reuse)) < 0) {
        std::cerr << "setsockopt(SO_REUSEADDR) failed." << std::endl;
        close(udp_sockfd);
        std::exit(errno);
    }

    sockaddr_in servaddr;
    std::memset(&servaddr, 0, sizeof(sockaddr_in));
    servaddr.sin_family = AF_INET;
    if (inet_pton(AF_INET, udp_listen_host.c_str(), &servaddr.sin_addr) <= 0) {
        std::cerr << "inet_pton failed." << std::endl << "udp_listen_addr = " << udp_listen_addr << std::endl
                  << "udp_listen_host = " << udp_listen_host << std::endl;
        close(udp_sockfd);
        std::exit(errno);
    }
    servaddr.sin_port = htons(std::stoi(udp_listen_port));

    if (bind(udp_sockfd, reinterpret_cast<const sockaddr *>(&servaddr), sizeof(servaddr)) != 0) {
        std::cerr << "bind() failed." << std::endl;
        close(udp_sockfd);
        std::exit(errno);
    }

    int on = 1;
    setsockopt(udp_sockfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));

    open_udp_sin();
}

void open_raw_socket() {
    raw_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    //raw_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (raw_sockfd < 0) {
        std::cerr << "Failed to open raw socket!" << std::endl;
        std::exit(errno);
    }

    sockaddr_in sin;
    std::memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(std::stoi(tcp_local_port));
    sin.sin_addr.s_addr = inet_addr(tcp_local_host.c_str());

    if (bind(raw_sockfd, reinterpret_cast<const sockaddr *>(&sin), sizeof(sin)) != 0) {
        std::cerr << "Failed to bind the raw socket to specified address!" << std::endl;
        std::exit(errno);
    }

    std::memset(raw_ip_packet, 0, sizeof(raw_ip_packet));

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(iphdr) + sizeof(tcphdr);
    iph->id = htons(54321); // Id of this packet
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0; // Set to 0 before calculating checksum
    iph->saddr = inet_addr(tcp_local_host.c_str()); // Source IP address
    iph->daddr = inet_addr(tcp_opponent_host.c_str());
    iph->check = 0;

    tcph->source = htons(std::stoi(tcp_local_port));
    tcph->dest = htons(std::stoi(tcp_opponent_port));
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5; // TCP header size
    tcph->fin = 0;
    tcph->syn = 0;
    tcph->rst = 0;
    tcph->psh = 1;
    tcph->ack = 1;
    tcph->urg = 0;
    tcph->window = htons(5840); // Maximum allowed window size
    tcph->check = 0;
    tcph->urg_ptr = htons(MAGIC_URGENT_POINTER);

    *reinterpret_cast<uint16_t *>(raw_tcp_phdr) = htons(IPPROTO_TCP);

    raw_sin.sin_family = AF_INET;
    raw_sin.sin_port = htons(std::stoi(tcp_opponent_port));
    raw_sin.sin_addr.s_addr = inet_addr(tcp_opponent_host.c_str());
}

void pcap_sniff_sn_get_packet(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
#ifndef NDEBUG
    std::cerr << "in pcap_sniff_sn_get_packet()" << std::endl;
#endif
    if (pkthdr->caplen < 14 + sizeof(iphdr) + sizeof(tcphdr))
        return;

    const tcphdr *tcph_ = reinterpret_cast<const tcphdr *>(packet + 14 + sizeof(iphdr));

    int seq = ntohl(tcph_->seq);
    int ack_seq = ntohl(tcph_->ack_seq);

#ifndef NDEBUG
    std::cerr << "saw seq = " << seq << ", ack_seq = " << ack_seq << std::endl;
#endif

    int new_seq = ack_seq - 3072;
    int new_ack_seq = seq - 3072;

#ifndef NDEBUG
    std::cerr << "set new_seq = " << new_seq << ", new_ack_seq = " << new_ack_seq << std::endl;
#endif

    tcph->seq = htonl(new_seq);
    tcph->ack_seq = htonl(new_ack_seq);
}

void pcap_sniff_sn_thread_main() {
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_t *device = pcap_open_live(raw_listen_dev.c_str(), 65535, 1, 50, errBuf);

    if (device == nullptr) {
        std::cerr << "error: pcap_open_live(): " << errBuf << std::endl;
        std::exit(EPERM);
    }

    absl::Cleanup device_closer = [device] {
        pcap_close(device);
        std::cerr << "pcap device closed." << std::endl;
    };

    bpf_program filter;
    std::string filter_rule =
            "ip src host " + tcp_opponent_host + " and tcp src port " + tcp_opponent_port + " and ip dst host " +
            tcp_local_host + " and tcp dst port " + tcp_local_port + " and " + SNIFF_SN_PCAP_RULE;

#ifndef NDEBUG
    std::cerr << filter_rule << std::endl;
#endif

    int res = pcap_compile(device, &filter, filter_rule.c_str(), 1, 0);
    if (res != 0) {
        std::cerr << "error: pcap_compile() failed: " << pcap_geterr(device) << std::endl;
        std::exit(res);
    }
    res = pcap_setfilter(device, &filter);
    if (res != 0) {
        std::cerr << "error: pcap_setfilter() failed: " << pcap_geterr(device) << std::endl;
        std::exit(res);
    }

    u_char id = 0;
    pcap_loop(device, -1, pcap_sniff_sn_get_packet, &id);

#ifndef NDEBUG
    std::cerr << "thread_raw exits." << std::endl;
#endif
}

int main(int argc, char *argv[]) {
    tcp_opponent_addr = read_env(ENV_TCP_OPPONENT_ADDR);
    tcp_local_addr = read_env(ENV_TCP_LOCAL_ADDR);
    udp_listen_addr = read_env(ENV_UDP_LISTEN_ADDR);
    udp_forward_addr = read_env(ENV_UDP_FORWARD_ADDR, true);
    raw_listen_dev = read_env(ENV_RAW_LISTEN_DEV);

    parse_addr_to_str(tcp_opponent_addr, tcp_opponent_host, tcp_opponent_port);
    parse_addr_to_str(tcp_local_addr, tcp_local_host, tcp_local_port);
    parse_addr_to_str(udp_listen_addr, udp_listen_host, udp_listen_port);


    open_udp_socket();
    open_raw_socket();

    std::jthread pcap_thread(pcap_thread_main);
    std::jthread udp_thread(udp_thread_main);
    std::jthread pcap_sniff_sn_thread(pcap_sniff_sn_thread_main);

    while (true) {
        std::cout << "I am alive." << std::endl;
        std::this_thread::sleep_for(1000ms);
    }
    return 0;
}