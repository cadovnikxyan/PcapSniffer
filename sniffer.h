#ifndef SNIFFER_H
#define SNIFFER_H
#include <fstream>
#include <iostream>
#include <pcap.h>
#include <string>
#include <vector>
#include <map>
#include <list>
#include <utility>
#include <algorithm>
#include <memory>

#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

class Sniffer
{
    /* IP header */
    struct sniff_ip {
        u_char ip_vhl;      /* version << 4 | header length >> 2 */
        u_char ip_tos;      /* type of service */
        u_short ip_len;     /* total length */
        u_short ip_id;      /* identification */
        u_short ip_off;     /* fragment offset field */
    #define IP_RF 0x8000        /* reserved fragment flag */
    #define IP_DF 0x4000        /* dont fragment flag */
    #define IP_MF 0x2000        /* more fragments flag */
    #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
        u_char ip_ttl;      /* time to live */
        u_char ip_p;        /* protocol */
        u_short ip_sum;     /* checksum */
        struct in_addr ip_src;
        struct in_addr ip_dst; /* source and dest address */
    };

public:
    Sniffer(std::string);
    void setFilters(const std::list<std::__cxx11::string> &);
    void read();
   ~Sniffer();
private:
    std::string path;
    pcap_t* pcap;
    const u_char *packet;
    u_int packetCount = 0;
    char errBuf[PCAP_ERRBUF_SIZE];
    struct sniff_ip* ip;
    struct pcap_pkthdr* header;
    struct ether_header *eptr; /* net/ethernet.h */
    struct bpf_program fp;     /*выражение фильтрации в составленном виде */
    bpf_u_int32 maskp;         /*маска подсети */
    bpf_u_int32 netp;          /* ip */
};

#endif // SNIFFER_H
