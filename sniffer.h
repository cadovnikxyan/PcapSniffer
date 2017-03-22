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

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

class Sniffer
{


public:
    Sniffer(std::string&);
    void setFilters(const std::string &host, const std::string &port);
    void read();
   ~Sniffer();
private:
    std::string path;
    pcap_t* pcap;
    const u_char *packet;
    char errBuf[PCAP_ERRBUF_SIZE];
    struct ip* ipheader;
    struct udphdr* udpHeader;
    struct pcap_pkthdr* header;
    struct ether_header *eptr; /* net/ethernet.h */
    struct bpf_program fp;     /*выражение фильтрации в составленном виде */
    bpf_u_int32 maskp;         /*маска подсети */
    bpf_u_int32 netp;          /* ip */
};

#endif // SNIFFER_H
