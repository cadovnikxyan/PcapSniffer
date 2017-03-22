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
    Sniffer(const std::string& path);
    void setFilters(const std::string& host, const std::string& port);
    void read();
private:
    pcap_t* pcap;
    const u_char *packet;
    char errBuf[PCAP_ERRBUF_SIZE];
    struct ip* ipheader;
    struct udphdr* udpHeader;
    struct pcap_pkthdr* header;
    struct bpf_program fp;
    bpf_u_int32 netp;
};

#endif // SNIFFER_H
