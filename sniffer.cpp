#include "sniffer.h"
#include "stdio.h"
Sniffer::Sniffer(std::string path_):path(path_)
{
    FILE* fd = fopen(path.c_str(),"r");
    pcap = pcap_fopen_offline(fd,errBuf);

}

void Sniffer::setFilters(const std::list<std::string> &filter_list)
{
    for(std::string s : filter_list){
        pcap_compile(pcap, &fp, s.c_str() , 0 ,netp);
    }
    pcap_setfilter(pcap, &fp);
}

void Sniffer::read()
{
    while (int returnValue = pcap_next_ex(pcap, &header, &packet) >= 0)
       {
        char destIP[INET_ADDRSTRLEN];
        ipheader = (struct ip*)(packet + sizeof(struct ether_header));
        if(ipheader->ip_p==IPPROTO_UDP){
        udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        inet_ntop(AF_INET,&(ipheader->ip_dst),destIP ,INET_ADDRSTRLEN);
           printf("Epoch Time: %ld:%ld seconds  Packet size: %ld bytes  Packet IP-Dest %s Packet Port-Dest %d \n"
                  , header->ts.tv_sec
                  , header->ts.tv_usec
                  , header->len
                  , destIP
                  ,ntohs(udpHeader->dest));

//                  , pcap_offline_filter(&fp,header,(const u_char *)"ip"));

           if (header->len != header->caplen)
               printf("Warning! Capture size different than packet size: %ld bytes\n", header->len);
               printf("\n\n");
       }
    }
}

Sniffer::~Sniffer()
{

}
