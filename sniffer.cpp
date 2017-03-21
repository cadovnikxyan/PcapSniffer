#include "sniffer.h"
#include "stdio.h"
#include <boost/algorithm/string/replace.hpp>
Sniffer::Sniffer(std::string path_):path(path_)
{
    pcap = pcap_open_offline(path.c_str(),errBuf);
}

void Sniffer::setFilters(const std::string host,const std::string port)
{
        std::string host_ ="dst host _i_" ;
        std::string port_ ="dst port _p_" ;

        boost::replace_all(host_, "_i_", host);
        boost::replace_all(port_, "_p_", port);

        pcap_compile(pcap, &fp, host_.c_str() , 0 ,netp);
        pcap_compile(pcap, &fp, port_.c_str() , 0 ,netp);

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


               if (header->len != header->caplen)
                   printf("Warning! Capture size different than packet size: %ld bytes\n", header->len);
                   printf("\n\n");
           }
      }
}

Sniffer::~Sniffer()
{

}
