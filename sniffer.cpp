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

           printf("Epoch Time: %ld:%ld seconds  Packet size: %ld bytes  Packet IP-Dest %ld \n", header->ts.tv_sec, header->ts.tv_usec,header->len, pcap_offline_filter(&fp,header,(const u_char *)"ip"));

           // Show a warning if the length captured is different
           if (header->len != header->caplen)
               printf("Warning! Capture size different than packet size: %ld bytes\n", header->len);

               // Add two lines between packets
               printf("\n\n");
       }
}

Sniffer::~Sniffer()
{

}
