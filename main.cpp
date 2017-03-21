#include "sniffer.h"

using namespace std;

int main(int argc, char *argv[])
{
    --argc;++argv;
auto sdd="1231";
    Sniffer s("data2.pcap");

    s.setFilters("192.168.88.102","");
    s.read();


    return 0;
}
