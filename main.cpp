#include <iostream>
#include "sniffer.h"

using namespace std;

int main(int argc, char *argv[])
{
    Sniffer* s = new Sniffer("data1.pcap");
    std::list<std::string> list;
    s->read();
    return 0;
}
