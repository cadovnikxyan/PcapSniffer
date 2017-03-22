#include "sniffer.h"

using namespace std;


bool isIp(const string& str)
{
    struct sockaddr_in sa;
    return inet_pton(AF_INET, str.c_str(), &(sa.sin_addr))!=0;
 }
int main(int argc, char *argv[])
{

    if(argc>1){
        --argc;++argv;

        std::vector<std::string> args;
        std::string ip_,port,path;

        for(auto i=0;i<argc;++i){
            args.push_back(argv[i]);
            auto file = args.back().find(".pcap");
            if(file !=std::string::npos){
                path = args.back();
            }
        }

        if(path.empty()){
            cout<<"Не указан .pcap файл \n";
            return 0;
        }

       auto s = new Sniffer(path);
       auto a = find(args.begin(),args.end(),"-a");
       auto p = find(args.begin(),args.end(),"-p");

       if(a!=args.end()){
           a++;
           if(isIp(*a)){
               ip_=*a;
           }else{
               cout<<"Введенный адрес не является IP, фильтрация по всем адресам \n";
           }
       }
       if(p!=args.end()){
           p++;
           if(atoi((*p).c_str())){
               port=*p;
           }else{
               cout<<"Введенное значение является портом, фильтрация по всем портам \n";
           }
       }
       s->setFilters(ip_,port);
       s->read();
    }
    return 0;
}
