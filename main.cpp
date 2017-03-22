#include "sniffer.h"




bool isIp(const std::string& str)
{
    struct sockaddr_in sa;
    const char* ip_str = str.c_str();
    if(ip_str==nullptr) return false;
    return inet_pton(AF_INET, ip_str, &(sa.sin_addr))!=0;
 }

bool isPort(const std::string& s)
{
    return !s.empty() && std::find_if(s.begin(),
        s.end(), [](char c) { return !std::isdigit(c); }) == s.end();
}

int main(int argc, char *argv[])
{

    if(argc>1 ){
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
            std::cout<<"Не указан .pcap файл \n";
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
               std::cout<<"Введенный адрес не является IP, фильтрация по всем адресам \n";
           }
       }
       if(p!=args.end()){
           p++;

           if(isPort(*p)){
               port=*p;
           }else{
               std::cout<<"Введенное значение не является портом, фильтрация по всем портам \n";
           }
       }
       s->setFilters(ip_,port);
       s->read();
    }
    return 0;
}
