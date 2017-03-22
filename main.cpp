#include "sniffer.h"

using namespace std;


bool isIp(const string& str)
{
    struct sockaddr_in sa;
    return inet_pton(AF_INET, str.c_str(), &(sa.sin_addr))!=0;
 }
int main(int argc, char *argv[])
{
    Sniffer* s;
    if(argc>1){
        --argc;++argv;

        std::vector<std::string> args;
        std::string ip_,port;
        for(auto i=0;i<argc;++i){
            args.push_back(argv[i]);
        }
        if(args.size()>1){

           s = new Sniffer(args[argc-1]);
            auto a =find(args.begin(),args.end(),"-a");
            auto p =find(args.begin(),args.end(),"-p");
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
        }else{

            s = new Sniffer(args[argc-1]);
            s->read();
        }



    }
    return 0;
}
