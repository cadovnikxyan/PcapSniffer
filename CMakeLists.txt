project(PcapSniffer)
cmake_minimum_required(VERSION 2.8)
aux_source_directory(. SRC_LIST)
add_executable(${PROJECT_NAME} ${SRC_LIST})
add_compile_options("-std=c++14")
#add_library(pcap IMPORTED STATIC)
#set_property(TARGET PcapSniffer PROPERTY
#             IMPORTED_LOCATION /usr/local/lib/libpcap.a)
target_link_libraries(PcapSniffer /usr/local/lib/libpcap.so.1)
