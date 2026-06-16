add_subdirectory(greedy_arp)

add_executable(greedy main.cpp)

target_link_libraries(greedy PRIVATE greedy_arp pcap)
