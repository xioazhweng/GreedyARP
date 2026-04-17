cmake_minimum_required(VERSION 3.16)


project (GreedyARP)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE INTERNAL "")

add_subdirectory(greedy_arp)
add_compile_options(-fsanitize=thread -g)
add_link_options(-fsanitize=thread)

add_executable(main main.cpp)
target_link_libraries(main PRIVATE greedy_arp pcap)
