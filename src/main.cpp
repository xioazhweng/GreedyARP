#include <pcap/pcap.h>
#include "greedy_arp/GreedyARP.h"
#include <iostream>

int main(int argc, char * argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: ./main interface_name" << std::endl;
    }
    GreedyARP snif{argv[1]};
    snif.run();
    return 0;
}
