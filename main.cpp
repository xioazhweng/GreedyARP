#include <pcap/pcap.h>
#include "greedy_arp/GreedyARP.h"


int main(void) {
    GreedyARP snif{"wlp3s0"};
    snif.run();
    return 0;
}
