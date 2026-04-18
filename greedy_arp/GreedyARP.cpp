#include "GreedyARP.h"

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>

GreedyARP::GreedyARP(const std::string & iface) {
    pcap_if_t * alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        throw std::runtime_error(errbuf);
    };
    bool found = false;
    if (iface == "None") {
        found = true;
        iface_ = alldevs->name;
    } else {
        pcap_if_t * l; 
        for (l = alldevs; l != NULL; l = l->next) {
            if (iface == l->name) {
                iface_ = iface;
                found = true;
                break;
            }
        }
    }
    pcap_freealldevs(alldevs);
    if (!found) {
        throw std::runtime_error("Did't find interface: " + iface);
    }
    set_mac();
}   

void GreedyARP::run(void) {
    struct bpf_program fp;
    char filter_exp[] = "arp";
    bpf_u_int32 mask = 0;
    bpf_u_int32 net = 0;
    if (pcap_lookupnet(get_interface(), &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;
    }
    const u_char *packet;
    struct pcap_pkthdr header;

    handle_ = pcap_open_live(get_interface(), BUFSIZ, 1, 1000, errbuf);
    if (handle_ == NULL) {
        throw std::runtime_error(errbuf);
    }
    if (pcap_compile(handle_, &fp, filter_exp, 0, net) == -1) {
        throw std::runtime_error("Couldn't parde filter");
    }
    if (pcap_setfilter(handle_, &fp) == -1) {
        throw std::runtime_error("Couldn't install filter");
    }
    std::thread sender(&GreedyARP::sender_thread, this);
    sender.detach(); 
    pcap_loop(handle_, 0, packet_handler, reinterpret_cast<u_char*>(this));
    pcap_freecode(&fp);
    pcap_close(handle_);
}

