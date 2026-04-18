#pragma once

#include <string>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <queue>
#include <vector>
#include <condition_variable>
#include <chrono>
#include <thread>
#include <cstdint>
#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <array>


/* Ethernet addresses are 6 bytes */
#define ETHERTYPE_ARP 0x0806

class GreedyARP {
    public:
        GreedyARP(const std::string & iface = "None");
        void run(void);
        const char * get_interface() {
            return iface_.c_str();
        }

    private:
        std::string iface_;
        pcap_t * handle_;
        char errbuf[PCAP_ERRBUF_SIZE];
        std::queue<std::vector<uint8_t>> packet_queue;
        std::mutex queue_mutex;
        std::condition_variable cv;
        std::array<uint8_t, 6> mac_;
        
        void sender_thread() {
            while (true) {
                std::vector<uint8_t> packet;
                {
                    std::unique_lock<std::mutex> lock(queue_mutex);
                    cv.wait(lock, [&] {return !packet_queue.empty();});
                    packet = std::move(packet_queue.front());
                    packet_queue.pop();
                }
                print_arp(packet.data());
                if (pcap_sendpacket(handle_, packet.data(), packet.size()) != 0) {
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }

        //Callback function
        static void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
            GreedyARP* self = reinterpret_cast<GreedyARP*>(user);
            struct ether_header *eth = (struct ether_header *) packet;
            if (ntohs(eth->ether_type) != ETHERTYPE_ARP) 
                return;
            struct ether_arp *arp = (struct ether_arp *)(packet + sizeof(struct ether_header));
            if (ntohs(arp->ea_hdr.ar_op) == ARPOP_REPLY) 
                return;
            self->print_arp(packet);
            std::vector<uint8_t> reply = build_arp_reply(packet);
            {
                std::lock_guard<std::mutex> lock(self->queue_mutex);
                self->packet_queue.push(std::move(reply));
            }
            self->cv.notify_one();
        }
        
        static std::vector<uint8_t> build_arp_reply(const u_char* packet) {
            struct ether_header *eth = (struct ether_header *) packet;
            struct ether_arp *arp = (struct ether_arp *)(packet + sizeof(struct ether_header));
            size_t packet_size = sizeof(ether_header) + sizeof(ether_arp);
            if (packet_size < 60) {
                 packet_size = 60; 
            }
            std::vector<uint8_t> reply(packet_size, 0);
            ether_header* eth_reply = (ether_header*)reply.data();
            ether_arp* arp_reply = (ether_arp*)(reply.data() + sizeof(ether_header));
            uint8_t mac[6] = {0xc0, 0x35, 0x32, 0x0e, 0x78, 0x35};
            // MAC адреса
            memcpy(eth_reply->ether_dhost, eth->ether_shost, 6); // куда отправляем
            memcpy(eth_reply->ether_shost, mac, 6); // наш MAC
            eth_reply->ether_type = htons(ETHERTYPE_ARP);
            // ARP заголовок
            arp_reply->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
            arp_reply->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
            arp_reply->ea_hdr.ar_hln = 6;
            arp_reply->ea_hdr.ar_pln = 4;
            arp_reply->ea_hdr.ar_op  = htons(ARPOP_REPLY);
            memcpy(arp_reply->arp_sha, mac, 6);                // наш MAC
            memcpy(arp_reply->arp_spa, arp->arp_tpa, 4);       // наш IP (IP, который отвечаем)
            memcpy(arp_reply->arp_tha, arp->arp_sha, 6);       // MAC адрес отправителя запроса
            memcpy(arp_reply->arp_tpa, arp->arp_spa, 4);       // IP отправителя запроса
            return reply;
        }

        static void print_arp(const uint8_t * packet) {
            struct ether_header *eth = (struct ether_header *) packet;
            struct ether_arp *arp = (struct ether_arp *)(packet + sizeof(struct ether_header));
        
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arp->arp_spa, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, arp->arp_tpa, dst_ip, sizeof(dst_ip));

            if (ntohs(arp->ea_hdr.ar_op) == ARPOP_REPLY) {
                printf("ARP Reply: %s ", src_ip);
            } else {
                printf("ARP Request: %s ", src_ip);
            }

            printf("(%02x:%02x:%02x:%02x:%02x:%02x)",
                arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
                arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
            printf(" -> %s", dst_ip);
            printf("(%02x:%02x:%02x:%02x:%02x:%02x)\n",
            arp->arp_tha[0], arp->arp_tha[1], arp->arp_tha[2],
            arp->arp_tha[3], arp->arp_tha[4], arp->arp_tha[5]);
        }

        void set_mac(void) {
            struct ifreq ifr;
            int sock, j, k;
            char *p, addr[32], mask[32], mac[32];
            sock=socket(PF_INET, SOCK_STREAM, 0);
            if (sock == -1) {
                throw std::runtime_error("Cannot open socket");
            }
            strncpy(ifr.ifr_name, iface_.c_str(), sizeof(ifr.ifr_name)-1);
            ifr.ifr_name[sizeof(ifr.ifr_name)-1]='\0';

            if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
                close(sock);
                throw std::runtime_error("Cannot get MAC address");
            }
            memcpy(mac_.data(), ifr.ifr_hwaddr.sa_data, 6);
            close(sock);
        }
};