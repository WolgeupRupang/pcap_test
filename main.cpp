#include <pcap.h>
#include <stdint.h>
#include <sys/time.h>
#include <netinet/in.h>
// #include <signal.h>
#include <stdio.h>
// #include <stdlib.h>
#include <string.h>
// #include <errno.h>
// #include <unistd.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// #include <netinet/ip_icmp.h>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

// IP 헤더 구조체
struct ip *iph;

// TCP 헤더 구조체
struct tcphdr *tcph;

// Ethernet header structure
struct ether_header *ethhdr;

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}


// 패킷을 받아들일경우 이 함수를 호출한다.
// packet 가 받아들인 패킷이다.
void callback(u_char *useless, const struct pcap_pkthdr *pkthdr,
                const u_char *packet)
{
    static int count = 1;
    struct ether_header *ep;
    unsigned short ether_type;
    int chcnt =0;
    int length=pkthdr->len;

    // 이더넷 헤더를 가져온다.
    ep = (struct ether_header *)packet;

    // IP 헤더를 가져오기 위해서
    // 이더넷 헤더 크기만큼 offset 한다.
    packet += sizeof(struct ether_header);

    // 프로토콜 타입을 알아낸다.
    ether_type = ntohs(ep->ether_type);

    // 만약 IP 패킷이라면
    if (ether_type == ETHERTYPE_IP)
    {
        // IP 헤더에서 데이타 정보를 출력한다.
        iph = (struct ip *)packet;
        printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
        printf("Dst Address : %s\n", inet_ntoa(iph->ip_dst));

        // 만약 TCP 데이타 라면
        // TCP 정보를 출력한다.
        if (iph->ip_p == IPPROTO_TCP)
        {
            tcph = (struct tcphdr *)(packet + iph->ip_hl * 4);
            printf("Src Port : %d\n" , ntohs(tcph->source));
            printf("Dst Port : %d\n" , ntohs(tcph->dest));
        }

        // Packet 데이타 를 출력한다.
        // IP 헤더 부터 출력한다.
        while(length--)
        {
            printf("%02x", *(packet++));
            if ((++chcnt % 16) == 0)
                printf("\n");
        }
    }
    // IP 패킷이 아니라면
    else
    {
        printf("NONE IP 패킷\n");
    }
    printf("\n\n");
}



int main(int argc, char* argv[]) { // starting command: /.pcap_test eth0 //
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1]; //2nd input variable = address (eth0) //
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  } //return handle//

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet); //function that capture the next packet-re code it!//
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
  }

   pcap_loop(handle, 0, callback, NULL);
/*
output ex:

printf("-------------Packet Capture-------------")
printf("d_mac = "); //struct ethhdr//
printf("s_mac = ");
printf("s_ip = "); //struct iphdr//
printf("d_ip = ");
printf("s_port = "); //struct tcphdr//
printf("d_port = ");

*/

  pcap_close(handle);
  return 0;
}
