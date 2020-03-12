#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define PROMISCUOUS 1

struct ip *iph; // IP header structure
struct tcphdr *tcph; // TCP header structure
struct ether_header *ethhdr; // Ethernet header structure

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

// function that called by pcap_loop()
void callback(unsigned char* unused, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    unsigned short ether_type;

    printf("-------------Packet Capture-------------\n");

    ethhdr = (struct ether_header *)packet; // GET ethernet header

    //print mac Addr
    printf("d_mac = %02X:%02X:%02X:%02X:%02X:%02X\n", ethhdr->ether_dhost[0], ethhdr->ether_dhost[1], ethhdr->ether_dhost[2], ethhdr->ether_dhost[3], ethhdr->ether_dhost[4], ethhdr->ether_dhost[5]);
    printf("s_mac = %02X:%02X:%02X:%02X:%02X:%02X\n", ethhdr->ether_shost[0], ethhdr->ether_shost[1], ethhdr->ether_shost[2], ethhdr->ether_shost[3], ethhdr->ether_shost[4], ethhdr->ether_shost[5]);

    // FILTER protocol following ONLY ethernet-ip-tcp
    ether_type = ntohs(ethhdr->ether_type);
    if (ether_type == ETHERTYPE_IP) {
        packet += sizeof(struct ether_header); // OFFSET to IP header
        iph = (struct ip *)packet;

        // print IP Addr
        printf("s_ip = %s\n", inet_ntoa(iph->ip_src));
        printf("d_ip = %s\n", inet_ntoa(iph->ip_dst));

        if (iph->ip_p == IPPROTO_TCP) {

            // print TCP Addr
            tcph = (struct tcphdr *)(packet + iph->ip_hl * 4); // OFFSET to TCP header
            printf("s_port = %d\n" , ntohs(tcph->source));
            printf("d_port = %d\n" , ntohs(tcph->dest));
        }
        else printf("NONE TCP Packet\n");
    }
    else printf("NONE IP Packet\n");
    printf("\n");
}

// STARTing command = /.pcap_test eth0
int main(int argc, char* argv[])
{
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t* handle = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, 1000, errbuf); // GET packet capture descriptor AKA pcd

  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  pcap_loop(handle, 0, callback, NULL); // RUN function callback IF packet captured

  pcap_close(handle);
  return 0;
}
