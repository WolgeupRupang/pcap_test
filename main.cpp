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

// IP header structure
struct ip *iph;

// TCP header structure
struct tcphdr *tcph;

// Ethernet header structure
struct ether_header *ethhdr;

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void callback(unsigned char* unused, const struct pcap_pkthdr *pkthdr, const u_char *packet) // call this function IF a packet captured
{
    printf("-------------Packet Capture-------------\n");

    // get ethernet header
    ethhdr = (struct ether_header *)packet;


    ether_type = ntohs(ep->ether_type);

    if (ether_type == ETHERTYPE_IP) {

        //print mac Addr
        printf("d_mac = %02X:%02X:%02X:%02X:%02X:%02X\n", ethhdr->ether_dhost[0], ethhdr->ether_dhost[1], ethhdr->ether_dhost[2], ethhdr->ether_dhost[3], ethhdr->ether_dhost[4], ethhdr->ether_dhost[5]);
        printf("s_mac = %02X:%02X:%02X:%02X:%02X:%02X\n", ethhdr->ether_shost[0], ethhdr->ether_shost[1], ethhdr->ether_shost[2], ethhdr->ether_shost[3], ethhdr->ether_shost[4], ethhdr->ether_shost[5]);

        // offset ethernet header length to IP header
        packet += sizeof(struct ether_header);
        iph = (struct ip *)packet;

        // print IP Addr
        printf("s_ip = %s\n", inet_ntoa(iph->ip_src));
        printf("d_ip = %s\n", inet_ntoa(iph->ip_dst));

        // print TCP Addr
        tcph = (struct tcphdr *)(packet + iph->ip_hl * 4);
        printf("s_port : %d\n" , ntohs(tcph->source));
        printf("d_port : %d\n" , ntohs(tcph->dest));
    }

}



int main(int argc, char* argv[]) // starting command: /.pcap_test eth0
{
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  } //return handle

  pcap_loop(handle, 0, callback, NULL); //run function callback IF packet captured

  pcap_close(handle);
  return 0;
}
