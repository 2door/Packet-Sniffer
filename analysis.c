#include "analysis.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

pthread_mutex_t muxlock_xmas = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t muxlock_arp = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t muxlock_blacklist = PTHREAD_MUTEX_INITIALIZER;

volatile int xmas_count = 0;
volatile int arp_count  = 0;
volatile int blacklist_count = 0;

void report() {
    printf("\nIntrusion Detection Report:\n");
    printf("%d Xmas scans (host fingerprinting)\n", xmas_count);
    printf("%d  ARP responses (cache poisoning)\n", arp_count);
    printf("%d  URL Blacklist violations\n", blacklist_count);
    
    pthread_mutex_destroy(&muxlock_xmas);
    pthread_mutex_destroy(&muxlock_arp);
    pthread_mutex_destroy(&muxlock_blacklist);
}

void analyse(struct pcap_pkthdr *head, const unsigned char *packet, int verbose) {
    // TODO your part 2 code here
    //Parsing ethernet packet to check the payload type (IP or ARP)
    struct ether_header *eth_header = (struct ether_header*) packet;
    unsigned short eth_type = ntohs(eth_header->ether_type);        //will store type: IP or ARP
    
    if(eth_type == ETHERTYPE_ARP) {
        const unsigned char *arp_data = packet + ETH_HLEN;              //strip of ethernet header
        struct ether_arp *arp_packet = (struct ether_arp *) arp_data;   //parse ARP packet data
        
        //check for ARP poisoning - record any ARP response (op code 2) received
        if(ntohs(arp_packet->ea_hdr.ar_op) == 2) {
            while(pthread_mutex_trylock(&muxlock_arp) != 0);    //wait until no threads editing arp_count
            arp_count++;                                        //count this response for report at end of execution
            pthread_mutex_unlock(&muxlock_arp);                 //unlock so threads can edit arp_count
        }
    } else if(eth_type == ETHERTYPE_IP) {
        const unsigned char *ip_data = packet + ETH_HLEN;   //strip of ethernet header
        struct ip *ip_header = (struct ip *) ip_data;       //parse IP packet data
        int ip_header_len = ip_header->ip_hl * 4;           //ip_hl represents the header length in 32-bit words
        
        const unsigned char *tcp_data = ip_data + ip_header_len;    //strip IP header
        struct tcphdr *tcp_header = (struct tcphdr *) tcp_data;     //parse TCP packet data
        int tcp_header_len = tcp_header->doff * 4;                  //doff represents the header length in 32-bit words
        
        //Xmass scan detection - checking for set flags
        if( (tcp_header->fin == 1) && (tcp_header->psh == 1) && (tcp_header->urg == 1) ) {
            while(pthread_mutex_trylock(&muxlock_xmas) != 0);    //wait until no threads editing xmas_count
            xmas_count++;                                        //count this suspicious packet for report at end of execution
            pthread_mutex_unlock(&muxlock_xmas);                 //unlock so threads can edit xmas_count
        }
        
        //only checking packets passed outward through port 80
        if(ntohs(tcp_header->dest) == 80) {
            const unsigned char *payload = tcp_data + tcp_header_len;   //strip of TCP header
            char *begin = strstr((const char *)payload, "Host: www.bbc.co.uk");       //if communicating with www.bbc.co.uk
            if(begin != NULL) {                                         //if there is a pointer to the locatoion of the point in which the searched string begins in payload
                while(pthread_mutex_trylock(&muxlock_blacklist) != 0);      //wait until no threads editing blacklist_count
                blacklist_count++;                                          //count this blacklist violation for report at end of execution
                pthread_mutex_unlock(&muxlock_blacklist);                   //unlock so threads can edit blacklist_count
            }
        }
    }
    free((unsigned char *) packet);                               //must free memory which was allocated in before dispatch (in sniff)
    //printf("\n");
}