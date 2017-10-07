#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>

struct packet_queue_elem {
    //stores all the packet data required by 'analyse' in 'analysis'
    struct packet_queue_elem *next; //next element in queue; NULL if tail
    struct pcap_pkthdr *header;
    const unsigned char *packet;
    int verbose;
};

struct packet_queue {
    struct packet_queue_elem *head; //for packet extraction by threads
    struct packet_queue_elem *tail; //for packet queuing by dispach
};

struct thread_args {
    //used for debugging purposes. stores thread number for each thread in thraedpool and can be passed to the thread in 'thread_create' in 'dispatch'
    unsigned int threadnum;
};

void dispatch(struct pcap_pkthdr *header, const unsigned char *packet, int verbose);
void thread_create();           //called in 'sniff' to initialize threads and the packet queue used by these
void sig_handler(int signo);    //called in order to terminate. initialized in 'sniff'
#endif
