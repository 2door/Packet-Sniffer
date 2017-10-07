#include "dispatch.h"

#include <pcap.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>

#include "analysis.h"

#define MAX_THREAD_NUM 10

pthread_mutex_t muxlock_queue = PTHREAD_MUTEX_INITIALIZER;  //used to change queue by threads and 'dispatch'
struct packet_queue *queue; //queue used to store packets for thread
pthread_t threads[MAX_THREAD_NUM];      //stores threads to be used
pthread_cond_t added;

void * thread_code(void *arg) {
    //struct thread_args *args = (struct thread_args *) arg;    //stores the thread's number (when passed by thread_createh)
    struct packet_queue_elem *tmp;
    //set cancel state enabled so that signal can terminate all threads
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    
    while(1) {
        if(queue->head == NULL) {
            pthread_cond_wait(&added, &muxlock_queue);  //wait for signal from dispatch saying that a packet has been added to the queue
        }
        
        //at this point, the queue is already locked
        //set cancel state disabled so that if thread is processing on termination, will wait until it is done before canceling
        //the reason for this is the need to free the memory allocated to the packet queue element extracted by the current thread
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
        tmp = queue->head;  //retrieve the oldest packet in queue
        if(tmp == NULL) {   //just a sanity check - should never be the case...
            queue->tail = NULL;
        } else if(tmp->next == NULL) {
            //the extracted packet queue element was the last one in the queue (head and tail must now not point to anything)
            queue->head = NULL;
            queue->tail = NULL;
        } else {
            //there are elements still in the queue. set head to the next element for the following thread to extract
            queue->head = queue->head->next;
        }
        pthread_mutex_unlock(&muxlock_queue);   //unlock so that other thread can use the queue
        
        //if there was actual packet in queue - another sanity check
        if(tmp != NULL) {
            analyse(tmp->header, tmp->packet, tmp->verbose);
            //free((unsigned char *) tmp->packet);
            free(tmp);  //must free memory allocated in 'dispatch'
            
        }
        //set cancel state back to enabled so that termination cancels thread
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    }
}

void thread_create() {
    //initializing queue that will store packets for threads to process
    queue = malloc(sizeof(struct packet_queue));
    queue->head = NULL;
    queue->tail = NULL;
    unsigned int i;
    for (i = 0; i < MAX_THREAD_NUM; i++) {
        //struct thread_args *args = malloc(sizeof(struct thread_args));
        //args->threadnum = i;
        pthread_create(&threads[i], NULL, &thread_code, NULL);
    }
}


void sig_handler(int signo) {
    //Ctrl + C signal 
    if(signo == SIGINT) {
        unsigned int i;
        for (i = 0; i < MAX_THREAD_NUM; ++i) {
            while(!pthread_cancel(threads[i]));  //terminate regardless of current activity. if the state is disabled, the cancel request is queued and the command returns 0
        }
        
        //free memory used by all packet structures in queue - allocated during execution
        while(queue->head != NULL) {
            if(queue->head->next == NULL) {
                free((unsigned char *) queue->head->packet);    //memory was allocated for the packet data each time a queue element was created - need to free this memory
                free(queue->head);                              //memory is allocated for these packet elements - need to free this memory
                break;
            } else {
                struct packet_queue_elem *tmp = queue->head;
                queue->head = queue->head->next;
                free((unsigned char *) tmp->packet);    //memory was allocated for the packet data each time a queue element was created - need to free this memory
                free(tmp);                              //memory is allocated for these packet elements - need to free this memory
            }
        }
        free(queue);    //memory was allocated for this structure upon creation - need to free 
        pthread_mutex_destroy(&muxlock_queue);  //no longer required because no threads will be using queue and 'dispatch' will not add anymore elemnts
        
        report();       //method in 'analyse' used to output data collected during run
        exit(signo);
    }
}

void dispatch(struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {
    // TODO: Your part 2 code here
    // This method should handle dispatching of work to threads. At present
    // it is a simple passthrough as this skeleton is single-threaded.
    
    //create temporary structure before locking queue to prevent excessive wait time for anything else trying to use queue
    struct packet_queue_elem *tmp = malloc(sizeof(struct packet_queue_elem));   //the new packet to be queued
    tmp->next = NULL;       //this will be tail so the next element must be set to NULL
    tmp->header = header;
    tmp->packet = packet;
    tmp->verbose = verbose;
    
    while(pthread_mutex_trylock(&muxlock_queue));  //wait until the mutex is unlocked
    
    if(queue->head == NULL) {
        //queue is empty so the only element will be the new one, also head and tail at the same time
        queue->head = tmp;
        queue->tail = tmp;
        pthread_cond_signal(&added);    //signal threads that a packet has been added
    } else {
        //there are elements in queue, add to tail, then this will be the new tail
        queue->tail->next = tmp;
        queue->tail = queue->tail->next;
        pthread_cond_signal(&added);    //signal threads that a packet has been added
    }
    pthread_mutex_unlock(&muxlock_queue);    //unlock so that threads can use queue
}