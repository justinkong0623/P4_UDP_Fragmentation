#include <stdlib.h>
#include <pif_plugin.h>
#include <pif_plugin_metadata.h>
#include <pif_common.h>
#include <memory.h>
#include <string.h>
#include <stdint.h>
#include <nfp.h>
#define SEM_COUNT 256
    
__declspec(shared scope(global) export imem aligned(64)) int min_id = 0;
__declspec(shared scope(global) export imem aligned(64)) uint32_t  max_seq = 0;

__declspec(local_mem) int now_id = 0;
__declspec(local_mem) uint32_t  now_seq = 0;
__declspec(ctm export aligned(64)) long long int my_data = 0;

//__declspec(imem export aligned(64)) int global_semaphores[SEM_COUNT] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

__declspec(shared scope(global) export imem aligned(64)) int global_semaphores[1] = {1};
// Just for debugging.
//__declspec(shared scope(global) export imem aligned(64)) long long int global_counters[SEM_COUNT];


void semaphore_down(volatile __declspec(mem addr40) void * addr) {
	/* semaphore "DOWN" = claim = wait */
	unsigned int addr_hi, addr_lo;
    int i=0;
	__declspec(read_write_reg) int xfer;
	 SIGNAL_PAIR my_signal_pair;
	addr_hi = ((unsigned long long int)addr >> 8) & 0xff000000;
	addr_lo = (unsigned long long int)addr & 0xffffffff;
	do {
		xfer = 1;
		__asm {
            mem[test_subsat, xfer, addr_hi, <<8, addr_lo, 1],\
                sig_done[my_signal_pair];
            ctx_arb[my_signal_pair]
        }
        
        if(min_id==0 || min_id-now_id>1000 || now_id-min_id>1000 ){

            min_id=now_id;
           // max_seq=now_seq;
        
        }else if(min_id==now_id){

            __asm {
             mem[incr, --, addr_hi, <<8, addr_lo, 1];
            }
            __asm {
            mem[test_subsat, xfer, addr_hi, <<8, addr_lo, 1],\
                sig_done[my_signal_pair];
            ctx_arb[my_signal_pair]
            }
           // min_seq=now_seq;
              
                min_id=now_id;

        }else {
             sleep(1000);
        }
	} while (xfer == 0);
}

void semaphore_up(volatile __declspec(mem addr40) void * addr) {
	/* semaphore "UP" = release = signal */
	unsigned int addr_hi, addr_lo;
	__declspec(read_write_reg) int xfer;
	addr_hi = ((unsigned long long int)addr >> 8) & 0xff000000;
	addr_lo = (unsigned long long int)addr & 0xffffffff;

    /*__asm {
        mem[incr, --, addr_hi, <<8, addr_lo, 1];
    }*/
    min_id+=1;

}

// lock a semaphore based on an ID in the metadata.
int pif_plugin_lock_sem(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *data){
    // Get the ID of the semaphore to lock from the packet header.
    __declspec(local_mem) int sem_sid;
    PIF_PLUGIN_ipv4_T *ipv4_header;
  //  PIF_PLUGIN_tcp_T *tcp_header ;
    sem_sid = (int)pif_plugin_meta_get__mymeta__sid(headers);
    
    ipv4_header = pif_plugin_hdr_get_ipv4(headers);
	
    now_id = PIF_HEADER_GET_ipv4___identification(ipv4_header);

    
  //  tcp_header= pif_plugin_hdr_get_tcp(headers);
  //  now_seq = PIF_HEADER_GET_tcp___seqNum(tcp_header);
	

    
    // Lock that semaphore.
    semaphore_down( &global_semaphores[sem_sid]);
    
    return PIF_PLUGIN_RETURN_FORWARD;
}
// Release a semaphore based on an ID in the metadata.
int pif_plugin_release_sem(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *data){
    // Get the ID of the semaphore to lock from the packet header.
    // Would like to store this in metadata, but..
    __declspec(local_mem) int sem_sid;
    sem_sid = (int)pif_plugin_meta_get__mymeta__sid(headers);
   /* ipv4_header = pif_plugin_hdr_get_ipv4(headers);
	
    now_id = PIF_HEADER_GET_ipv4___identification(ipv4_header);
    min_id=now_id;*/
    // Release that semaphore.
    semaphore_up( &global_semaphores[sem_sid]);


    return PIF_PLUGIN_RETURN_FORWARD;
}


int pif_plugin_slept(EXTRACTED_HEADERS_T *headers,
                             MATCH_DATA_T *match_data)
{   int i;
    for(i=0;i<10;i++)
    {
    sleep(10000000);}
    //slep();
   // __nfp_meid(island, me_num);
    //i=island;

    return PIF_PLUGIN_RETURN_FORWARD;
}
