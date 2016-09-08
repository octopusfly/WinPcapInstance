#include <stdio.h>
#include <stdlib.h>
#define HAVE_REMOTE
#include <pcap.h>

#define ETHER_ADDR_LEN 6 		/* ethernet address. */
#define ETHERTYPE_IP 0x0800 	/* ip protocol. */
#define TCP_PROTOCAL 0x0600 	/* tcp protocol. */
#define BUFFER_MAX_LENGTH 65536 /* buffer max length. */
#define TRUE 1  				/* define true. */
#define FALSE 0 				/* define false. */

/*
 * define struct of ethernet header , ip address , ip header and tcp header.
 */
 
/* ethernet header */
typedef struct ether_header {
    u_char ether_shost[ETHER_ADDR_LEN]; /* source ethernet address, 6 bytes. */
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination ethernet addresss, 6 bytes. */
    u_short ether_type;                 /* ethernet type, 2 bytes. */
}ether_header;

/* four bytes ip address */
typedef struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* ipv4 header */
typedef struct ip_header {
    u_char ver_ihl;         /* version and ip header length. */
    u_char tos;             /* type of service. */
    u_short tlen;           /* total length. */
    u_short identification; /* identification. */
    u_short flags_fo;       /* flags and fragment offset. */
    u_char ttl;             /* time to live. */
    u_char proto;           /* protocol. */
    u_short crc;            /* header checksum. */
    ip_address saddr;       /* source address. */
    ip_address daddr;       /* destination address. */
    u_int op_pad;           /* option and padding. */
}ip_header;

/* tcp header */
typedef struct tcp_header {
    u_short th_sport;         /* source port. */
    u_short th_dport;         /* destination port. */
    u_int th_seq;             /* sequence number. */
    u_int th_ack;             /* acknowledgement number. */
    u_short th_len_resv_code; /* datagram length and reserved code. */
    u_short th_window;        /* window. */
    u_short th_sum;           /* checksum. */
    u_short th_urp;           /* urgent pointer. */
}tcp_header;

int main(void) {
	pcap_if_t *alldevs; // list of alldevices.
	pcap_if_t *d; 		// device you choose.
	
	pcap_t *adhandle;
	
	char errbuf[PCAP_ERRBUF_SIZE];
	int i = 0;
	int inum;
	
	struct pcap_pkthdr *pheader; /* packet header. */
	const u_char *pkt_data; 	 /* packet data. */
	int res;
	
	/* pcap_findalldevs_ex got something wrong. */
	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, /* auth is not needed. */
		&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);		
	}
	
	/* print the list of all devices */
	for(d = alldevs; d != NULL; d = d->next) {
		/* print device name, which starts with rpcap:// */
		printf("%d.%s", ++i, d->name); 
		
		if(d->description) {
			printf(" (%s)\n", d->description);
		} else {
			printf(" (No description available)\n");
		}
	} 
	
	/* no interfaces found. */
	if(i == 0) {
		printf("\nNo interfaces found! Make sure Winpcap is installed.\n");
		return -1;
	}
	
	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);
	
	if(inum < 1 || inum > i) {
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* jump to the selected interface. */
	for(d = alldevs, i = 0; i < inum - 1; i++, d = d->next);
	
	/* opent the selected interface. */
	if((adhandle = pcap_open(
		d->name, 	// the interface name.
		65536, 		// length of packet that has to be retained. 
		PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode.
		1000, 		// read time-out.		
		NULL, 		// auth.
		errbuf 		// error buffer.
	)) == NULL) {
		fprintf(stderr, "\nUnable to open the adapter."
			"%s is not supported by Winpcap.\n", d->description);
		return -1;
	}
	
	printf("\nListenting on %s...\n", d->description);
	
	pcap_freealldevs(alldevs);
	
	/* capture packet */
	while((res = pcap_next_ex(adhandle, &pheader, &pkt_data)) >= 0) {
		if(res == 0) {
			continue; /* read timeout. */
		}
		
		/* transform packet data to ethernet header */
		ether_header *eheader = (ether_header*) pkt_data;
		
		if(eheader->ether_type == htons(ETHERTYPE_IP)) { /* ip packet only. */ 
			ip_header *ih = (ip_header*) (pkt_data + 14); /* get ip header. */			
			if(ih->proto == htons(TCP_PROTOCAL)) { /* tcp packet only. */
				/* get ip length, it contains header and body. */
				int ip_len = ntohs(ih->tlen); 
				
				int find_http = FALSE;
				char* ip_pkt_data = (char*)ih;
				int n = 0;
				char buffer[BUFFER_MAX_LENGTH];
				int bufsize = 0;
				
				for(; n < ip_len; n++) {
					/* http get or post request. */
				 	if(!find_http && 
				 	((n + 3 < ip_len 
						&& strncmp(ip_pkt_data + n, "GET", strlen("GET")) ==0)
       				|| (n + 4 < ip_len 
			   			&& strncmp(ip_pkt_data + n, "POST", strlen("POST")) == 0))) {
				   		find_http = TRUE;			
		   			}
					
					/* http response. */
					if(! find_http && 
						n + 8 < ip_len &&
						strncmp(ip_pkt_data + n, "HTTP/1.1", strlen("HTTP/1.1")) == 0) {
						find_http = TRUE;		
					}
					
					/* if http is found. */	
					if(find_http) {
						/* copy http data to buffer. */
						buffer[bufsize] = ip_pkt_data[n]; 
						bufsize++;
					}	
				}
				
				/* print http content. */
				if(find_http) {
					buffer[bufsize] = '\0';
					printf("%s\n", buffer);
					printf("\n**********************************************\n\n");
				} 
			}
		}
	} 
	
	return 0;
}
