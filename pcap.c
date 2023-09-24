#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

#include "myheader.h"


void got_packet(u_char *args, const struct pcap_pkthdr *header,
		const u_char *packet)
{
	struct ethheader *eth = (struct ethheader *)packet;

	printf("Source MAC address: %02x-%02x-%02x-%02x-%02x-%02x\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
	printf("Destination MAC address: %02x-%02x-%02x-%02x-%02x-%02x\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

	if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
		struct ipheader * ip = (struct ipheader *)
			(packet + sizeof(struct ethheader)); 

		printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));   
		printf("         To: %s\n", inet_ntoa(ip->iph_destip));    

		/* determine protocol */
		switch(ip->iph_protocol) {                                 
			case IPPROTO_TCP:
				printf("   Protocol: TCP\n");
				struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl*4));
				printf("   Source Port: %d\n", ntohs(tcp->tcp_sport));
				printf("   Destination Port: %d\n", ntohs(tcp->tcp_dport));

				int payload_size = ntohs(ip->iph_len) - (ip->iph_ihl*4) - (TH_OFF(tcp)*4);
				u_char *payload = (u_char *)(packet + sizeof(struct ethheader) + (ip->iph_ihl*4) + (TH_OFF(tcp)*4));

				printf("======Payload======\n");
				for(int i = 0; i < payload_size; i++) {
					printf("%c", payload[i]);
				}
				printf("\n\n");
				return;
			case IPPROTO_UDP:
				printf("   Protocol: UDP\n");
				return;
			case IPPROTO_ICMP:
				printf("   Protocol: ICMP\n");
				return;
			default:
				printf("   Protocol: others\n");
				return;
		}
	}
}

int main()
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "tcp";
	bpf_u_int32 net;

	// Step 1: Open live pcap session on NIC with name enp0s3
	handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

	// Step 2: Compile filter_exp into BPF psuedo-code
	pcap_compile(handle, &fp, filter_exp, 0, net);
	if (pcap_setfilter(handle, &fp) !=0) {
		pcap_perror(handle, "Error:");
		exit(EXIT_FAILURE);
	}

	// Step 3: Capture packets
	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle);   //Close the handle
	return 0;
}


