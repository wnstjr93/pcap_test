#include <pcap.h>
#include <stdio.h>

int Mac_ad(const u_char *packet);

typedef struct ether_info
	{
		u_char Mac_dst[6];
		u_char Mac_src[6];
		u_char ether_type[2];
	}ether_info;

int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	
	
	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	// 1000=1->
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	//port 80.
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	/* Grab a packet */ //1000=1
	int i=0;
//	while(1) {
		pcap_next_ex(handle, &header ,&packet) ; //data in packet
		
		
		
		for(i=0;i<header->len;i++){
		printf("[%02x]",packet[i]);}
		i=Mac_ad(packet);
		/* And close the session */
//	}
	pcap_close(handle);
	return(0);
}
int Mac_ad(const u_char *packet)
{
	int i;
	ether_info *ether;
	ether=(ether_info *)packet;
	for(i = 0; i < 12; i++)
	{
	if(i==0)printf("Destination Mac_Adress: %02x ",ether->Mac_dst[i]);	
	else if(i==6) printf("\nSource Mac_Adress : %02X ",ether->Mac_src[i]);
	else printf(": %02x ",packet[i]);
	}
	

	return i;

}

/*(if[12]==0x08)&&(p[13]==0x00)*/


