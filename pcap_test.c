#include <pcap.h>
#include <stdio.h>

void Mac_ad(const u_char *packet);

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
	//(caplen) , (ts)
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
	// - header
	//packet
	//
	//pcap_next_ex(handle, &header, &packet);
	int i=0;
//	while(1) {
		pcap_next_ex(handle, &header ,&packet) ; //data in packet
		/* Print its length */
		for(i=0;i<header->len;i++){
		printf("[%02x]",packet[i]);}
		for(i=0;i<12;i++){
			printf("%02x ",packet[i]);}
		Mac_ad(packet);
		//printf("Jacked a packet with length of [%x]\n", header->len);
		/* And close the session */
//	}
	pcap_close(handle);
	return(0);
}
void Mac_ad(const u_char *packet)
{
	for(int i = 0; i < 12; i++)
	{
	if(i==0)printf("Destination Mac_Adress: %02x ",packet[i]);	
	else if(i==6) printf("\nSource Mac_Adress : %02X ",packet[i]);
	else printf(":%02x ",packet[i]);
	}
}
/*(if[12]==0x08)&&(p[13]==0x00)*/


