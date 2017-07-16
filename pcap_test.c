#include <pcap.h>
#include <stdio.h>

int Mac_ad(const u_char *packet);
int Ip_ad(const u_char *packet,int i);


typedef struct ether_info
	{
		u_char Mac_dst[6];
		u_char Mac_src[6];
		short ether_type;
	}ether_info;

typedef struct ip_info
	{
		u_char Ip_version:4;
		u_char Head_len:4;
		short Ip_len;
		u_char Ip_dst[4];
		u_char Ip_src[4];
	}ip_info;



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
	int i;				/* ether->ip->tcp->http flag */
	
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
//	while(1) {
		pcap_next_ex(handle, &header ,&packet) ; //data in packet
		
		
		
		for(i=0;i<header->len;i++){
		if(i%8==0||i==header->len)printf("\n");
		printf("%02x ",packet[i]);}
		i=Mac_ad(packet);
		Ip_ad(packet,i);
		/* And close the session */
//	}
	pcap_close(handle);
	return(0);
}
/*Mac_address - ethernet part*/
int Mac_ad(const u_char *packet)
{
	int i;
	ether_info *ether;
	ether=(ether_info *)packet;
	short M_ether_type;
	printf("\n******ether packet******\n");
	for(i = 0; i < 12; i++)
	{
	if(i==0)printf("Dst Mac_Adress : %02x ",ether->Mac_dst[i]);	
	else if(i==6) printf("\nSrc Mac_Adress : %02X ",ether->Mac_src[i]);
	else printf(": %02x ",packet[i]);
	}
	M_ether_type=ntohs(ether->ether_type);//big->little endian
	printf("\nnext protocol :%03x\n",M_ether_type);
	printf("******ether packet******\n");
	return i+10;

}
/*IP_address - Ip part*/
int Ip_ad(const u_char *packet,int i)
{
	int k=i+8;
	ip_info *ip;
	ip=(ip_info *)packet;
	printf("\n*********ip packet******\n");
	for(i;i<k;i++)
	{
	if(i==(k-8))printf("Dst Ip_Address : %3d",ip->Ip_dst[i]);
	else if(i==(k-4)) printf("\nSrc Ip_Address : %3d ",ip->Ip_src[i]);
	else printf(".%3d ",packet[i]);
	}
	i=k-8;
	for(i;i<k;i++)
	{
	printf("%02x ",ip->Ip_dst[i]);
	}
	printf("\n*********ip packet******\n");
	return i;

}
/*(if[12]==0x08)&&(p[13]==0x00)*/


