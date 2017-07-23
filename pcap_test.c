#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h> //ipproto_tcp
#include <netinet/if_ether.h> //ethernet_type...
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>//inet..
#include <ctype.h> //fixed for broken string

#define HTTP_TEMP 1500
#define ETHER_SIZE 14


int Mac_ad(const u_char *packet);
int Ip_ad(const u_char *packet);
int Port_ad(const u_char *packet,int ip_l);
void Http_put(const u_char *packet,int ip_l,int po_l);

typedef struct ether_info
{
	u_char Mac_dst[6];
	u_char Mac_src[6];
	uint16_t ether_type;
}ether_info;

typedef struct ip_info
{
	u_char Ip_version:4;
	u_char Head_len:4;
	u_char Tos;
	uint16_t Total_len;
	uint16_t Iden;
	uint16_t frag;
	u_char ttl;
	u_char ip_protocol;
	u_char Header_Checksum[2];
	struct in_addr Ip_src;
	struct in_addr Ip_dst;
}ip_info;


typedef struct Port_info
{
	uint16_t Port_src;
	uint16_t Port_dst;
	u_char unused[4];
	u_char tcp_hlen:4;
}Port_info;

typedef struct Http_info
{
	
	u_char Http_text[HTTP_TEMP];
}Http_info;



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
	int ip_l,po_l;				/* ether->ip->tcp->http flag */

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	/*my dum0 using ~~~~~*/
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
	while(1) {
		pcap_next_ex(handle, &header ,&packet) ; //data in packet
		printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n*****Packet binary*****");
		for(int i=0;i<header->len;i++){
			if(i%8==0||i==header->len)printf("\n");
			printf("%02x ",packet[i]);
		}
		
		/*MAIN FUNCTION*/
		Mac_ad(packet);
		ip_l=Ip_ad(packet);
		po_l=Port_ad(packet,ip_l);
		Http_put(packet,ip_l,po_l);
	}
	pcap_close(handle);
	return(0);
}
/*Mac_ADDRESS - ETHERNET PART*/
int Mac_ad(const u_char *packet)
{	
	
		int i;
		ether_info *ether;
		ether=(ether_info *)packet;
		uint16_t M_ether_type;
		M_ether_type=ntohs(ether->ether_type);//big->little endian

			printf("\n******ether packet******\n");
			for(i = 0; i < 12; i++)
			{
				if(i==0)printf("Dst Mac_Adress : %02x ",ether->Mac_dst[i]);	
				else if(i==6) printf("\nSrc Mac_Adress : %02X ",ether->Mac_src[i]);
				else printf(": %02x ",packet[i]);
			}
			//printf("\nnext protocol :%03x\n",M_ether_type);
			printf("\n************************\n");
		
			if(M_ether_type!=ETHERTYPE_IP){
				printf("Is this not IP PROTOCOL?\n");
				exit(0);}
			else return 0;//i=i+12;// wait..

}
/*IP ADDRESS - IP PART*/
int Ip_ad(const u_char *packet)
{
	ip_info *ip;
	ip=(ip_info *)(packet+ETHER_SIZE);//structure point
	u_char Header_len;
	u_char M_Ip_protocol;
	M_Ip_protocol=(ip->ip_protocol);
	char buf[20];


	printf("*********ip packet*********\n");
	inet_ntop(AF_INET,&(ip->Ip_src),buf,sizeof(buf));
	printf("Src Ip_Address : %s",buf);
	inet_ntop(AF_INET,&(ip->Ip_dst),buf,sizeof(buf));
	printf("\nDst Ip_Address : %s",buf);///
	//	printf("Src Ip_Address : %s",inet_ntoa(ip->Ip_src));//
	//	printf("\nDst Ip_Address : %s",inet_ntoa(ip->Ip_dst));///
		
	//}
	Header_len=4*(ip->Head_len);
	printf("ip_len:%d\n",Header_len);
	printf("\n***************************\n");
	if(M_Ip_protocol!=IPPROTO_TCP){ 
		printf("Is this not TCP??\n");
		exit(0);}
	else return Header_len;

}
/*TCP_PORT NUMBER - TCP PART*/
int Port_ad(const u_char *packet, int ip_l)
{
	u_char TCP_len;
	Port_info *Port;
	Port=(Port_info *)(packet+ip_l+ETHER_SIZE);
	TCP_len=4*(Port->tcp_hlen);
	printf("tcp len: %d\n", TCP_len);
	printf("*********Port  address******\n");
	uint16_t Ps=ntohs(Port->Port_src);
	uint16_t Pd=ntohs(Port->Port_dst);
	
	printf("Src Port : %d\n",Ps);
	printf("Dst Port : %d\n",Pd);
	printf("********HTTP_TEXT************\n");
	return TCP_len;
}
/*HTTP_CONTENT - HTTP PART*/
void Http_put(const u_char *packet,int ip_l,int po_l)
{

	uint16_t Http_len;
	uint16_t Ip_total;
	Http_info *Http; // of course can use array
    Http=(Http_info *)(packet+ETHER_SIZE+ip_l+po_l);	
	ip_info *Ip;
	Ip=(ip_info *)(packet+ETHER_SIZE);
	Ip_total=ntohs(Ip->Total_len); //if val have 2byte~~ MUST USE 'ntohs'

	Http_len=Ip_total-(ip_l+po_l);
	
	printf("Ip_total:%d\n",Ip_total);
	printf("ip_l+po_l:%d\n",ip_l+po_l);
	printf("ht_len:%d\n",Http_len);
	if(Ip_total>Http_len){
	for(int i=0;i<Http_len;i++)if(isascii(Http->Http_text[i]))putchar(Http->Http_text[i]);
	}
	else printf("How can it be longer than the total?\n");
	//if(isprint(Http->Http_text[i]))
	printf("\n********HTTP_END**********\n");
}

//1. main local_variable , 2.struct in struct
