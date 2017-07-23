all: pcap_test

pcap_test: pcap_test.c
		gcc -o pcap_test pcap_test.c -lpcap

pcap_modi: pcap_modi.c
		gcc -lpacp pcap_modi.c
clean:
		rm pcap_test | rm *.out


		
