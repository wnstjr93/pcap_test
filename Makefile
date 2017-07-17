all: pcap_test

pcap_test: pcap_test.c
		gcc -lpcap pcap_test.c
clean:
		rm *.out
