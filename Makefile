all : pcap_test

pcap_test: main.o
	g++ -g -o pcap_test main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -rf pcap_test
	rm -rf *.o
