LDLIBS += -lpcap

all: pcap-test

pcap-test: libnet.h pcap-test.c

clean:
	rm -f pcap-test *.o
