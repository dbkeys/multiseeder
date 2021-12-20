CXXFLAGS = -O3 -g0
LDFLAGS = $(CXXFLAGS)

multiseed: dns.o bitcoin.o netbase.o protocol.o db.o main.o util.o
	g++ -pthread $(LDFLAGS) -o multiseed dns.o bitcoin.o netbase.o protocol.o db.o main.o util.o -lcrypto -lcurl -lconfig++ -lncurses

%.o: %.cpp *.h
	g++ -std=c++11 -pthread $(CXXFLAGS) -Wall -Wno-unused -Wno-sign-compare -Wno-reorder -Wno-comment -c -o $@ $<
