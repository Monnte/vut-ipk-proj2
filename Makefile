OBJS=obj/main.o obj/packet.o obj/sniffer.o
HEADERS=src/main.h src/packet.h src/sniffer.h
CC=g++
CFLAGS=-Wall -Wextra -pedantic -lpcap -Wno-unused-variable -Wno-unused-parameter
BINARY=ipk-sniffer


obj/%.o: src/%.cpp $(HEADERS)
	@mkdir -p obj
	$(CC) -c $< -o $@ $(CFLAGS)


$(BINARY): $(OBJS)
	$(CC) $^ -o $@ $(CFLAGS)


all: $(BINARY)

clean:
	rm -rf obj/
	rm -f $(BINARY)

