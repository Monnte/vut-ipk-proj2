CC = g++
CFLAGS  = -Werror -Wextra -pedantic
RM = rm -rf

TARGET = main
OUTPUT = ipk-sniffer


all: $(TARGET)

$(TARGET): $(TARGET).cpp
	$(CC) $(CFLAGS) -c $(TARGET).cpp -lpcap
	$(CC) $(CFLAGS) -o $(OUTPUT) $(TARGET).o -lpcap

clean:
	$(RM) $(OUTPUT)
	$(RM) *.o