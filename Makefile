CC = gcc

C_DIRS += ./

CFLAGS = -lssl -lcrypto -lpthread

all: client

client: client.o
	gcc $^ -o $@ $(CFLAGS)

clean: 
	rm client.o