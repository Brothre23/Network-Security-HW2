CC = gcc
LIB = -lssl -lcrypto

all: server client

clean:
	@rm -rf ./newfile/*
	@rm -rf ./client
	@rm -rf ./server
	@rm -rf ./*.dSYM

server: server.c
	$(CC) server.c -o server $(LIB)

client: client.c
	$(CC) client.c -o client $(LIB)