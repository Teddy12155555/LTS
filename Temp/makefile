all: Server Client
CC = gcc

Server: server.c 
	$(CC) -o Server server.c -lcrypto -lssl

Client: client.c 
	$(CC) -o Client client.c -lcrypto -lssl