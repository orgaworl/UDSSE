all:
	g++ ./UPE.cpp ./BloomFilter.cpp ./SRE.h ./main.cpp  -L. -lpbc -lgmp -lssl -lcrypto -o ../prog/main.bin
	../prog/main.bin
server: 
	g++ ./CS.cpp ./testServer.cpp -o ../prog/server.bin
	../prog/server.bin
client: 
	g++ ./CS.cpp ./testClient.cpp -o ../prog/client.bin
	../prog/client.bin
clean:
	rm ../prog/*.bin