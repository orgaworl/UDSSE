UPE:
	g++ ./UPE.cpp ./testUPE.cpp  -L. -lpbc -lgmp -lssl -lcrypto -o ../prog/main.bin
	../prog/main.bin
server: 
	g++ ./CS.cpp ./testServer.cpp -o ../prog/server.bin
	../prog/server.bin
client: 
	g++ ./CS.cpp ./testClient.cpp -o ../prog/client.bin
	../prog/client.bin
PRF:
	g++ ./PRF.cpp -o ../prog/PRF.bin -L. -lpbc -lgmp -lssl -lcrypto 
	echo "\n\n"
	../prog/PRF.bin
SRE:
	g++ ./UPE.cpp ./BloomFilter.cpp ./SRE.cpp ./testSRE.cpp -o ../prog/SRE.bin -L. -lpbc -lgmp -lssl -lcrypto 
	echo "\n\n"
	../prog/SRE.bin
clean:
	rm ../prog/*.bin