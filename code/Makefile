# makefile
prog= ../prog/main.bin
lib= -L. -lpbc -lgmp -lssl -lcrypto
ob_PRF= ./PRF.cpp 
ob_UPE= ./UPE.cpp ./testUPE.cpp
ob_SRE= ./UPE.cpp ./BloomFilter.cpp ./SRE.cpp ./testSRE.cpp
ob_UDSSE=  ./UPE.cpp ./BloomFilter.cpp ./PRF.cpp ./RSA.cpp ./SRE.cpp ./UDSSE.cpp 
ob_client= ./UPE.cpp ./BloomFilter.cpp ./PRF.cpp ./RSA.cpp ./SRE.cpp ./UDSSE.cpp ./CS.cpp ./testClient.cpp
ob_server= ./UPE.cpp ./BloomFilter.cpp ./PRF.cpp ./RSA.cpp ./SRE.cpp ./UDSSE.cpp ./CS.cpp ./testServer.cpp



test:
	g++ ./test.cpp -o $(prog)
	$(prog)
PRF:
	g++ $(ob_PRF) -o $(prog) $(lib)
	$(prog)
UPE:./UPE.cpp ./testUPE.cpp
	g++  $^ -o $(prog) $(lib)
	$(prog)
SRE:
	g++  $(ob_SRE) -o $(prog) $(lib)
	$(prog)
UDSSE:
	clear
	g++  $(ob_UDSSE) -o $(prog) $(lib) -w
	
server: 
	clear
	g++ $(ob_server) -o ./server.bin $(lib) -w
	./server.bin
client: 
	clear
	g++ $(ob_client) -o ./client.bin $(lib) -w
	./client.bin
cs:
	clear
	g++ $(ob_server) -o server.bin $(lib) -w
	g++ $(ob_client) -o client.bin $(lib) -w

clean:
	rm ../prog/*.bin