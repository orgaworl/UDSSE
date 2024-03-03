# makefile
prog= ../prog/main.bin
lib= -L. -lpbc -lgmp -lssl -lcrypto
ob_PRF= ./PRF.cpp 
ob_UPE= ./UPE.cpp ./testUPE.cpp
ob_SRE= ./UPE.cpp ./BloomFilter.cpp ./SRE.cpp ./testSRE.cpp
ob_client= ./CS.cpp ./testClient.cpp
ob_server= ./CS.cpp ./testServer.cpp
ob_DSSE= ./UPE.cpp ./BloomFilter.cpp ./SRE.cpp ./DSSE.cpp ./testDSSE.cpp


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
DSSE:
	g++  $(ob_DSSE) -o $(prog) $(lib)
	$(prog)
server: 
	g++ $(ob_server) -o $(prog)
	$(prog)
client: 
	g++ $(ob_client) -o $(prog)
	$(prog)
clean:
	rm ../prog/*.bin