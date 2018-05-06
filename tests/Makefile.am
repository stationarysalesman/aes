AM_CXXFLAGS=-Wall -std=c++11
#AM_LDFLAGS=-L../lib/ 

check_PROGRAMS=TestAES TestThroughput 
TestAES_SOURCES=TestAES.cpp
TestThroughput_SOURCES=TestThroughput.cpp

TestAES_LDADD= ../lib/libaes.a -lpthread -lgtest_main -lgtest 
check: TestAES ../src/aes
	./TestAES
	./AcceptanceTest1.sh
	./AcceptanceTest2.sh
	./AcceptanceTest3.sh
	./AcceptanceTest4.sh

throughput: TestThroughput ../src/aes
	./TestThroughput

clean: TestAES.cpp
	rm -rf *tmp* *.o TestAES *.enc *.dec
