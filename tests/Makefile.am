AM_CXXFLAGS=-Wall -std=c++11
#AM_LDFLAGS=-L../lib/ 

check_PROGRAMS=TestAES 
TestAES_SOURCES=TestAES.cpp

TestAES_LDADD= ../lib/libaes.a -lpthread -lgtest_main -lgtest 
check: TestAES ../src/AES
	./TestAES
	./AcceptanceTest1.sh
	./AcceptanceTest2.sh
	./AcceptanceTest3.sh

clean:
	rm -rf *tmp* *.o TestAES Makefile *.enc *.dec
