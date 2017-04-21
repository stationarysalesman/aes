AM_CXXFLAGS=-Wall -std=c++11
#AM_LDFLAGS=-L../lib/ 

check_PROGRAMS=TestAES 
TestAES_SOURCES=TestAES.cpp

TestAES_LDADD= ../lib/libaes.a -lpthread -lgtest_main -lgtest 
check: TestAES ../src/AES
	./TestAES

	python AEStestvectors.py > in.tmp
	../src/AES e Acceptance1key.txt in.tmp
	../src/AES d Acceptance1key.txt in.tmp.enc
	diff -i in.tmp.enc.dec in.tmp

clean:
	rm -rf *tmp* *.o TestAES Makefile
