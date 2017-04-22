AM_CXXFLAGS=-Wall -std=c++11
#AM_LDFLAGS=-L../lib/ 

check_PROGRAMS=TestAES 
TestAES_SOURCES=TestAES.cpp

TestAES_LDADD= ../lib/libaes.a -lpthread -lgtest_main -lgtest 
check: TestAES ../src/AES
	./TestAES

	python AEStestvectors.py > in.tmp
	../src/AES -e -k Acceptance1key.txt -i in.tmp -o acceptance1.enc
	../src/AES -d -k Acceptance1key.txt -i acceptance1.enc -o acceptance1.dec
	diff -i acceptance1.dec in.tmp

	../src/AES -e -k Acceptance1key.txt -i example_binary2 -o acceptance2.enc
	../src/AES -d -k Acceptance1key.txt -i acceptance2.enc -o acceptance2.dec
	diff -i acceptance2.dec example_binary2

clean:
	rm -rf *tmp* *.o TestAES Makefile *.enc *.dec
