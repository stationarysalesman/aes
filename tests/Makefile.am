AM_CXXFLAGS=-Wall -std=c++11
#AM_LDFLAGS=-L../lib/ 

check_PROGRAMS=TestAES
TestAES_SOURCES=TestAES.cpp
TestAES_LDADD= ../lib/libaes.a -lpthread -lgtest_main -lgtest 
check: TestAES
	./TestAES

