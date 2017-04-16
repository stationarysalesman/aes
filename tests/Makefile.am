AM_CXXFLAGS=-Wall -std=c++11
AM_LDFLAGS=-pthread -lgtest_main -lgtest

check_PROGRAMS=TestAES
TestAES_SOURCES=TestAES.cpp 
TestAES_LDADD=../lib/libaes.a 

check: TestAES
	./TestAES
