SRC= \
	AES.cpp \
	RunAES.cpp

OBJ= \
	AES.o \
	RunAES.o

DEPS= \
	Rijndael.h

CXX=g++

CXX_FLAGS=-std=c++11

%.o: %.cpp
	$(CXX) $(CXX_FLAGS) -c -o $@ $< 

AES: $(OBJ)
	$(CXX) $(CXX_FLAGS) -o $@ $^ 

.PHONY: clean

clean:
	rm -f *.o *.tmp
 
