SRC= \
	AES.cpp
OBJ= \
	AES.o
DEPS= \
	RijndaelConstants.h
CXX=g++
CXX_FLAGS=-std=c++11

%.o: %.c $(DEPS)
	$(CXX) -c -o $@ $< $(CXX_FLAGS)

AES: $(OBJ)
	$(CXX) -o $@ $^ $(CXX_FLAGS)

.PHONY: clean

clean:
	rm -f *.o *.tmp
 
