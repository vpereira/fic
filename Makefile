CXX=c++
CXXFLAGS=-std=c++11 -Wall -c -O2 -fPIC -pedantic
#CXXFLAGS+=-fsanitize=address

LFLAGS=
#LFLAGS+=-fsanitize=address
LIBS=-lcrypto

all: fic libfic.so

fic: openpgp.o fic.o main.o base64.o
	$(CXX) $(LFLAGS) $^ $(LIBS) -o $@

clean:
	rm -f *.o

openpgp.o: openpgp.cc openpgp.h
	$(CXX) $(CXXFLAGS) $<

fic.o: fic.cc fic.h
	$(CXX) $(CXXFLAGS) $<

main.o: main.cc
	$(CXX) $(CXXFLAGS) $<

base64.o: base64.cc base64.h
	$(CXX) $(CXXFLAGS) $<

libfic.so: binding.cc binding.h fic.o base64.o openpgp.o
	$(CXX) $(CXXFLAGS) $<
	$(CXX) $(LFLAGS) -shared -Wl,-soname=libfic.so binding.o fic.o base64.o openpgp.o $(LIBS) -o $@

