CXX=c++
CXXFLAGS=-std=c++11 -Wall -c -O2
LIBS=-lcrypto

all: openpgp.o fic.o main.o base64.o
	$(CXX) *.o $(LIBS) -o fic

openpgp.o: openpgp.cc openpgp.h
	$(CXX) $(CXXFLAGS) openpgp.cc

fic.o: fic.cc fic.h
	$(CXX) $(CXXFLAGS) fic.cc

main.o: main.cc
	$(CXX) $(CXXFLAGS) main.cc

base64.o: base64.cc base64.h
	$(CXX) $(CXXFLAGS) base64.cc

