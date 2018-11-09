GPP=g++
GCC=gcc

OUTFILE="../Release/samp_akm.so"

COMPILE_FLAGS=--verbose -c -m32 -O3 -fPIC -w -DLINUX -Wall -ISDK/amx

all:
	$(GPP) $(COMPILE_FLAGS) SDK/*.cpp
	$(GPP) $(COMPILE_FLAGS) *.cpp
	$(GPP) --verbose -m32 -O2 -fshort-wchar -shared -o $(OUTFILE) *.o 
	rm -f *.o
