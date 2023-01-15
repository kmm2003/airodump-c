LDLIBS += -lpcap

all:airodump

airodump:  airodump.o main.o airodump.h
	g++ -g airodump.o main.o -o $@ -lncurses ${LDLIBS}  

airodump.o : airodump.h airodump.cpp 
	$(CC) -g -c -o $@ airodump.cpp 

main.o: airodump.h main.cpp 
	$(CC) -g -c -o $@ main.cpp

clean:
	rm -f airodump *.o