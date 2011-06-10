all: stud

stud: stud.c
	gcc -O2 -g -std=c99 -fno-strict-aliasing -Wall -W -I/usr/local/include -L/usr/local/lib -I. -o stud ringbuffer.c stud.c -D_GNU_SOURCE -lssl -lcrypto -lev

install: stud
	cp stud /usr/local/bin

clean:
	rm -f stud *.o
