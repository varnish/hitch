all: stud

stud: stud.c
	gcc -O2 -g -std=c99 -fno-strict-aliasing -Wall -W -I/usr/local/include -L/usr/local/lib -I. -o stud ringbuffer.c stud.c -D_GNU_SOURCE -lssl -lcrypto -lev

# The -shared targets use shared memory between child processes
# for the SSL session cache--potentially a huge performance gain
# for large stud deployments with many children
ebtree/libebtree.a: ebtree/*.c
	make -C ebtree

ebtree: ebtree/libebtree.a
	@echo "Please download libebtree at http://1wt.eu/tools/ebtree/ untar it. and create a symbolik link named 'ebtree' to point on it"

stud-shared: stud.c shctx.c ebtree/libebtree.a
	gcc -O2 -g -std=c99 -fno-strict-aliasing -Wall -W -I/usr/local/include -L/usr/local/lib -Lebtree -I. -DUSE_SHARED_CACHE -o stud ringbuffer.c shctx.c stud.c -D_GNU_SOURCE -lssl -lcrypto -lev -lpthread -lebtree

stud-shared-futex: stud.c shctx.c
	gcc -O2 -g -std=c99 -fno-strict-aliasing -Wall -W -I/usr/local/include -L/usr/local/lib -Lebtree -I. -DUSE_SHARED_CACHE -DUSE_SYSCALL_FUTEX -o stud ringbuffer.c shctx.c stud.c -D_GNU_SOURCE -lssl -lcrypto -lev -lebtree

install: stud
	cp stud /usr/local/bin

clean:
	rm -f stud *.o
