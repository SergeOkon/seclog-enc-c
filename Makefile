CC=gcc
LD=ld
CFLAGS=-O2 -std=c99
LDLIBS=-lm

all: build/crypto test

build:
	mkdir build

build/curve25519-donna.o: build
	${CC} ${CFLAGS} -o build/curve25519-donna.o -c c/curve25519-donna.c 

build/aes.o: build
	${CC} ${CFLAGS} -o build/aes.o -c c/aes.c 

build/crypto.o: build
	${CC} ${CFLAGS} -o build/crypto.o -c c/crypto.c 

build/util.o: build
	${CC} ${CFLAGS} -o build/util.o -c c/util.c 

build/crypto: build/aes.o build/curve25519-donna.o build/crypto.o build/util.o
	${CC} ${CFLAGS} -o build/main.o -c c/main.c 
	${LD} ${LDLIBS} -o build/crypto build/curve25519-donna.o build/aes.o build/util.o build/crypto.o build/main.o

build/test: build/aes.o build/curve25519-donna.o build/crypto.o build/util.o
	${CC} ${CFLAGS} -o build/test.o -c test/test.c 
	${LD} ${LDLIBS} -o build/test build/curve25519-donna.o build/aes.o build/util.o build/crypto.o build/test.o

.PHONY: test
test: build/test
	#Running tests, check diff if errors occur...
	./build/test > ./test/results.txt
	diff ./test/expected.txt ./test/results.txt
	#Tests passed.

clean:
	rm -fr build test/results.txt
