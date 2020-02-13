CC=gcc
LD=ld
CFLAGS=-O2 -std=c99
LDLIBS=-lm


all: build/util

build:
	mkdir build

build/curve25519-donna.o: build
	${CC} ${CFLAGS} -o build/curve25519-donna.o -c c/curve25519-donna.c 

build/aes.o: build
	${CC} ${CFLAGS} -o build/aes.o -c c/aes.c 

build/crypto.o: build
	${CC} ${CFLAGS} -o build/crypto.o -c c/crypto.c 

build/util: build/aes.o build/curve25519-donna.o build/crypto.o
	${CC} ${CFLAGS} -o build/util.o -c c/util.c 
	${LD} ${LDLIBS} -o build/crypto build/curve25519-donna.o build/aes.o build/util.o build/crypto.o

clean:
	rm -fr build
