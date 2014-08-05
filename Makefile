CC = gcc

all: ropchain libropchain.so

ropchain: main.c libropchain.so
	${CC} $< -L. -Wl,-rpath . -lropchain -o $@

libropchain.so: rop.c
	${CC} $< -fPIC -shared -Wall -lcapstone -o $@

clean:
	@rm ropchain libropchain.so
