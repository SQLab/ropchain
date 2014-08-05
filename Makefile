LIBNAME = capstone

ropchain: rop.o
	${CC} $< main.c -O3 -Wall -l$(LIBNAME) -o $@

rop.o: rop.c
	${CC} -c $< -o $@

clean:
	rm ropchain rop.o
