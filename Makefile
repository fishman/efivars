CFLAGS=-lpthread ./libunistring.a

all:
	$(CC) $(CFLAGS) -o test dmpstore.c createmxml.c mxml/*.c

clean:
	rm *.o
