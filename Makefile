CFLAGS = -Wall -Werror
all:
	g++ $(CFLAGS) -o dups dups.cpp -lcrypto

clean:
	rm dups

install:
	mkdir -p $(HOME)/bin
	cp dups $(HOME)/bin/dups
