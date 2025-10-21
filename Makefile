CFLAGS = -Wall -Werror
all:
	g++ $(CFLAGS) -o dups dups.cpp -lcrypto -llzma

clean:
	rm dups

install:
	mkdir -p $(HOME)/bin
	cp dups $(HOME)/bin/dups

prereqs:
	sudo apt install -y liblzma-dev
