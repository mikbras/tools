CFLAGS = -Wall -Werror
all:
	g++ $(CFLAGS) -o dups dups.cpp -llzma
	g++ $(CFLAGS) -o rmfiles rmfiles.cpp -llzma

clean:
	rm dups

install:
	mkdir -p $(HOME)/bin
	cp dups $(HOME)/bin/dups
	cp rmfiles $(HOME)/bin/rmfiles

prereqs:
	sudo apt install -y liblzma-dev
