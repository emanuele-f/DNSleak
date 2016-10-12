.PHONY: default clean install uninstall

default: dnsleak

dnsleak: names_count.o ndpi_util.o dnsleak.c
	gcc -Wall -O2 `pkg-config --cflags libndpi --libs libndpi` -lpcap -lpthread -lanl $^ -o $@

ndpi_util.o: ndpi_util.c ndpi_util.h
	gcc -Wall -O2 `pkg-config --cflags libndpi --libs libndpi` -lpcap $^ -c

names_count.o: names_count.c
	gcc -Wall -O2 $^ -c

clean:
	rm -f dnsleak
	rm -f *.o

install: PREFIX ?= /usr
install: dnsleak
	mkdir -p "$(DESTDIR)$(PREFIX)/bin"
	cp ./dnsleak "$(DESTDIR)$(PREFIX)/bin"

uninstall: PREFIX ?= /usr
uninstall:
	rm "$(DESTDIR)$(PREFIX)/bin/dnsleak"
