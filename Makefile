.PHONY: default clean install uninstall

NDPI_LIB=./nDPI/lib/libndpi.a

default: dnsleak

dnsleak: names_count.o ndpi_util.o dnsleak.c $(NDPI_LIB)
	gcc -Wall -O2 -I./nDPI/src/include -L./nDPI/lib -lpcap -lpthread -lanl $^ -o $@

ndpi_util.o: $(NDPI_LIB)
ndpi_util.o: ndpi_util.c ndpi_util.h
	gcc -Wall -O2 -I./nDPI/src/include $^ -c

names_count.o: names_count.c
	gcc -Wall -O2 $^ -c

$(NDPI_LIB):
	git clone https://github.com/ntop/nDPI.git; \
	cd nDPI; \
	git checkout 6fd334dcd77f12f22870d81be2c0a14231e6edea; \
	./autogen.sh; \
	make

clean:
	rm -f dnsleak
	rm -f *.o
	rm -rf ./nDPI

install: PREFIX ?= /usr
install: dnsleak
	mkdir -p "$(DESTDIR)$(PREFIX)/bin"
	cp ./dnsleak "$(DESTDIR)$(PREFIX)/bin"

uninstall: PREFIX ?= /usr
uninstall:
	rm "$(DESTDIR)$(PREFIX)/bin/dnsleak"
