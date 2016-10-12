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

install: dnsleak
	$(shell [ -z "$$PREFIX" ] && PREFIX=/usr; target="$$PREFIX/bin/dnsleak"; cp dnsleak "$$target" && echo "@echo Installed as '$$target'")
	@:

uninstall:
	$(shell [ -z "$$PREFIX" ] && PREFIX=/usr; target="$$PREFIX/bin/dnsleak"; rm "$$PREFIX/bin/dnsleak" && echo "@echo Uninstalled '$$target'")
	@:
