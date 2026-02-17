CC ?= cc
CFLAGS ?= -Wall -Wextra -Wpedantic -Werror -std=c11
LDFLAGS ?=
LDLIBS = -lpcap

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

SRC = src/udpreplay.c
BIN = udpreplay

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(BIN)

install: $(BIN)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(BIN) $(DESTDIR)$(BINDIR)

.PHONY: all clean install
