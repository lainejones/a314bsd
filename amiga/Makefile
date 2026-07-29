CC     = m68k-amigaos-gcc
CFLAGS = -m68000 -O2 -nostartfiles -nostdlib -fomit-frame-pointer \
         -I../include \
         -I../include/netinclude \
         -I../../A314RTG/a314-1.2.3/Software/a314device

TARGET  = bsdsocket.library
OBJS    = lib_start.o bsdsocket.o


TESTCC  = m68k-amigaos-gcc
TESTCFLAGS = -m68000 -O2 \
         -I../include \
         -I../include/netinclude \
         -I../../A314RTG/a314-1.2.3/Software/a314device

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -m68000 -nostartfiles -nostdlib -o $@ $(OBJS)

lib_start.o: lib_start.S
	$(CC) -m68000 -c -o $@ $<

bsdsocket.o: bsdsocket.c
	$(CC) $(CFLAGS) -c -o $@ $<

test_bsd: test_bsd.c
	$(TESTCC) $(TESTCFLAGS) -o $@ $<

bsdnet: bsdnet.c
	$(TESTCC) $(TESTCFLAGS) -o $@ $<

# fd-allocation churn regression test (fd_set overflow fix)
fdchurn: fdchurn.c
	$(TESTCC) $(TESTCFLAGS) -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET) test_bsd bsdnet fdchurn
