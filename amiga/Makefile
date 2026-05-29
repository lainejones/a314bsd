CC     = m68k-amigaos-gcc
CFLAGS = -m68000 -O2 -nostartfiles -nostdlib -fomit-frame-pointer \
         -I../include \
         -I../include/netinclude \
         -I../../A314RTG/a314-1.2.3/Software/a314device

TARGET  = bsdsocket.library
OBJS    = lib_start.o bsdsocket.o

# AmiSSL shim libraries — SSL extension (TLS offloaded to the Pi)
AMISSL_OBJS = amissl_start.o amissl.o
MASTER_OBJS = amisslmaster_start.o amisslmaster.o


TESTCC  = m68k-amigaos-gcc
TESTCFLAGS = -m68000 -O2 \
         -I../include \
         -I../include/netinclude \
         -I../../A314RTG/a314-1.2.3/Software/a314device

all: $(TARGET) amissl.library amisslmaster.library

$(TARGET): $(OBJS)
	$(CC) -m68000 -nostartfiles -nostdlib -o $@ $(OBJS)

lib_start.o: lib_start.S
	$(CC) -m68000 -c -o $@ $<

# Unity build: bsdsocket_main.c #includes bsdsocket.c (unchanged) + bsd_ssl_stubs.c,
# so the SSL LVO stubs share the translation unit and can call bsdsocket.c statics.
bsdsocket.o: bsdsocket_main.c bsdsocket.c bsd_ssl_stubs.c
	$(CC) $(CFLAGS) -c -o $@ bsdsocket_main.c

# ---- AmiSSL shim libraries -------------------------------------------------
amissl.library: $(AMISSL_OBJS)
	$(CC) -m68000 -nostartfiles -nostdlib -o $@ $(AMISSL_OBJS)
amissl_start.o: amissl_start.S
	$(CC) -m68000 -c -o $@ $<
amissl.o: amissl.c
	$(CC) $(CFLAGS) -c -o $@ $<

amisslmaster.library: $(MASTER_OBJS)
	$(CC) -m68000 -nostartfiles -nostdlib -o $@ $(MASTER_OBJS)
amisslmaster_start.o: amisslmaster_start.S
	$(CC) -m68000 -c -o $@ $<
amisslmaster.o: amisslmaster.c
	$(CC) $(CFLAGS) -c -o $@ $<

test_bsd: test_bsd.c
	$(TESTCC) $(TESTCFLAGS) -o $@ $<

bsdnet: bsdnet.c
	$(TESTCC) $(TESTCFLAGS) -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET) $(AMISSL_OBJS) $(MASTER_OBJS) \
	      amissl.library amisslmaster.library test_bsd bsdnet
