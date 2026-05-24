| lib_start.S - a314bsd bsdsocket.library startup
| GNU Assembler m68k Motorola syntax
|
| RTF_AUTOINIT is NOT used — exec's InitResident/MakeLibrary path caused
| a Line-1111 (#8000000B) exception on every test.  Instead rt_Init points
| directly to our Init function, which calls MakeLibrary and AddLibrary
| itself, then fills in our custom fields.

    .equ    VERSION,        4
    | Internally this is the v5.0 architectural rewrite (dispatcher task +
    | chunked-data streaming + one Wait per caller-task call), but VERSION
    | stays at 4 to preserve OpenLibrary compatibility for apps that asked
    | for V4 against the old codebase.  REVISION jumps to 50 to clearly
    | differentiate from the previous v4.42.
    .equ    REVISION,       53

    | exec/nodes.h
    .equ    LN_TYPE,        8
    .equ    LN_PRI,         9
    .equ    LN_NAME,        10

    | exec/libraries.h
    .equ    LIB_FLAGS,      14
    .equ    LIB_NEGSIZE,    16
    .equ    LIB_POSSIZE,    18
    .equ    LIB_VERSION,    20
    .equ    LIB_REVISION,   22
    .equ    LIB_IDSTRING,   24
    .equ    LIB_OPENCNT,    32

    .equ    LIBF_CHANGED,   2
    .equ    NT_LIBRARY,     9
    | RTF_AUTOINIT intentionally not set

    | BsdBase layout (struct Library = 34 bytes, then our fields)
    | See bsdsocket.c for the full C definition.
    .equ    bsdbase_SysBase,       34
    .equ    bsdbase_SegList,       38
    .equ    bsdbase_Sessions,      42  | MinList (12 bytes)
    .equ    bsdbase_NextSocketId,  54  | ULONG monotonic counter (offset 54)
    .equ    bsdbase_SIZEOF,        60  | rounded up from 58

    | v4.366: extend table to match Roadshow's full LVO range.
    | 4 std + 46 implemented + 87 stub = 137 entries, 137*6 = 822
    | Stubs return 0 / NULL so wget's feature-probe paths see "function failed,
    | fall back to legacy".  Without this any wget call past LVO -300 would
    | JSR into junk memory and crash.
    .equ    LIB_NEGSIZE_VAL,    822

    | exec LVO offsets — confirmed from pragmas/exec_pragmas.h
    | #pragma syscall MakeLibrary 54 ...   → LVO -0x54 = -84
    | #pragma syscall AddLibrary  18c ...  → LVO -0x18C = -396

    .text

| Safety: return -1 if accidentally executed directly
Start:
    moveq   #-1,d0
    rts
    .even

| ---- ROM tag ---------------------------------------------------------------
| RTF_AUTOINIT (bit 0 of rt_Flags) is CLEAR.
| rt_Init points to our Init function instead of an InitTable.
RomTag:
    .word   0x4AFC
    .long   RomTag
    .long   EndSkip
    .byte   0               | rt_Flags: NO RTF_AUTOINIT
    .byte   VERSION
    .byte   NT_LIBRARY
    .byte   0
    .long   LibName
    .long   IDString
    .long   Init            | rt_Init = manual init function

EndSkip:
    .even

LibName:
    .ascii  "bsdsocket.library"
    .byte   0
    .even

IDString:
    | NOTE: the AmigaDOS `version` command reads this string (not lib_Revision)
    | to report the version number, so the "4.NN" here MUST match REVISION above.
    .ascii  "a314bsd bsdsocket.library 4.53 (23.05.2026)"
    .byte   13,10,0
    .even

| Function table — used by MakeLibrary to build the JMP table.
| Standard: Open Close Expunge Null (LVO -6..-24)
| Socket:   socket .. GetSocketEvents (LVO -30..-300)  AmiTCP order.
FuncTable:
    .long   Open
    .long   Close
    .long   Expunge
    .long   Null
    | --- socket LVOs (-30 .. -300) in AmiTCP order ---
    .long   _bsd_socket             | -30
    .long   _bsd_bind               | -36
    .long   _bsd_listen             | -42
    .long   _bsd_accept             | -48
    .long   _bsd_connect            | -54
    .long   _bsd_sendto             | -60
    .long   _bsd_send               | -66
    .long   _bsd_recvfrom           | -72
    .long   _bsd_recv               | -78
    .long   _bsd_shutdown           | -84
    .long   _bsd_setsockopt         | -90
    .long   _bsd_getsockopt         | -96
    .long   _bsd_getsockname        | -102
    .long   _bsd_getpeername        | -108
    .long   _bsd_ioctlsocket        | -114
    .long   _bsd_closesocket        | -120
    .long   _bsd_waitselect         | -126
    .long   _bsd_setsocketsignals   | -132
    .long   _bsd_getdtablesize      | -138
    .long   _bsd_obtainsocket       | -144
    .long   _bsd_releasesocket      | -150
    .long   _bsd_releasecopyofsocket | -156
    .long   _bsd_errno              | -162
    .long   _bsd_seterrnoptr        | -168
    .long   _bsd_inet_ntoa          | -174
    .long   _bsd_inet_addr          | -180
    .long   _bsd_inet_lnaof         | -186
    .long   _bsd_inet_netof         | -192
    .long   _bsd_inet_makeaddr      | -198
    .long   _bsd_inet_network       | -204
    .long   _bsd_gethostbyname      | -210
    .long   _bsd_gethostbyaddr      | -216
    .long   _bsd_getnetbyname       | -222
    .long   _bsd_getnetbyaddr       | -228
    .long   _bsd_getservbyname      | -234
    .long   _bsd_getservbyport      | -240
    .long   _bsd_getprotobyname     | -246
    .long   _bsd_getprotobynumber   | -252
    .long   _bsd_vsyslog            | -258
    .long   _bsd_dup2socket         | -264
    .long   _bsd_sendmsg            | -270
    .long   _bsd_recvmsg            | -276
    .long   _bsd_gethostname        | -282
    .long   _bsd_gethostid          | -288
    .long   _bsd_socketbasetaglist  | -294
    .long   _bsd_getsocketevents    | -300
    | --- Roadshow LVOs -306..-822 stubbed to StubRetZero (87 entries) ---
    | These cover bpf_*, route mgmt, interface mgmt, netmonitor, DNS server
    | mgmt, *net*ent iterators, inet_aton/ntop/pton, mbuf_*, server APIs,
    | Roadshow data, gethostbyname_r, freeaddrinfo, getaddrinfo, gai_strerror,
    | getnameinfo, etc.  All return 0 so callers see "unsupported / failed".
    .long   StubRetZero | -306
    .long   StubRetZero | -312
    .long   StubRetZero | -318
    .long   StubRetZero | -324
    .long   StubRetZero | -330
    .long   StubRetZero | -336
    .long   StubRetZero | -342
    .long   StubRetZero | -348
    .long   StubRetZero | -354
    .long   StubRetZero | -360
    .long   StubRetZero | -366  bpf_open
    .long   StubRetZero | -372  bpf_close
    .long   StubRetZero | -378  bpf_read
    .long   StubRetZero | -384  bpf_write
    .long   StubRetZero | -390  bpf_set_notify_mask
    .long   StubRetZero | -396  bpf_set_interrupt_mask
    .long   StubRetZero | -402  bpf_ioctl
    .long   StubRetZero | -408  bpf_data_waiting
    .long   StubRetZero | -414  AddRouteTagList
    .long   StubRetZero | -420  DeleteRouteTagList
    .long   StubRetZero | -426
    .long   StubRetZero | -432  FreeRouteInfo
    .long   StubRetZero | -438  GetRouteInfo
    .long   StubRetZero | -444  AddInterfaceTagList
    .long   StubRetZero | -450  ConfigureInterfaceTagList
    .long   StubRetZero | -456  ReleaseInterfaceList
    .long   StubRetZero | -462  ObtainInterfaceList
    .long   StubRetZero | -468  QueryInterfaceTagList
    .long   StubRetZero | -474  CreateAddrAllocMessageA
    .long   StubRetZero | -480  DeleteAddrAllocMessage
    .long   StubRetZero | -486  BeginInterfaceConfig
    .long   StubRetZero | -492  AbortInterfaceConfig
    .long   StubRetZero | -498  AddNetMonitorHookTagList
    .long   StubRetZero | -504  RemoveNetMonitorHook
    .long   StubRetZero | -510  GetNetworkStatistics
    .long   StubRetZero | -516  AddDomainNameServer
    .long   StubRetZero | -522  RemoveDomainNameServer
    .long   StubRetZero | -528  ReleaseDomainNameServerList
    .long   StubRetZero | -534  ObtainDomainNameServerList
    .long   StubRetZero | -540  setnetent
    .long   StubRetZero | -546  endnetent
    .long   StubRetZero | -552  getnetent
    .long   StubRetZero | -558  setprotoent
    .long   StubRetZero | -564  endprotoent
    .long   StubRetZero | -570  getprotoent
    .long   StubRetZero | -576  setservent
    .long   StubRetZero | -582  endservent
    .long   StubRetZero | -588  getservent
    .long   StubRetZero | -594  inet_aton
    .long   StubRetZero | -600  inet_ntop
    .long   StubRetZero | -606  inet_pton
    .long   StubRetZero | -612  In_LocalAddr
    .long   StubRetZero | -618  In_CanForward
    .long   StubRetZero | -624  mbuf_copym
    .long   StubRetZero | -630  mbuf_copyback
    .long   StubRetZero | -636  mbuf_copydata
    .long   StubRetZero | -642  mbuf_free
    .long   StubRetZero | -648  mbuf_freem
    .long   StubRetZero | -654  mbuf_get
    .long   StubRetZero | -660  mbuf_gethdr
    .long   StubRetZero | -666  mbuf_prepend
    .long   StubRetZero | -672  mbuf_cat
    .long   StubRetZero | -678  mbuf_adj
    .long   StubRetZero | -684  mbuf_pullup
    .long   StubRetZero | -690  ProcessIsServer
    .long   StubRetZero | -696  ObtainServerSocket
    .long   StubRetZero | -702  GetDefaultDomainName
    .long   StubRetZero | -708  SetDefaultDomainName
    .long   StubRetZero | -714  ObtainRoadshowData
    .long   StubRetZero | -720  ReleaseRoadshowData
    .long   StubRetZero | -726  ChangeRoadshowData
    .long   StubRetZero | -732  RemoveInterface
    .long   StubRetZero | -738  gethostbyname_r
    .long   StubRetZero | -744  gethostbyaddr_r
    .long   StubRetZero | -750
    .long   StubRetZero | -756
    .long   StubRetZero | -762
    .long   StubRetZero | -768
    .long   StubRetZero | -774
    .long   StubRetZero | -780
    .long   StubRetZero | -786
    .long   StubRetZero | -792
    .long   StubRetZero | -798
    .long   StubRetZero | -804  freeaddrinfo
    .long   StubRetZero | -810  getaddrinfo
    .long   StubRetZero | -816  gai_strerror
    .long   StubRetZero | -822  getnameinfo
    .long   -1

    | C symbols
    .extern _bsd_open
    .extern _bsd_close_lib

    .extern _bsd_socket
    .extern _bsd_bind
    .extern _bsd_listen
    .extern _bsd_accept
    .extern _bsd_connect
    .extern _bsd_sendto
    .extern _bsd_send
    .extern _bsd_recvfrom
    .extern _bsd_recv
    .extern _bsd_shutdown
    .extern _bsd_setsockopt
    .extern _bsd_getsockopt
    .extern _bsd_getsockname
    .extern _bsd_getpeername
    .extern _bsd_ioctlsocket
    .extern _bsd_closesocket
    .extern _bsd_waitselect
    .extern _bsd_setsocketsignals
    .extern _bsd_getdtablesize
    .extern _bsd_obtainsocket
    .extern _bsd_releasesocket
    .extern _bsd_releasecopyofsocket
    .extern _bsd_errno
    .extern _bsd_seterrnoptr
    .extern _bsd_inet_ntoa
    .extern _bsd_inet_addr
    .extern _bsd_inet_lnaof
    .extern _bsd_inet_netof
    .extern _bsd_inet_makeaddr
    .extern _bsd_inet_network
    .extern _bsd_gethostbyname
    .extern _bsd_gethostbyaddr
    .extern _bsd_getnetbyname
    .extern _bsd_getnetbyaddr
    .extern _bsd_getservbyname
    .extern _bsd_getservbyport
    .extern _bsd_getprotobyname
    .extern _bsd_getprotobynumber
    .extern _bsd_vsyslog
    .extern _bsd_dup2socket
    .extern _bsd_sendmsg
    .extern _bsd_recvmsg
    .extern _bsd_gethostname
    .extern _bsd_gethostid
    .extern _bsd_socketbasetaglist
    .extern _bsd_getsocketevents

| ---- Init: called by exec InitResident with d0=segList, a6=ExecBase --------
| Responsible for: MakeLibrary → fill fields → AddLibrary → return libbase.
| exec preserves nothing except what we save; exec LVOs preserve d2-d7/a2-a7.
Init:
    movem.l d2-d7/a2-a6,-(sp)
    move.l  d0,d6               | d6 = segList (safe: exec LVOs preserve d2-d7)

    | MakeLibrary(funcInit/a0, structInit/a1, libInit/a2, posSize/d0, segList/d1)
    | libInit=NULL: we initialise fields ourselves below
    lea     FuncTable(pc),a0
    sub.l   a1,a1               | no struct data table
    sub.l   a2,a2               | no lib init callback
    move.l  #bsdbase_SIZEOF,d0
    move.l  d6,d1               | segList
    jsr     -84(a6)             | exec MakeLibrary → d0 = libbase or NULL

    move.l  d0,d5               | d5 = libbase (preserved across AddLibrary call)
    beq.s   .fail

    movea.l d5,a1               | a1 = libbase

    | Our custom fields
    move.l  a6,bsdbase_SysBase(a1)
    move.l  d6,bsdbase_SegList(a1)

    | MinList init: head → &tail, tail = NULL, tailpred → &head
    lea     bsdbase_Sessions(a1),a0
    lea     4(a0),a2
    move.l  a2,(a0)             | mlh_Head = &mlh_Tail
    clr.l   4(a0)               | mlh_Tail = NULL
    move.l  a0,8(a0)            | mlh_TailPred = &mlh_Head

    | Library node fields (MakeLibrary zeros the block; we fill what we need)
    move.b  #NT_LIBRARY,LN_TYPE(a1)
    lea     LibName(pc),a0
    move.l  a0,LN_NAME(a1)
    lea     IDString(pc),a0
    move.l  a0,LIB_IDSTRING(a1)
    move.b  #LIBF_CHANGED,LIB_FLAGS(a1)
    move.w  #VERSION,LIB_VERSION(a1)
    move.w  #REVISION,LIB_REVISION(a1)
    move.w  #LIB_NEGSIZE_VAL,LIB_NEGSIZE(a1)
    move.w  #bsdbase_SIZEOF,LIB_POSSIZE(a1)

    | AddLibrary(library/a1) — a1 already holds libbase
    | Save libbase on stack: belt-and-suspenders in case this Kickstart's
    | AddLibrary trashes d5 despite the RKRM guarantee.
    move.l  d5,-(sp)
    jsr     -396(a6)            | exec AddLibrary; d0/d1/a0/a1 trashed
    move.l  (sp)+,d0            | restore libbase as return value
    bra.s   .done

.fail:
    moveq   #0,d0
.done:
    movem.l (sp)+,d2-d7/a2-a6
    rts

| ---- Open: a6=libbase, d0=version ------------------------------------------
Open:
    movem.l d1-d7/a0-a5,-(sp)
    move.l  a6,-(sp)
    jsr     _bsd_open
    addq.l  #4,sp
    movem.l (sp)+,d1-d7/a0-a5
    | d0 = libbase or 0 from _bsd_open
    rts

| ---- Close: a6=libbase ------------------------------------------------------
Close:
    movem.l d1-d7/a0-a5,-(sp)
    move.l  a6,-(sp)
    jsr     _bsd_close_lib
    addq.l  #4,sp
    movem.l (sp)+,d1-d7/a0-a5
    moveq   #0,d0               | never expunge
    rts

| ---- Expunge ----------------------------------------------------------------
Expunge:
    moveq   #0,d0
    rts

| ---- Null -------------------------------------------------------------------
Null:
    moveq   #0,d0
    rts

| ---- StubRetZero -----------------------------------------------------------
| Used for all LVOs -306..-822 that we don't implement.  Returns 0/NULL in d0
| so callers see "function failed / returned nothing" and fall back to their
| legacy / non-Roadshow code path.  Preserves d2-d7/a2-a7 implicitly (no save
| needed since we touch nothing).
StubRetZero:
    moveq   #0,d0
    rts

| ---- GCC soft-division helpers ---------------------------------------------
|
| GCC -m68000 emits calls to __udivsi3 / __umodsi3 for 32÷32 unsigned
| division because the 68000 DIVU is only 32÷16.  The Amiga cross-compiler's
| libgcc deliberately omits these (it targets hand-written asm), so we
| supply them here.
|
| Calling convention — m68k-amigaos C ABI (stack, NOT register):
|   Arguments pushed right-to-left; caller pops after return.
|   [sp+4] = dividend (first arg), [sp+8] = divisor (second arg)
|   Returns: D0 = result.  Must preserve D2-D7 / A2-A7.
|
| Note: the GCC register-based helper ABI (D0/D1) is NOT used by
| m68k-amigaos-gcc 6.5.0b; it generates normal C stack calls.
|
| Algorithm: classic shift-subtract binary long division (32 iterations).
|   remainder = 0
|   for bit = 31 downto 0:
|     remainder = (remainder << 1) | bit[i](dividend)
|     if remainder >= divisor: remainder -= divisor; quotient |= (1<<i)
|
| Uses numeric local labels so they don't clash with anything else.

    .globl  ___udivsi3
___udivsi3:
    | [sp+4]=dividend, [sp+8]=divisor at entry
    movem.l d2/d3/d4,-(sp)     | save 12 bytes; args now at [sp+16],[sp+20]
    move.l  16(sp),d0           | d0 = dividend
    move.l  20(sp),d3           | d3 = divisor
    moveq   #0,d2               | d2 = remainder
    moveq   #0,d4               | d4 = quotient
    moveq   #31,d1              | d1 = bit counter 31..0 (dbra uses word part)
10:
    lsl.l   #1,d2               | remainder <<= 1
    btst    d1,d0               | test bit[d1] of dividend (d0 unchanged)
    beq     11f
    bset    #0,d2               | remainder |= 1
11:
    cmp.l   d3,d2               | remainder >= divisor?
    blo     12f
    sub.l   d3,d2               | remainder -= divisor
    bset    d1,d4               | quotient |= (1 << bit)
12:
    dbra    d1,10b
    move.l  d4,d0               | return quotient in d0
    movem.l (sp)+,d2/d3/d4
    rts

    .globl  ___umodsi3
___umodsi3:
    | [sp+4]=dividend, [sp+8]=divisor at entry
    movem.l d2/d3,-(sp)         | save 8 bytes; args now at [sp+12],[sp+16]
    move.l  12(sp),d0           | d0 = dividend
    move.l  16(sp),d3           | d3 = divisor
    moveq   #0,d2               | d2 = remainder
    moveq   #31,d1              | d1 = bit counter 31..0
13:
    lsl.l   #1,d2               | remainder <<= 1
    btst    d1,d0               | test bit[d1] of dividend (d0 unchanged)
    beq     14f
    bset    #0,d2               | remainder |= 1
14:
    cmp.l   d3,d2               | remainder >= divisor?
    blo     15f
    sub.l   d3,d2               | remainder -= divisor
15:
    dbra    d1,13b
    move.l  d2,d0               | return remainder in d0
    movem.l (sp)+,d2/d3
    rts
