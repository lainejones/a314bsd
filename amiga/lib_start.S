| lib_start.S - a314bsd bsdsocket.library startup
| GNU Assembler m68k Motorola syntax
|
| RTF_AUTOINIT is NOT used — exec's InitResident/MakeLibrary path caused
| a Line-1111 (#8000000B) exception on every test.  Instead rt_Init points
| directly to our Init function, which calls MakeLibrary and AddLibrary
| itself, then fills in our custom fields.

    .equ    VERSION,        4
    .equ    REVISION,       9

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

    | 4 standard funcs + 46 socket LVOs = 50 total, 50*6 = 300
    .equ    LIB_NEGSIZE_VAL,    300

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
    .ascii  "a314bsd bsdsocket.library 4.9 (21.05.2026)"
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
