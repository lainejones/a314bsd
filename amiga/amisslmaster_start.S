| amisslmaster_start.S — AmiSSL master loader library for a314bsd
| GNU Assembler m68k Motorola syntax
|
| amisslmaster.library is the standard AmiSSL 4.x entry point.
| Apps open this library, call InitAmiSSLMaster() to declare the API level
| they need, then call OpenAmiSSL() which opens amissl.library and returns
| its base pointer.  Apps use that base pointer (in a6) for all SSL calls.
|
| FD: amisslmaster_lib.fd  (##bias 30)
|
| LVO table (10 entries × 6 = 60 bytes):
|   slot  1 (LVO  -6): Open
|   slot  2 (LVO -12): Close
|   slot  3 (LVO -18): Expunge
|   slot  4 (LVO -24): Null
|   slot  5 (LVO -30): InitAmiSSLMaster(APIVersion,UsesOpenSSLStructs)(d0,d1)
|   slot  6 (LVO -36): OpenAmiSSL()()  → struct Library *
|   slot  7 (LVO -42): CloseAmiSSL()()
|   slot  8 (LVO -48): OpenAmiSSLCipher(Cipher)(d0)  → struct Library *
|   slot  9 (LVO -54): CloseAmiSSLCipher(CipherBase)(a0)
|   slot 10 (LVO -60): OpenAmiSSLTagList(APIVersion,tagList)(d0,a0) → LONG

    .equ    VERSION,        50
    .equ    REVISION,       0

    | exec/nodes.h
    .equ    LN_TYPE,        8
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

    | AmiSSLMasterBase layout (after standard 34-byte Library header):
    |   SysBase      offset 34  (4 bytes) — stored in Init from a6
    |   SegList      offset 38  (4 bytes)
    |   AmiSSLBase   offset 42  (4 bytes) — opened amissl.library base
    |   SIZEOF = 46
    .equ    masterbase_SysBase,     34
    .equ    masterbase_SegList,     38
    .equ    masterbase_AmiSSLBase,  42
    .equ    masterbase_SIZEOF,      46

    .equ    LIB_NEGSIZE_VAL,    60      | 10 entries × 6

    .text

| Safety — return -1 if executed directly
Start:
    moveq   #-1,d0
    rts
    .even

| ---- ROM tag ----------------------------------------------------------------
| RTF_AUTOINIT not set; Init handles everything manually.
RomTag:
    .word   0x4AFC                  | RTC_MATCHWORD
    .long   RomTag                  | rt_MatchTag
    .long   EndSkip                 | rt_EndSkip
    .byte   0                       | rt_Flags (no RTF_AUTOINIT)
    .byte   VERSION                 | rt_Version
    .byte   NT_LIBRARY              | rt_Type
    .byte   0                       | rt_Pri
    .long   LibName                 | rt_Name
    .long   IDString                | rt_IdString
    .long   Init                    | rt_Init

EndSkip:
    .even

LibName:
    .ascii  "amisslmaster.library"
    .byte   0
    .even

IDString:
    .ascii  "a314 AmiSSLmaster 50.1 build27 (29.05.2026)"
    .byte   13,10,0
    .even

| ---- Function table ---------------------------------------------------------
FuncTable:
    .long   Open                                | slot  1  LVO  -6
    .long   Close                               | slot  2  LVO -12
    .long   Expunge                             | slot  3  LVO -18
    .long   Null                                | slot  4  LVO -24
    .long   _ami_master_InitAmiSSLMaster        | slot  5  LVO -30  (pure stub, no exec call)
    .long   WrapOpenAmiSSL                      | slot  6  LVO -36  (calls OpenLibrary → wrap)
    .long   WrapCloseAmiSSL                     | slot  7  LVO -42  (calls CloseLibrary → wrap)
    .long   WrapOpenAmiSSLCipher                | slot  8  LVO -48  (Build 23: lazy-opens → wrap a6)
    .long   _ami_master_CloseAmiSSLCipher       | slot  9  LVO -54  (pure stub, void)
    .long   WrapOpenAmiSSLTagList               | slot 10  LVO -60  (calls OpenLibrary → wrap)
    .long   -1                                  | FuncTable terminator

| ---- a6-preserving wrappers for amisslmaster public API functions ----------
|
| OpenAmiSSL, CloseAmiSSL, and OpenAmiSSLTagList call exec library functions
| (OpenLibrary / CloseLibrary) internally.  The exec inline-asm stubs load
| a6 = SysBase before the JSR, so on return a6 no longer holds the caller's
| amisslmaster library base.  Without a wrapper, iBrowse's a6 is corrupted
| after the first call — exactly the same bug that was fixed for amissl.library
| (where _bsd_call* helpers load a6 = BsdBase before JSRing into bsdsocket).
|
| Pattern:  save a6 (= amisslmaster_base from iBrowse) before the C function,
|           restore it after.  The C function still receives the correct a6
|           because the wrapper does not modify a6 before the JSR.

WrapOpenAmiSSL:
    move.l  a6,-(sp)
    jsr     _ami_master_OpenAmiSSL
    move.l  (sp)+,a6
    rts

WrapCloseAmiSSL:
    move.l  a6,-(sp)
    jsr     _ami_master_CloseAmiSSL
    move.l  (sp)+,a6
    rts

WrapOpenAmiSSLTagList:
    move.l  a6,-(sp)
    jsr     _ami_master_OpenAmiSSLTagList
    move.l  (sp)+,a6
    rts

| Build 23: OpenAmiSSLCipher now lazily calls OpenLibrary, so it needs the same
| a6 save/restore as the others.
WrapOpenAmiSSLCipher:
    move.l  a6,-(sp)
    jsr     _ami_master_OpenAmiSSLCipher
    move.l  (sp)+,a6
    rts

| ---- C symbol declarations --------------------------------------------------
    .extern _ami_master_open
    .extern _ami_master_close
    .extern _ami_master_InitAmiSSLMaster
    .extern _ami_master_OpenAmiSSL
    .extern _ami_master_CloseAmiSSL
    .extern _ami_master_OpenAmiSSLCipher
    .extern _ami_master_CloseAmiSSLCipher
    .extern _ami_master_OpenAmiSSLTagList

| ---- Init: called by exec with d0=segList, a6=ExecBase ---------------------
Init:
    movem.l d2-d7/a2-a6,-(sp)
    move.l  d0,d6               | d6 = segList

    | MakeLibrary(funcInit/a0, structInit/a1=NULL, libInit/a2=NULL,
    |             posSize/d0, segList/d1)
    lea     FuncTable(pc),a0
    sub.l   a1,a1
    sub.l   a2,a2
    move.l  #masterbase_SIZEOF,d0
    move.l  d6,d1
    jsr     -84(a6)             | exec MakeLibrary

    move.l  d0,d5               | d5 = libbase or NULL
    beq.s   .fail

    movea.l d5,a1

    | Fill our custom fields
    move.l  a6,masterbase_SysBase(a1)
    move.l  d6,masterbase_SegList(a1)
    clr.l   masterbase_AmiSSLBase(a1)  | filled on first OpenAmiSSL()

    | Standard library node fields
    move.b  #NT_LIBRARY,LN_TYPE(a1)
    lea     LibName(pc),a0
    move.l  a0,LN_NAME(a1)
    lea     IDString(pc),a0
    move.l  a0,LIB_IDSTRING(a1)
    move.b  #LIBF_CHANGED,LIB_FLAGS(a1)
    move.w  #VERSION,LIB_VERSION(a1)
    move.w  #REVISION,LIB_REVISION(a1)
    move.w  #LIB_NEGSIZE_VAL,LIB_NEGSIZE(a1)
    move.w  #masterbase_SIZEOF,LIB_POSSIZE(a1)

    | AddLibrary(a1 = libbase)
    move.l  d5,-(sp)
    jsr     -396(a6)
    move.l  (sp)+,d0
    bra.s   .done

.fail:
    moveq   #0,d0
.done:
    movem.l (sp)+,d2-d7/a2-a6
    rts

| ---- Open -------------------------------------------------------------------
| Called by exec with a6 = library base, d0 = version requested.
| Returns library base in d0, or NULL on failure.
Open:
    movem.l d1-d7/a0-a5,-(sp)
    move.l  a6,-(sp)            | pass base as C stack argument
    jsr     _ami_master_open
    addq.l  #4,sp
    movem.l (sp)+,d1-d7/a0-a5
    | d0 = libbase from ami_master_open
    rts

| ---- Close ------------------------------------------------------------------
| Called with a6 = library base.  Returns 0 (never expunge).
Close:
    movem.l d1-d7/a0-a5,-(sp)
    move.l  a6,-(sp)
    jsr     _ami_master_close
    addq.l  #4,sp
    movem.l (sp)+,d1-d7/a0-a5
    moveq   #0,d0               | never expunge
    rts

| ---- Expunge / Null ---------------------------------------------------------
Expunge:
Null:
    moveq   #0,d0
    rts
