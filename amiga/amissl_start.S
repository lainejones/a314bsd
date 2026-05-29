| amissl_start.S — AmiSSL compatibility shim for a314bsd
| GNU Assembler m68k Motorola syntax
|
| LVO table verified against the real AmiSSL SDK FD file:
|   AmiSSL/Developer/fd/amissl_lib.fd  (amissl_v11_lib.fd, OpenSSL 1.1.x)
|   Source: C:\projects\AmiSSL\amissl-master\include\fd\amissl_lib.fd
|
| Total FuncTable entries: 5452
| LIB_NEGSIZE_VAL = 5452 * 6 = 32712
|
| Implemented functions and their verified LVOs:
|   ERR_get_error              LVO  -3960  slot  660
|   ERR_peek_error             LVO  -3978  slot  663
|   ERR_clear_error            LVO  -4014  slot  669
|   ERR_error_string           LVO  -4020  slot  670
|   SSL_CTX_set_cipher_list    LVO  -8202  slot 1367
|   SSL_CTX_new                LVO  -8208  slot 1368
|   SSL_CTX_free               LVO  -8214  slot 1369
|   SSL_pending                LVO  -8352  slot 1392
|   SSL_set_fd                 LVO  -8358  slot 1393
|   SSL_CTX_get_verify_mode    LVO  -8682  slot 1447
|   SSL_CTX_get_verify_callback LVO -8694  slot 1449
|   SSL_CTX_set_verify         LVO  -8700  slot 1450
|   SSL_new                    LVO  -8784  slot 1464
|   SSL_free                   LVO  -8820  slot 1470
|   SSL_connect                LVO  -8832  slot 1472
|   SSL_read                   LVO  -8838  slot 1473
|   SSL_write                  LVO  -8850  slot 1475
|   SSL_ctrl                   LVO  -8856  slot 1476  (handles SNI via cmd=55)
|   SSL_CTX_ctrl               LVO  -8868  slot 1478
|   SSL_get_error              LVO  -8880  slot 1480
|   SSL_get_version            LVO  -8886  slot 1481
|   SSL_shutdown               LVO  -8994  slot 1499
|   SSL_CTX_set_default_verify_paths  LVO -9168  slot 1528
|   SSL_CTX_load_verify_locations     LVO -9174  slot 1529
|   SSL_get_SSL_CTX            LVO  -9192  slot 1532
|   SSL_get_info_callback      LVO  -9204  slot 1534
|   SSL_get_verify_result      LVO  -9222  slot 1537
|   SSL_CTX_set_ex_data        LVO  -9264  slot 1544  (store app data; was stub→crash)
|   SSL_CTX_get_ex_data        LVO  -9270  slot 1545  (retrieve app data; 0→deref crash)
|   SSL_CTX_get_ssl_method     LVO -24216  slot 4036  (returns (SSL_METHOD*)1; NULL→crash)
|   SSL_CTX_set_options        LVO -26682  slot 4447
|   TLS_client_method          LVO -26934  slot 4489
|   TLS_method                 LVO -26940  slot 4490
|   OpenSSL_version_num        LVO -24966  slot 4161
|   OPENSSL_init_ssl           LVO -26568  slot 4428  (returns 1; was stubbed 0 → iBrowse abort)
|   SSL_CTX_new_ex             LVO -32370  slot 5395  (AmiSSL5: SSL_CTX_new → SSL_CTX_new_ex)
|   SSL_CTX_get_info_callback  LVO -19398  slot 3233  (PROBE_52; NULL→iBrowse calls through→crash)
|   SSL_CTX_sess_get_get_cb    LVO -19386  slot 3231  (build5; GETTER; was NULL→crash)
|   SSL_CTX_get_client_cert_cb LVO -19422  slot 3237  (build5; GETTER; was NULL→crash)
|   SSL_CTX_sess_get_remove_cb LVO -19428  slot 3238  (build5; GETTER; was NULL→crash)
|   SSL_CTX_get_default_passwd_cb          LVO -27558  slot 4593  (PROBE_52; NULL→crash)
|   SSL_CTX_get_default_passwd_cb_userdata LVO -27564  slot 4594  (PROBE_52; NULL→crash)
|   X509_STORE_get_verify      LVO -28776  slot 4796  (PROBE_52; NULL→crash)
|   X509_STORE_get_verify_cb   LVO -28782  slot 4797  (PROBE_52; NULL→JSR 0→#80000004 CRASH!)
|
|   BIO_new                    LVO  -1728  slot  288  (PROBE_R; BIO_new after DNS → crash?)
|   BIO_ctrl                   LVO  -1782  slot  297  (PROBE_S; BIO_do_connect/get_ssl after DNS?)
|   BIO_new_connect            LVO  -2070  slot  345  (PROBE_Q; TCP connect BIO after DNS)
|   BIO_f_ssl                  LVO  -8166  slot 1361  (PROBE_M; returns non-NULL sentinel)
|   BIO_new_ssl                LVO  -8172  slot 1362  (PROBE_N; returns non-NULL sentinel)
|   BIO_new_ssl_connect        LVO  -8178  slot 1363  (PROBE_O; if fired = BIO path is crash site)
|   BIO_new_buffer_ssl_connect LVO  -8184  slot 1364  (PROBE_P; returns non-NULL sentinel)
|   SSL_CTX_get_cert_store     LVO  -8232  slot 1372  (returns non-NULL fake store; NULL → crash)
|   SSL_get_current_cipher     LVO  -8262  slot 1377  (returns dummy non-NULL)
|   SSL_CIPHER_get_bits        LVO  -8268  slot 1378  (returns 256)
|   SSL_CIPHER_get_version     LVO  -8274  slot 1379  (returns "TLSv1.3")
|   SSL_CIPHER_get_name        LVO  -8280  slot 1380  (returns cipher name)
|   SSL_get_version            LVO  -8886  slot 1481  (returns "TLSv1.3")
|   SSL_get_verify_callback    LVO  -8418  slot 1403  (non-NULL sentinel; was NULL→crash)
|   OpenSSL_version            LVO -24960  slot 4160  (returns version strings)
|
| Note: SSLv23_client_method / SSLv23_method are NOT in the FD file;
|       they are header-level #define aliases for TLS_client_method /
|       TLS_method in AmiSSL 4.x — no separate LVO entry needed.
|
| All other LVO slots (5413 entries) → StubRetZero (returns 0/NULL).
| Slots 4491-5452 cover AmiSSL 5+ / OpenSSL 3.x functions (mostly stubbed).
| iBrowse 3.0 calls some of these; without them the CPU reads past the JMP
| table into garbage memory and executes F-line opcodes → #8000000B crash.
|
| SSL_set_tlsext_host_name is a C macro expanding to SSL_ctrl(s, 55, 0, name).
| We implement SSL_ctrl at slot 1476 and detect cmd==55 there.

    .equ    VERSION,        50
    .equ    REVISION,       0

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

    | AmiSSLBase layout:
    |   struct Library = 34 bytes (standard)
    |   SysBase        = offset 34, 4 bytes
    |   SegList        = offset 38, 4 bytes
    |   BsdBase        = offset 42, 4 bytes  (bsdsocket.library base)
    |   SIZEOF         = 48
    .equ    amisslbase_SysBase, 34
    .equ    amisslbase_SegList, 38
    .equ    amisslbase_BsdBase, 42
    .equ    amisslbase_SIZEOF,  48

    | 5453 FuncTable entries × 6 bytes each = 32718
    | AmiSSL FD file (amissl-master): 4840 public functions, last at LVO -32718 (slot 5453)
    | iBrowse 3.0 uses AmiSSL 5+ (OpenSSL 3.x) and may call functions up to that slot.
    | Slots beyond our implemented functions use StubRetZero (return 0/NULL safely).
    .equ    LIB_NEGSIZE_VAL, 32712

    .text

| Safety — return -1 if executed directly
Start:
    moveq   #-1,d0
    rts
    .even

| ---- ROM tag ---------------------------------------------------------------
| RTF_AUTOINIT not set; Init handles everything manually.
RomTag:
    .word   0x4AFC              | RTC_MATCHWORD
    .long   RomTag              | rt_MatchTag
    .long   EndSkip             | rt_EndSkip
    .byte   0                   | rt_Flags (no RTF_AUTOINIT)
    .byte   VERSION             | rt_Version
    .byte   NT_LIBRARY          | rt_Type
    .byte   0                   | rt_Pri
    .long   LibName             | rt_Name
    .long   IDString            | rt_IdString
    .long   Init                | rt_Init

EndSkip:
    .even

LibName:
    .ascii  "amissl.library"
    .byte   0
    .even

IDString:
    .ascii  "a314 AmiSSL shim 50.1 build38 (29.05.2026)"
    .byte   13,10,0
    .even

| ---- Function table --------------------------------------------------------
| Entries are 32-bit function addresses; exec MakeLibrary converts each
| to a 6-byte JMP instruction.  Terminator = -1 (0xFFFFFFFF).
|
| Each slot N → LVO -(N*6).  Slot 1 = LVO -6 (Open), slot 4489 = LVO -26934.
FuncTable:
    | Slots 1-4 (LVO -6 to -24): standard exec library entries
    .long   Open                            | slot    1  LVO    -6
    .long   Close                           | slot    2  LVO   -12
    .long   Expunge                         | slot    3  LVO   -18
    .long   Null                            | slot    4  LVO   -24

    | Slot 5 (LVO -30): InternalInitAmiSSL (##private in FD — stub OK)
    .long   StubRetZero

    | Slot 6 (LVO -36): InitAmiSSLA(tagList)(a0) — returns 0 on success (AmiSSL 4/5).
    | Build 19: now wrapped so the 0xFB00 probe doesn't corrupt a6.
    .long   WrapInitAmiSSLA

    | Slot 7 (LVO -42): CleanupAmiSSLA(tagList)(a0) — no-op
    .long   _ami_CleanupAmiSSLA

    | Slots 8-35 (LVO -48 to -210): stubs (28 entries)
    .rept   28
    .long   StubRetZero
    .endr

    | Slot 36 (LVO -216): ASN1_STRING_length → strlen(g_last_sni) (AWeb CN hostname check)
    .long   _ami_ASN1_STRING_length

    | Slots 37-38 (LVO -222 to -228): stubs (2 entries)
    .rept   2
    .long   StubRetZero
    .endr

    | Slot 39 (LVO -234): ASN1_STRING_data → g_last_sni (cert CN = SNI host)
    .long   _ami_ASN1_STRING_data

    | Slots 40-287 (LVO -240 to -1722): stubs (248 entries)
    | (28 + 1 + 2 + 1 + 248 = 280, the original count.)
    .rept   248
    .long   StubRetZero
    .endr

    | Slot 288 (LVO -1728): BIO_new(type)(a0) → BIO* (PROBE_R)
    | iBrowse may call BIO_new(BIO_s_connect()) to create a TCP BIO after DNS.
    | If PROBE_R fires after op=16, this is the crash path.
    .long   _ami_BIO_new

    | Slots 289-291 (LVO -1734 to -1746): gap, BIO_free, BIO_vfree — stubs
    .rept   3
    .long   StubRetZero
    .endr

    | Slot 292 (LVO -1752): BIO_read(b,data,len)(a0,a1,d0) → LONG
    | Proxies through g_bio_ssl_id after BIO_do_connect succeeds.
    | Called via WrapBIORead to preserve a6 around bsdsocket SSL_read call.
    .long   WrapBIORead

    | Slot 293 (LVO -1758): BIO_gets — stub
    .long   StubRetZero

    | Slot 294 (LVO -1764): BIO_write(b,data,len)(a0,a1,d0) → LONG
    | Proxies through g_bio_ssl_id after BIO_do_connect succeeds.
    | Called via WrapBIOWrite to preserve a6 around bsdsocket SSL_write call.
    .long   WrapBIOWrite

    | Slots 295-296 (LVO -1770 to -1776): BIO_puts, BIO_indent — stubs
    .rept   2
    .long   StubRetZero
    .endr

    | Slot 297 (LVO -1782): BIO_ctrl(bp,cmd,larg,parg)(a0,d0,d1,a1) → LONG
    | Handles: cmd=100 (set_conn_hostname), cmd=10 (do_connect: DNS+TCP+SSL),
    |          cmd=110 (get_ssl: return ssl_id), cmd=11 (flush: nop).
    | Called via WrapBIOCtrl to preserve a6 (AmiSSLBase) around bsdsocket calls.
    .long   WrapBIOCtrl

    | Slots 298-344 (LVO -1788 to -2064): stubs (47 entries)
    .rept   47
    .long   StubRetZero
    .endr

    | Slot 345 (LVO -2070): BIO_new_connect(host_port)(a0) → BIO* (PROBE_Q)
    | iBrowse creates a TCP connect BIO after DNS resolution.
    | If PROBE_Q fires after op=16 in Pi log, this is the crash site.
    .long   _ami_BIO_new_connect

    | Slots 346-659 (LVO -2076 to -3954): stubs (314 entries)
    .rept   314
    .long   StubRetZero
    .endr

    | Slot 660 (LVO -3960): ERR_get_error
    .long   _ami_ERR_get_error

    | Slots 661-662 (LVO -3966 to -3972): stubs (2 entries)
    .rept   2
    .long   StubRetZero
    .endr

    | Slot 663 (LVO -3978): ERR_peek_error
    .long   _ami_ERR_peek_error

    | Slots 664-668 (LVO -3984 to -4008): stubs (5 entries)
    .rept   5
    .long   StubRetZero
    .endr

    | Slot 669 (LVO -4014): ERR_clear_error
    .long   _ami_ERR_clear_error

    | Slot 670 (LVO -4020): ERR_error_string
    .long   _ami_ERR_error_string

    | Slots 671-1360 (LVO -4026 to -8160): stubs (690 entries)
    | FIX: was 691 (slots 671-1361) — one extra stub shifted BIO_f_ssl through
    | SSL_CTX_get_ex_data all 6 bytes too high.  SSL_CTX_new at LVO -8208 was
    | displaced to LVO -8214, so iBrowse's JSR -8208(a6) hit SSL_CTX_set_cipher_list
    | (which returned 1) instead of creating a real Pi-side SSL_CTX.
    .rept   690
    .long   StubRetZero
    .endr

    | Slot 1361 (LVO -8166): BIO_f_ssl() → SSL BIO method (PROBE_M)
    | Returning NULL here crashes iBrowse when it dereferences bio->method
    .long   _ami_BIO_f_ssl

    | Slot 1362 (LVO -8172): BIO_new_ssl(ctx,client)(a0,d0) → BIO* (PROBE_N)
    .long   _ami_BIO_new_ssl

    | Slot 1363 (LVO -8178): BIO_new_ssl_connect(ctx)(a0) → BIO* (PROBE_O)
    | iBrowse may use this to create a BIO-based SSL connection after gethostbyname.
    | Build 17: now fires PROBE 0xC001 via _bsd_call1d → REQUIRES WrapBIONewSslConnect
    | to restore a6 (AmiSSLBase) after the bsdsocket call corrupts it.
    .long   WrapBIONewSslConnect

    | Slot 1364 (LVO -8184): BIO_new_buffer_ssl_connect(ctx)(a0) → BIO* (PROBE_P)
    .long   _ami_BIO_new_buffer_ssl_connect

    | Slots 1365-1366 (LVO -8190 to -8196): BIO_ssl_copy_session_id, BIO_ssl_shutdown — stubs
    .rept   2
    .long   StubRetZero
    .endr

    | Slot 1367 (LVO -8202): SSL_CTX_set_cipher_list
    | Build 19: wrapped so 0xF008 probe doesn't corrupt a6.
    .long   WrapSSLCTXSetCipherList

    | Slot 1368 (LVO -8208): SSL_CTX_new  (wrapped: restores a6)
    | FD verified: ##bias 8124 → RAND_poll at slot 1354; +14 entries = slot 1368
    .long   WrapSSLCTXNew

    | Slot 1369 (LVO -8214): SSL_CTX_free  (wrapped: restores a6)
    .long   WrapSSLCTXFree

    | Slots 1370-1371 (LVO -8220, -8226): SSL_CTX_set_timeout, SSL_CTX_get_timeout — stubs
    .rept   2
    .long   StubRetZero
    .endr

    | Slot 1372 (LVO -8232): SSL_CTX_get_cert_store — returns fake non-NULL store
    | iBrowse calls this after SSL_CTX_new to add CA certs; NULL return causes crash
    | Build 19: wrapped so 0xF004 probe doesn't corrupt a6.
    .long   WrapSSLCTXGetCertStore

    | Slots 1373-1376 (LVO -8238 to -8256): SSL_CTX_set_cert_store, SSL_want,
    |   SSL_clear, SSL_CTX_flush_sessions — stubs
    .rept   4
    .long   StubRetZero
    .endr

    | Slot 1377 (LVO -8262): SSL_get_current_cipher — returns non-NULL dummy
    .long   _ami_SSL_get_current_cipher

    | Slot 1378 (LVO -8268): SSL_CIPHER_get_bits — returns 256
    .long   _ami_SSL_CIPHER_get_bits

    | Slot 1379 (LVO -8274): SSL_CIPHER_get_version — returns "TLSv1.3"
    .long   _ami_SSL_CIPHER_get_version

    | Slot 1380 (LVO -8280): SSL_CIPHER_get_name — returns cipher name string
    .long   _ami_SSL_CIPHER_get_name

    | Slots 1381-1391 (LVO -8286 to -8346): stubs (11 entries)
    .rept   11
    .long   StubRetZero
    .endr

    | Slot 1392 (LVO -8352): SSL_pending
    | FD verified: ##bias 8316 → SSL_get_fd at slot 1386; +6 entries = slot 1392
    .long   _ami_SSL_pending

    | Slot 1393 (LVO -8358): SSL_set_fd  (wrapped: restores a6)
    .long   WrapSSLSetFd

    | Slots 1394-1402 (LVO -8364 to -8412): stubs (9 entries)
    | SSL_set_rfd, SSL_set_wfd, SSL_set_bio, SSL_get_rbio, SSL_get_wbio,
    | SSL_set_cipher_list, SSL_set_read_ahead, SSL_get_verify_mode, SSL_get_verify_depth
    .rept   9
    .long   StubRetZero
    .endr

    | Slot 1403 (LVO -8418): SSL_get_verify_callback(ssl)(a0) → verify callback ptr
    | Was StubRetZero (NULL) → iBrowse calls through NULL → JSR 0 → #80000004!
    | Returns g_verify_callback (sentinel 1UL if not set, real cb if set).
    | FD verified: ##bias 8316 → SSL_get_fd at slot 1386; SSL_get_verify_callback
    | at line 1219 = offset 17 → slot 1403
    .long   _ami_SSL_get_verify_callback

    | Slots 1404-1446 (LVO -8424 to -8676): stubs (43 entries)
    | SSL_set_verify, SSL_set_verify_depth, SSL_use_RSAPrivateKey through
    | SSL_get_peer_cert_chain (verified ##bias 8316, ##bias 8610 in FD file)
    .rept   43
    .long   StubRetZero
    .endr

    | Slot 1447 (LVO -8682): SSL_CTX_get_verify_mode(ctx)(a0) → LONG
    | Returns the verify mode last set by SSL_CTX_set_verify.
    | Was StubRetZero (returned 0 = SSL_VERIFY_NONE), causing iBrowse to
    | think no verification was requested.  Now returns g_verify_mode.
    | FD verified: ##bias 8610 → slot 1435; SSL_CTX_get_verify_mode at +12 = slot 1447
    | Build 19: wrapped so 0xF003 probe doesn't corrupt a6.
    .long   WrapSSLCTXGetVerifyMode

    | Slot 1448 (LVO -8688): SSL_CTX_get_verify_depth — stub (depth not tracked)
    .long   StubRetZero

    | Slot 1449 (LVO -8694): SSL_CTX_get_verify_callback(ctx)(a0) → SSL_verify_cb
    | Returns the verify callback last set by SSL_CTX_set_verify.
    | Was StubRetZero (returned NULL), causing iBrowse to call through NULL → crash!
    | Now returns g_verify_callback (sentinel 1UL if not set, real cb if set).
    | Build 19: wrapped so 0xF002 probe doesn't corrupt a6.
    .long   WrapSSLCTXGetVerifyCB

    | Slot 1450 (LVO -8700): SSL_CTX_set_verify
    | FD verified: ##bias 8610 → slot 1435; SSL_CTX_set_verify at line 1265 = +15 = slot 1450
    | Build 19: wrapped so 0xF001 probe doesn't corrupt a6.
    .long   WrapSSLCTXSetVerify

    | Slots 1451-1463 (LVO -8706 to -8778): stubs (13 entries)
    | FD verified (##bias 8610): 13 functions between SSL_CTX_set_verify
    | (slot 1450) and SSL_new (slot 1464):
    |   1451 SSL_CTX_set_verify_depth        1452 SSL_CTX_set_cert_verify_callback
    |   1453 SSL_CTX_use_RSAPrivateKey       1454 SSL_CTX_use_RSAPrivateKey_ASN1
    |   1455 SSL_CTX_use_PrivateKey          1456 SSL_CTX_use_PrivateKey_ASN1
    |   1457 SSL_CTX_use_certificate         1458 SSL_CTX_use_certificate_ASN1
    |   1459 SSL_CTX_set_default_passwd_cb   1460 SSL_CTX_set_default_passwd_cb_userdata
    |   1461 SSL_CTX_check_private_key       1462 SSL_check_private_key
    |   1463 SSL_CTX_set_session_id_context
    .rept   13
    .long   StubRetZero
    .endr

    | Slot 1464 (LVO -8784): SSL_new  (wrapped: restores a6)
    | FD verified: ##bias 8610 → slot 1435; SSL_new at line 1279 = +29 = slot 1464
    .long   WrapSSLNew

    | Slots 1465-1469 (LVO -8790 to -8814): stubs (5 entries)
    | 1465 SSL_set_session_id_context  1466 SSL_CTX_set_purpose
    | 1467 SSL_set_purpose             1468 SSL_CTX_set_trust  1469 SSL_set_trust
    .rept   5
    .long   StubRetZero
    .endr

    | Slot 1470 (LVO -8820): SSL_free  (wrapped: restores a6)
    | FD verified: ##bias 8610 → slot 1435; SSL_free at line 1285 = +35 = slot 1470
    .long   WrapSSLFree

    | Slot 1471 (LVO -8826): stub  (SSL_accept — server-side, not used)
    .long   StubRetZero

    | Slot 1472 (LVO -8832): SSL_connect  (wrapped: restores a6)
    | FD verified: ##bias 8610 → slot 1435; SSL_connect at line 1287 = +37 = slot 1472
    .long   WrapSSLConnect

    | Slot 1473 (LVO -8838): SSL_read  (wrapped: restores a6)
    .long   WrapSSLRead

    | Slot 1474 (LVO -8844): stub  (SSL_peek — no passthrough peek support)
    .long   StubRetZero

    | Slot 1475 (LVO -8850): SSL_write  (wrapped: restores a6)
    .long   WrapSSLWrite

    | Slot 1476 (LVO -8856): SSL_ctrl (handles SNI: cmd=SSL_CTRL_SET_TLSEXT_HOSTNAME=55)
    |   (wrapped: restores a6 when cmd=55 path calls bsdsocket)
    .long   WrapSSLCtrl

    | Slot 1477 (LVO -8862): stub  (SSL_callback_ctrl)
    .long   StubRetZero

    | Slot 1478 (LVO -8868): SSL_CTX_ctrl
    | Build 19: now calls Pi with probe 0xEC00|cmd — MUST be wrapped.
    .long   WrapSSLCTXCtrl

    | Slot 1479 (LVO -8874): stub  (SSL_CTX_callback_ctrl)
    .long   StubRetZero

    | Slot 1480 (LVO -8880): SSL_get_error  (wrapped: restores a6)
    .long   WrapSSLGetError

    | Slot 1481 (LVO -8886): SSL_get_version — returns "TLSv1.3"
    | FD: SSL_get_error and SSL_get_version are adjacent (lines 1295-1296), no gap
    .long   _ami_SSL_get_version

    | Slots 1482-1498 (LVO -8892 to -8988): stubs (17 entries)
    .rept   17
    .long   StubRetZero
    .endr

    | Slot 1499 (LVO -8994): SSL_shutdown  (wrapped: restores a6)
    | FD verified: ##bias 8952 → TLSv1_method at slot 1492; SSL_shutdown at +7 = slot 1499
    .long   WrapSSLShutdown

    | Slots 1500-1527 (LVO -9000 to -9162): stubs (28 entries)
    .rept   28
    .long   StubRetZero
    .endr

    | Slot 1528 (LVO -9168): SSL_CTX_set_default_verify_paths
    | FD verified: ##bias 8952 → slot 1492; line 1335 = +36 = slot 1528
    | Build 19: wrapped so 0xF005 probe doesn't corrupt a6.
    .long   WrapSSLCTXSetDefaultVP

    | Slot 1529 (LVO -9174): SSL_CTX_load_verify_locations
    | Build 19: wrapped so 0xF009 probe doesn't corrupt a6.
    .long   WrapSSLCTXLoadVerifyLoc

    | Slots 1530-1531 (LVO -9180 to -9186): stubs (2 entries)
    | SSL_get_session, SSL_get1_session — return opaque handles, NULL is benign
    .rept   2
    .long   StubRetZero
    .endr

    | Slot 1532 (LVO -9192): SSL_get_SSL_CTX(ssl)(a0) → SSL_CTX*
    | Was StubRetZero (NULL) → iBrowse passes NULL to SSL_CTX_get_ex_data → crash!
    | Returns sentinel 1UL; ami_SSL_CTX_get_ex_data ignores the ctx arg.
    | FD verified: ##bias 8952 → slot 1492; line 1339 = +40 = slot 1532
    .long   _ami_SSL_get_SSL_CTX

    | Slot 1533 (LVO -9198): SSL_set_info_callback(ssl,cb)(a0,a1) — stub
    .long   StubRetZero

    | Slot 1534 (LVO -9204): SSL_get_info_callback(ssl)(a0) → info callback ptr
    | Was StubRetZero (NULL) → if iBrowse calls through NULL → JSR 0 → #80000004!
    | FD verified: ##bias 8952 → slot 1492; line 1341 = +42 = slot 1534
    .long   _ami_SSL_get_info_callback

    | Slots 1535-1536 (LVO -9210 to -9216): stubs (2 entries)
    | 1535 = gap (bias jump from -9204 to ##bias 9216);
    | 1536 = SSL_set_verify_result (##bias 9216 block, line 1343)
    .rept   2
    .long   StubRetZero
    .endr

    | Slot 1537 (LVO -9222): SSL_get_verify_result
    | FD verified: ##bias 9216 → SSL_set_verify_result at slot 1536; +1 = slot 1537
    .long   _ami_SSL_get_verify_result

    | Slots 1538-1543 (LVO -9228 to -9258): stubs (6 entries)
    .rept   6
    .long   StubRetZero
    .endr

    | Slot 1544 (LVO -9264): SSL_CTX_set_ex_data(ssl,idx,data)(a0,d0,a1)
    | iBrowse stores app data in SSL_CTX; stub returning 0 is benign
    | FD verified: ##bias 9216 → slot 1536; SSL_CTX_set_ex_data at line 1351 = +8 = slot 1544
    | Build 19: wrapped so 0xE200|idx probe doesn't corrupt a6.
    .long   WrapSSLCTXSetExData

    | Slot 1545 (LVO -9270): SSL_CTX_get_ex_data(ssl,idx)(a0,d0) → APTR
    | Returning 0 causes crash if iBrowse dereferences the result as a pointer.
    | Stores/returns the value previously set via SSL_CTX_set_ex_data.
    | FD verified: ##bias 9216 → slot 1536; SSL_CTX_get_ex_data at line 1352 = +9 = slot 1545
    | Build 19: wrapped so 0xE100|idx probe doesn't corrupt a6.
    .long   WrapSSLCTXGetExData

    | Slots 1546-1553 (LVO -9276 to -9318): stubs (8 entries)
    .rept   8
    .long   StubRetZero
    .endr

    | Slot 1554 (LVO -9324): OPENSSL_sk_num → 0 (empty stack; AWeb iterates sk_value)
    .long   _ami_OPENSSL_sk_num

    | Slot 1555 (LVO -9330): OPENSSL_sk_value → NULL
    .long   _ami_OPENSSL_sk_value

    | Slots 1556-1973 (LVO -9336 to -11838): stubs (418 entries)
    .rept   418
    .long   StubRetZero
    .endr

    | Slot 1974 (LVO -11844): X509_verify_cert → 1 (cert verified; Pi did real check)
    .long   _ami_X509_verify_cert

    | Slots 1975-2024 (LVO -11850 to -12144): stubs (50 entries)
    .rept   50
    .long   StubRetZero
    .endr

    | Slot 2025 (LVO -12150): X509_STORE_CTX_init → 1 (success)
    .long   _ami_X509_STORE_CTX_init

    | Slots 2026-3229 (LVO -12156 to -19374): stubs (1204 entries)
    | (418 + 1 + 50 + 1 + 1204 = 1674, the original count; keeps slot 3230 aligned.)
    .rept   1204
    .long   StubRetZero
    .endr

    | Slot 3230 (LVO -19380): SSL_CTX_sess_get_get_cb(ctx)(a0) → get-session callback
    | Was StubRetZero (NULL); iBrowse calls through NULL → JSR 0 → #80000004!
    .long   _ami_SSL_CTX_sess_get_get_cb

    | Slot 3231 (LVO -19386): SSL_CTX_sess_get_get_cb GETTER → was StubRetZero → CRASH!
    | FD verified: ##bias 19362 → slot 3227; slot 3231 = SSL_CTX_sess_get_get_cb (GETTER)
    | iBrowse saves the returned cb ptr, later calls through it; NULL → JSR 0 → #80000004
    .long   _ami_SSL_CTX_sess_get_get_cb_real

    | Slot 3232 (LVO -19392): SSL_CTX_sess_set_get_cb SETTER → stub OK
    .long   StubRetZero

    | Slot 3233 (LVO -19398): SSL_CTX_get_info_callback(ctx)(a0) → info callback ptr
    | Was StubRetZero (returned NULL); iBrowse calls through NULL → JSR 0 → #80000004!
    | PROBE_52 fires op=52 if iBrowse calls this between set_options and crash.
    .long   _ami_SSL_CTX_get_info_callback

    | Slot 3234 (LVO -19404): SSL_CTX_sess_get_new_cb(ctx)(a0) → new-session callback
    | Was StubRetZero (NULL); iBrowse calls through NULL → crash!
    .long   _ami_SSL_CTX_sess_get_new_cb

    | Slot 3235 (LVO -19410): SSL_CTX_get_client_cert_cb(ctx)(a0) → client-cert callback
    .long   _ami_SSL_CTX_get_client_cert_cb

    | Slot 3236 (LVO -19416): SSL_CTX_sess_get_remove_cb(ctx)(a0) → remove-session callback
    .long   _ami_SSL_CTX_sess_get_remove_cb

    | Slot 3237 (LVO -19422): SSL_CTX_get_client_cert_cb GETTER → was StubRetZero → CRASH!
    | FD: slot 3237 = SSL_CTX_get_client_cert_cb (GETTER — returns client-cert callback ptr)
    .long   _ami_SSL_CTX_get_client_cert_cb_real

    | Slot 3238 (LVO -19428): SSL_CTX_sess_get_remove_cb GETTER → was StubRetZero → CRASH!
    | FD: slot 3238 = SSL_CTX_sess_get_remove_cb (GETTER — returns session-remove callback ptr)
    .long   _ami_SSL_CTX_sess_get_remove_cb_real

    | Slots 3239-4035 (LVO -19434 to -24210): stubs (797 entries)  [was 800, split 2 off top]
    .rept   797
    .long   StubRetZero
    .endr

    | Slot 4036 (LVO -24216): SSL_CTX_get_ssl_method(ctx)(a0) → SSL_METHOD*
    | Returning NULL causes crash if iBrowse calls through the method vtable.
    .long   _ami_SSL_CTX_get_ssl_method

    | Slots 4037-4159 (LVO -24222 to -24954): stubs (123 entries)
    .rept   123
    .long   StubRetZero
    .endr

    | Slot 4160 (LVO -24960): OpenSSL_version(type)(d0) → returns version strings
    | iBrowse displays this in the connection security info / padlock dialog.
    | Returning NULL here would crash string-display code.  Return proper strings.
    .long   _ami_OpenSSL_version

    | Slot 4161 (LVO -24966): OpenSSL_version_num() → returns OpenSSL version number
    | iBrowse 3.0 calls this and requires the result >= 0x30100040 (OpenSSL 3.1.4+).
    | We return 0x30600020 which encodes OpenSSL 3.6.2 per the 0xMNN00PP0 scheme:
    |   (3<<28)|(6<<20)|(2<<4) = 0x30000000|0x00600000|0x00000020 = 0x30600020
    .long   _ami_OpenSSL_version_num

    | Slots 4162-4427 (LVO -24972 to -26562): stubs (266 entries)
    .rept   266
    .long   StubRetZero
    .endr

    | Slot 4428 (LVO -26568): OPENSSL_init_ssl(opts,settings)(d0,a0) → LONG
    | Must return 1 (success); returning 0 causes iBrowse to abort SSL init.
    | Build 19: wrapped so 0xF007 probe doesn't corrupt a6.
    .long   WrapOpenSSLInitSSL

    | Slots 4429-4446 (LVO -26574 to -26676): stubs (18 entries)
    .rept   18
    .long   StubRetZero
    .endr

    | Slot 4447 (LVO -26682): SSL_CTX_set_options
    | Build 19: wrapped so 0xF006 probe doesn't corrupt a6.
    .long   WrapSSLCTXSetOptions

    | Slots 4448-4449 (LVO -26688 to -26694): stubs (2 entries)
    .rept   2
    .long   StubRetZero
    .endr

    | Slot 4450 (LVO -26700): SSL_CTX_up_ref — returns 1 (int success).
    | AWeb 3.6b8 loops on this; StubRetZero's non-1 return made it spin.
    .long   _ami_SSL_CTX_up_ref

    | Slots 4451-4488 (LVO -26706 to -26928): stubs (38 entries)
    .rept   38
    .long   StubRetZero
    .endr

    | Slot 4489 (LVO -26934): TLS_client_method
    .long   _ami_TLS_client_method

    | Slot 4490 (LVO -26940): TLS_method
    .long   _ami_TLS_method

    | Slots 4491-4592 (LVO -26946 to -27552): stubs (102 entries)
    .rept   102
    .long   StubRetZero
    .endr

    | Slot 4593 (LVO -27558): SSL_CTX_get_default_passwd_cb(ctx)(a0) → pem_password_cb*
    | Was StubRetZero (returned NULL); iBrowse calls through NULL → #80000004!
    | PROBE_52 fires op=52 if iBrowse calls this between set_options and crash.
    .long   _ami_SSL_CTX_get_default_passwd_cb

    | Slot 4594 (LVO -27564): SSL_CTX_get_default_passwd_cb_userdata(ctx)(a0) → void*
    | Returns application userdata pointer; returning NULL may cause crash if dereferenced.
    .long   _ami_SSL_CTX_get_default_passwd_cb_userdata

    | Slots 4595-4795 (LVO -27570 to -28770): stubs (201 entries)
    .rept   201
    .long   StubRetZero
    .endr

    | Slot 4796 (LVO -28776): X509_STORE_get_verify(xs)(a0) → X509_STORE_ctx_verify_fn
    | Was StubRetZero (returned NULL); returning non-NULL sentinel prevents call-through-NULL.
    | Build 20: wrapped so 0xD002 probe doesn't corrupt a6.
    .long   WrapX509StoreGetVerify

    | Slot 4797 (LVO -28782): X509_STORE_get_verify_cb(xs)(a0) → X509_STORE_ctx_verify_cb
    | CRITICAL: Was StubRetZero (returned NULL/0); iBrowse calls the returned function →
    | JSR 0 → CPU executes from address 0 → hits 0x4AFC → #80000004 Illegal Instruction!
    | Build 20: returns dummy_verify_cb (real callable 68K fn) so JSR through it is safe.
    | Wrapped so 0xD001 probe doesn't corrupt a6.
    .long   WrapX509StoreGetVerifyCb

    | Slots 4798-5394 (LVO -28788 to -32364): stubs (597 entries)
    .rept   597
    .long   StubRetZero
    .endr

    | Slot 5395 (LVO -32370): SSL_CTX_new_ex(libctx,propq,method)(a0,a1,a2) → SSL_CTX*
    | In AmiSSL 5 headers SSL_CTX_new(meth) compiles as SSL_CTX_new_ex(NULL,NULL,meth).
    | iBrowse calls this immediately after OpenAmiSSL; returning NULL → crash.
    .long   WrapSSLCTXNewEx

    | Slots 5396-5452 (LVO -32376 to -32712): stubs (57 entries)
    .rept   57
    .long   StubRetZero
    .endr

    .long   -1                              | FuncTable terminator

| ---- C symbol declarations -------------------------------------------------
    .extern _ami_ssl_open
    .extern _ami_ssl_close
    .extern _ami_stub_probe
    .extern _ami_SSL_CTX_up_ref
    .extern _ami_OPENSSL_sk_num
    .extern _ami_OPENSSL_sk_value
    .extern _ami_X509_verify_cert
    .extern _ami_X509_STORE_CTX_init
    .extern _ami_ASN1_STRING_length
    .extern _ami_ASN1_STRING_data

    .extern _ami_InitAmiSSLA
    .extern _ami_CleanupAmiSSLA

    .extern _ami_ERR_get_error
    .extern _ami_ERR_peek_error
    .extern _ami_ERR_clear_error
    .extern _ami_ERR_error_string

    .extern _ami_BIO_new
    .extern _ami_BIO_ctrl
    .extern _ami_BIO_read
    .extern _ami_BIO_write
    .extern _ami_BIO_f_ssl
    .extern _ami_BIO_new_ssl
    .extern _ami_BIO_new_ssl_connect
    .extern _ami_BIO_new_buffer_ssl_connect
    .extern _ami_BIO_new_connect

    .extern _ami_SSL_CTX_set_cipher_list
    .extern _ami_SSL_CTX_new
    .extern _ami_SSL_CTX_free
    .extern _ami_SSL_CTX_get_cert_store
    .extern _ami_SSL_CTX_set_verify
    .extern _ami_SSL_CTX_get_verify_mode
    .extern _ami_SSL_CTX_get_verify_callback
    .extern _ami_SSL_CTX_set_default_verify_paths
    .extern _ami_SSL_CTX_load_verify_locations
    .extern _ami_SSL_CTX_set_options
    .extern _ami_SSL_CTX_ctrl
    .extern _ami_SSL_CTX_set_ex_data
    .extern _ami_SSL_CTX_get_ex_data
    .extern _ami_SSL_CTX_get_ssl_method
    .extern _ami_SSL_CTX_sess_get_get_cb
    .extern _ami_SSL_CTX_get_info_callback
    .extern _ami_SSL_CTX_sess_get_new_cb
    .extern _ami_SSL_CTX_get_client_cert_cb
    .extern _ami_SSL_CTX_sess_get_remove_cb
    | Build 5: corrected getter slots (3230, 3236, 3237) — were StubRetZero → NULL → crash
    .extern _ami_SSL_CTX_sess_get_get_cb_real
    .extern _ami_SSL_CTX_get_client_cert_cb_real
    .extern _ami_SSL_CTX_sess_get_remove_cb_real
    .extern _ami_SSL_CTX_get_default_passwd_cb
    .extern _ami_SSL_CTX_get_default_passwd_cb_userdata
    .extern _ami_X509_STORE_get_verify
    .extern _ami_X509_STORE_get_verify_cb

    .extern _ami_SSL_pending
    .extern _ami_SSL_get_current_cipher
    .extern _ami_SSL_CIPHER_get_bits
    .extern _ami_SSL_CIPHER_get_version
    .extern _ami_SSL_CIPHER_get_name
    .extern _ami_SSL_get_version
    .extern _ami_SSL_get_verify_callback
    .extern _ami_SSL_get_SSL_CTX
    .extern _ami_SSL_get_info_callback
    .extern _ami_SSL_set_fd
    .extern _ami_SSL_new
    .extern _ami_SSL_free
    .extern _ami_SSL_connect
    .extern _ami_SSL_read
    .extern _ami_SSL_write
    .extern _ami_SSL_ctrl
    .extern _ami_SSL_get_error
    .extern _ami_SSL_shutdown
    .extern _ami_SSL_get_verify_result

    .extern _ami_TLS_client_method
    .extern _ami_TLS_method

    .extern _ami_OpenSSL_version
    .extern _ami_OpenSSL_version_num

    .extern _ami_OPENSSL_init_ssl
    .extern _ami_SSL_CTX_new_ex

| ---- Init: called by exec with d0=segList, a6=ExecBase ---------------------
Init:
    movem.l d2-d7/a2-a6,-(sp)
    move.l  d0,d6               | d6 = segList

    | MakeLibrary(funcInit/a0, structInit/a1=NULL, libInit/a2=NULL,
    |             posSize/d0, segList/d1)
    | exec scans FuncTable to determine negSize from the -1 terminator.
    lea     FuncTable(pc),a0
    sub.l   a1,a1
    sub.l   a2,a2
    move.l  #amisslbase_SIZEOF,d0
    move.l  d6,d1
    jsr     -84(a6)             | exec MakeLibrary

    move.l  d0,d5               | d5 = libbase or NULL
    beq.s   .fail

    movea.l d5,a1

    | Fill our custom fields
    move.l  a6,amisslbase_SysBase(a1)
    move.l  d6,amisslbase_SegList(a1)
    clr.l   amisslbase_BsdBase(a1)    | filled on first Open

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
    move.w  #amisslbase_SIZEOF,LIB_POSSIZE(a1)

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

| ---- Open ------------------------------------------------------------------
| Called by exec with a6 = library base, d0 = version requested.
| Must return library base in d0, or NULL on failure.
Open:
    movem.l d1-d7/a0-a5,-(sp)
    move.l  a6,-(sp)            | pass library base as C argument
    jsr     _ami_ssl_open
    addq.l  #4,sp
    movem.l (sp)+,d1-d7/a0-a5
    | d0 = libbase or 0 (from ami_ssl_open)
    rts

| ---- Close -----------------------------------------------------------------
| Called with a6 = library base.  Return 0 (never expunge).
Close:
    movem.l d1-d7/a0-a5,-(sp)
    move.l  a6,-(sp)
    jsr     _ami_ssl_close
    addq.l  #4,sp
    movem.l (sp)+,d1-d7/a0-a5
    moveq   #0,d0               | never expunge
    rts

| ---- Expunge / Null --------------------------------------------------------
Expunge:
Null:
    moveq   #0,d0
    rts

| ---- StubRetZero -----------------------------------------------------------
| Default handler for every UNIMPLEMENTED LVO.  Routes through ami_stub_probe,
| which returns a real callable no-op (dummy_verify_cb) rather than 0/1 — so if
| an app treats the result as a function pointer and JSRs through it, it lands on
| a safe routine instead of address 0/1 (#80000004).  a6 = AmiSSLBase on entry and
| must be preserved (Amiga ABI); the C function may clobber it, so save/restore it
| around the JSR.  (Name is historical; it no longer returns zero.)
StubRetZero:
    move.l  a6,-(sp)
    jsr     _ami_stub_probe            | -> dummy_verify_cb in d0 (non-NULL, callable)
    move.l  (sp)+,a6
    rts

| ---- a6-preserving wrappers for SSL functions that call bsdsocket ----------
|
| Problem: the _bsd_call* inline-asm helpers in amissl.c set a6 = BsdBase
| before the JSR to bsdsocket.library.  After the JSR, bsdsocket preserves
| a6 (per Amiga convention), but a6 is still BsdBase — NOT amissl_base.
| When the C function returns, iBrowse's a6 is corrupted.  The very next
| amissl LVO call does JSR -N(a6) with a6 = BsdBase, landing in bsdsocket's
| JMP table at a completely wrong offset → executes 0xF9xx → F-line #8000000B.
|
| Fix: each FuncTable entry for an SSL function that calls bsdsocket uses one
| of these wrappers instead of the C function directly.  The wrapper saves a6
| (amissl_base) before calling the C function, then restores it on return.
|
| Stack layout inside wrapper after JSR to C function:
|   (sp)   = return address (to "move.l (sp)+,a6" below)
|   (sp+4) = saved amissl_base   ← pushed by "move.l a6,-(sp)" before JSR
|   (sp+8) = iBrowse's return address (from JSR -LVO(a6))
|
| When the C function's RTS fires, it pops (sp) = return addr inside wrapper,
| leaving (sp) = saved amissl_base, (sp+4) = iBrowse's return addr.
| "move.l (sp)+,a6" restores amissl_base; "rts" pops iBrowse's return addr.

WrapSSLCTXNew:
    move.l  a6,-(sp)
    jsr     _ami_SSL_CTX_new
    move.l  (sp)+,a6
    rts

WrapSSLCTXFree:
    move.l  a6,-(sp)
    jsr     _ami_SSL_CTX_free
    move.l  (sp)+,a6
    rts

WrapSSLSetFd:
    move.l  a6,-(sp)
    jsr     _ami_SSL_set_fd
    move.l  (sp)+,a6
    rts

WrapSSLNew:
    move.l  a6,-(sp)
    jsr     _ami_SSL_new
    move.l  (sp)+,a6
    rts

WrapSSLFree:
    move.l  a6,-(sp)
    jsr     _ami_SSL_free
    move.l  (sp)+,a6
    rts

WrapSSLConnect:
    move.l  a6,-(sp)
    jsr     _ami_SSL_connect
    move.l  (sp)+,a6
    rts

WrapSSLRead:
    move.l  a6,-(sp)
    jsr     _ami_SSL_read
    move.l  (sp)+,a6
    rts

WrapSSLWrite:
    move.l  a6,-(sp)
    jsr     _ami_SSL_write
    move.l  (sp)+,a6
    rts

WrapSSLCtrl:
    move.l  a6,-(sp)
    jsr     _ami_SSL_ctrl
    move.l  (sp)+,a6
    rts

WrapSSLGetError:
    move.l  a6,-(sp)
    jsr     _ami_SSL_get_error
    move.l  (sp)+,a6
    rts

WrapSSLShutdown:
    move.l  a6,-(sp)
    jsr     _ami_SSL_shutdown
    move.l  (sp)+,a6
    rts

WrapSSLCTXNewEx:
    move.l  a6,-(sp)
    jsr     _ami_SSL_CTX_new_ex
    move.l  (sp)+,a6
    rts

| ---- BIO a6-preserving wrappers -------------------------------------------
|
| ami_BIO_ctrl, ami_BIO_read, ami_BIO_write call bsdsocket via _bsd_call* helpers
| which set a6 = BsdBase before each JSR.  After each JSR, bsdsocket may leave
| a6 pointing to SysBase (or BsdBase), corrupting iBrowse's AmiSSLBase in a6.
|
| These wrappers use the same save/restore pattern as the WrapSSL* functions above:
|   push a6 (= AmiSSLBase), call C function, pop a6 back, rts to iBrowse.
|
| NOTE: ami_BIO_new_ssl_connect does NOT call bsdsocket, so it needs no wrapper.

| ---- Build 19: wrappers for newly-probed functions ------------------------
| Each of these now calls bsdsocket (via _bsd_call1d probe) → a6 would be
| corrupted without the wrapper.  Pattern: save a6 (AmiSSLBase), call C
| function (which may trash a6 via _bsd_call*), restore a6, rts to iBrowse.

WrapInitAmiSSLA:
    move.l  a6,-(sp)
    jsr     _ami_InitAmiSSLA
    move.l  (sp)+,a6
    rts

WrapSSLCTXSetCipherList:
    move.l  a6,-(sp)
    jsr     _ami_SSL_CTX_set_cipher_list
    move.l  (sp)+,a6
    rts

WrapSSLCTXGetCertStore:
    move.l  a6,-(sp)
    jsr     _ami_SSL_CTX_get_cert_store
    move.l  (sp)+,a6
    rts

WrapSSLCTXGetVerifyMode:
    move.l  a6,-(sp)
    jsr     _ami_SSL_CTX_get_verify_mode
    move.l  (sp)+,a6
    rts

WrapSSLCTXGetVerifyCB:
    move.l  a6,-(sp)
    jsr     _ami_SSL_CTX_get_verify_callback
    move.l  (sp)+,a6
    rts

WrapSSLCTXSetVerify:
    move.l  a6,-(sp)
    jsr     _ami_SSL_CTX_set_verify
    move.l  (sp)+,a6
    rts

WrapSSLCTXCtrl:
    move.l  a6,-(sp)
    jsr     _ami_SSL_CTX_ctrl
    move.l  (sp)+,a6
    rts

WrapSSLCTXSetDefaultVP:
    move.l  a6,-(sp)
    jsr     _ami_SSL_CTX_set_default_verify_paths
    move.l  (sp)+,a6
    rts

WrapSSLCTXLoadVerifyLoc:
    move.l  a6,-(sp)
    jsr     _ami_SSL_CTX_load_verify_locations
    move.l  (sp)+,a6
    rts

WrapSSLCTXSetExData:
    move.l  a6,-(sp)
    jsr     _ami_SSL_CTX_set_ex_data
    move.l  (sp)+,a6
    rts

WrapSSLCTXGetExData:
    move.l  a6,-(sp)
    jsr     _ami_SSL_CTX_get_ex_data
    move.l  (sp)+,a6
    rts

WrapOpenSSLInitSSL:
    move.l  a6,-(sp)
    jsr     _ami_OPENSSL_init_ssl
    move.l  (sp)+,a6
    rts

WrapSSLCTXSetOptions:
    move.l  a6,-(sp)
    jsr     _ami_SSL_CTX_set_options
    move.l  (sp)+,a6
    rts

| Build 20: X509_STORE getter wrappers (now call Pi via probe → must save a6)
WrapX509StoreGetVerify:
    move.l  a6,-(sp)
    jsr     _ami_X509_STORE_get_verify
    move.l  (sp)+,a6
    rts

WrapX509StoreGetVerifyCb:
    move.l  a6,-(sp)
    jsr     _ami_X509_STORE_get_verify_cb
    move.l  (sp)+,a6
    rts

| ---- BIO a6-preserving wrappers -------------------------------------------
|
| ami_BIO_ctrl, ami_BIO_read, ami_BIO_write call bsdsocket via _bsd_call* helpers
| which set a6 = BsdBase before each JSR.  After each JSR, bsdsocket may leave
| a6 pointing to SysBase (or BsdBase), corrupting iBrowse's AmiSSLBase in a6.
|
| These wrappers use the same save/restore pattern as the WrapSSL* functions above:
|   push a6 (= AmiSSLBase), call C function, pop a6 back, rts to iBrowse.
|
| NOTE: ami_BIO_new_ssl_connect does NOT call bsdsocket, so it needs no wrapper.

WrapBIONewSslConnect:
    move.l  a6,-(sp)
    jsr     _ami_BIO_new_ssl_connect
    move.l  (sp)+,a6
    rts

WrapBIOCtrl:
    move.l  a6,-(sp)
    jsr     _ami_BIO_ctrl
    move.l  (sp)+,a6
    rts

WrapBIORead:
    move.l  a6,-(sp)
    jsr     _ami_BIO_read
    move.l  (sp)+,a6
    rts

WrapBIOWrite:
    move.l  a6,-(sp)
    jsr     _ami_BIO_write
    move.l  (sp)+,a6
    rts

| ---- GCC soft-division helpers (32÷32 unsigned) ----------------------------
| m68k-amigaos-gcc may emit __udivsi3/__umodsi3 calls when C code uses
| integer division.  Provide them here so we don't need libgcc.

    .globl  ___udivsi3
___udivsi3:
    movem.l d2/d3/d4,-(sp)
    move.l  16(sp),d0
    move.l  20(sp),d3
    moveq   #0,d2
    moveq   #0,d4
    moveq   #31,d1
10:
    lsl.l   #1,d2
    btst    d1,d0
    beq     11f
    bset    #0,d2
11:
    cmp.l   d3,d2
    blo     12f
    sub.l   d3,d2
    bset    d1,d4
12:
    dbra    d1,10b
    move.l  d4,d0
    movem.l (sp)+,d2/d3/d4
    rts

    .globl  ___umodsi3
___umodsi3:
    movem.l d2/d3,-(sp)
    move.l  12(sp),d0
    move.l  16(sp),d3
    moveq   #0,d2
    moveq   #31,d1
13:
    lsl.l   #1,d2
    btst    d1,d0
    beq     14f
    bset    #0,d2
14:
    cmp.l   d3,d2
    blo     15f
    sub.l   d3,d2
15:
    dbra    d1,13b
    move.l  d2,d0
    movem.l (sp)+,d2/d3
    rts
