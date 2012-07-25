; Qualys Vulnerabliity & Malware Research Labs (VMRL)
; Blackhat 2012 Presentation Samples
; TiTle:   A Scientific (but non academic) study of how malware employs anti-debugging,
;          anti-disassembly and anti-virtualization technologies
; Authors: Rodrigo Rubira Branco <rbranco *NOSPAM* qualys.com>
;          Gabriel Negreira Barbosa <gbarbosa *NOSPAM* qualys.com>
;          Pedro Drimel Neto <pdrimel *NOSPAM* qualys.com>
;
include 'win32ax.inc'

.code

  start:
	nop
	nop
	nop

	;jmp     .destination
	;push    0x12345678
	;inc     eax
	;mov     esp,eax
	;invoke  MessageBox,HWND_DESKTOP,"This does not execute!",invoke GetCommandLine,MB_OK
	;.destination:
	;        invoke  MessageBox,HWND_DESKTOP,"This gets executed!",invoke GetCommandLine,MB_OK

	;xor     eax,eax
	;jnz     .fake_code
	;jmp     .destination
	;.fake_code:
	;        push    0x12345678
	;        inc     eax
	;        mov     esp,eax
	;        invoke  MessageBox,HWND_DESKTOP,"This does not execute!",invoke GetCommandLine,MB_OK
	;.destination:
	;        invoke  MessageBox,HWND_DESKTOP,"This gets executed!",invoke GetCommandLine,MB_OK

	push	.destination
	ret
	push	0x12345678
	inc	eax
	mov	esp,eax
	invoke	MessageBox,HWND_DESKTOP,"This does not execute!",invoke GetCommandLine,MB_OK
	.destination:
		invoke	MessageBox,HWND_DESKTOP,"This gets executed!",invoke GetCommandLine,MB_OK




	invoke	ExitProcess,0
  .end start
