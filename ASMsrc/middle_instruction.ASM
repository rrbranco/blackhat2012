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
	;xor     eax,eax
	;jz      $+4
	;mov     eax,0xc3abcdef

	;mov     ax,0x05eb
	;xor     eax,eax
	;jz      -6;
	;db      0xe8;
	;xor     eax,eax
	;pop     eax
	;mov     eax,esp
	;push    ecx

	;jmp     -1
	;db      0xc0
	;db      0x48

	invoke	ExitProcess,0
  .end start
