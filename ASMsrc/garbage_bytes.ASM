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
	;db      0x6a ; garbage byte technique
	;.destination:
	;        pop eax

	mov	eax,eax
	jz	.destination
	db	0x6a
	.destination:
		pop eax

	invoke	ExitProcess,0
  .end start
