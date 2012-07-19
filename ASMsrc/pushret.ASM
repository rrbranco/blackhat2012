; Qualys Vulnerabliity & Malware Research Labs (VMRL)
; Blackhat 2012 Presentation Samples
; TiTle:   A Scientific (but non academic) study of how malware employs anti-debugging,
;          anti-disassembly and anti-virtualization technologies
; Authors: Rodrigo Rubira Branco <rbranco *NOSPAM* qualys.com>
;          Gabriel Negreira Barbosa <gbarbosa *NOSPAM* qualys.com>
;          Pedro Drimel Neto <pdrimel *NOSPAM* qualys.com>
;
;
; This program was created to test push-ret anti-disassembly technique (5.1)

include 'win32ax.inc'

.code

  start:
	pop	eax
	pop	ebx
	pop	ecx
	push	.continue
	ret
	db	0xab
	db	0xbc
	db	0xcd
	db	0xff
	db	0xaa
	db	0x1
	db	0x2
	db	0xff
	db	0xef
	db	0xe9
	db	0xab
	db	0xe8
	db	0xa9

	.continue:
		xor	eax,eax
		mov	ecx,1
		nop
		xchg	eax,ecx
		push	edx
		pop	edx
		invoke	ExitProcess,0
  .end start
