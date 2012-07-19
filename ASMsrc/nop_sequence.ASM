; Qualys Vulnerabliity & Malware Research Labs (VMRL)
; Blackhat 2012 Presentation Samples
; TiTle:   A Scientific (but non academic) study of how malware employs anti-debugging,
;          anti-disassembly and anti-virtualization technologies
; Authors: Rodrigo Rubira Branco <rbranco *NOSPAM* qualys.com>
;          Gabriel Negreira Barbosa <gbarbosa *NOSPAM* qualys.com>
;          Pedro Drimel Neto <pdrimel *NOSPAM* qualys.com>
;
;
; This program was created to test NOP sequence detection (4.2)
; reference: Mihai Christodorescu, Somesh Jha - Proceedings of the 12th USENIX Security

include 'win32ax.inc'

.code

  start:
	xor	eax, eax
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	mov	eax,0x10101010
	nop
	nop
	nop
	invoke	ExitProcess,0

  .end start
