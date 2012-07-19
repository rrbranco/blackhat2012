; Qualys Vulnerabliity & Malware Research Labs (VMRL)
; Blackhat 2012 Presentation Samples
; TiTle:   A Scientific (but non academic) study of how malware employs anti-debugging,
;          anti-disassembly and anti-virtualization technologies
; Authors: Rodrigo Rubira Branco <rbranco *NOSPAM* qualys.com>
;          Gabriel Negreira Barbosa <gbarbosa *NOSPAM* qualys.com>
;          Pedro Drimel Neto <pdrimel *NOSPAM* qualys.com>
;
;
; This program was created to test detection of software breakpoint (3.26)
; reference: "The Art Of Unpacking" by Mark Vincent Yason

include 'win32ax.inc'

.code

  start:
	nop
	xor	eax,eax
	xor	ebx,ebx
	xor	ecx,ecx
	xor	edx,edx

	.protectedcode:
		nop
		nop
		nop
		xor	eax,eax
		nop
		nop
		nop
		nop
	cld
	mov	edi,.protectedcode
	mov	ecx,0x09
	mov	al,0xCC
	repne	scasb
	jz	.being_debugged
	jmp	.exit

	.being_debugged:
		invoke	MessageBox,HWND_DESKTOP,"Software Breakpoint Found!",invoke GetCommandLine,MB_OK
		invoke	ExitProcess,0
	.exit:
		invoke	MessageBox,HWND_DESKTOP,"Software Breakpoint NOT Found!",invoke GetCommandLine,MB_OK
		invoke	ExitProcess,0

  .end start
